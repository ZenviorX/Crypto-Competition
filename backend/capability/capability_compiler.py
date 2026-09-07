from __future__ import annotations

import hashlib
import re
import uuid
from typing import List, Optional

from backend.capability.capability_contract import (
    CapabilityContract,
    CapabilityRule,
)


COMPILER_VERSION = "agentguard.taskspec.v3"

EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

PATH_PATTERN = re.compile(
    r"(?:data/)?"
    r"(?:public|course|secret|private)/"
    r"[A-Za-z0-9_\-./]+\.[A-Za-z0-9]+"
    r"|"
    r"outbox/"
    r"[A-Za-z0-9_\-./]+\.[A-Za-z0-9]+"
    r"|"
    r"\.\./[A-Za-z0-9_\-./]+"
)


MANAGED_TOOLS = {
    "file.read",
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "db.query",
}

ALWAYS_FORBIDDEN_TOOLS = {
    "code.exec",
    "run_code",
}


DESTRUCTIVE_SQL_KEYWORDS = [
    "drop",
    "delete",
    "truncate",
    "update",
    "insert",
    "alter",
    "grant",
    "revoke",
    "attach database",
    "load_extension",
    "xp_cmdshell",
]

DANGEROUS_SHELL_KEYWORDS = [
    "rm -rf",
    "rm -r",
    "del /s",
    "format",
    "shutdown",
    "reboot",
    "curl",
    "wget",
    "nc ",
    "netcat",
    "powershell",
    "cmd.exe",
    "certutil",
    "bitsadmin",
    "ssh ",
    "scp ",
    "ftp ",
    "sudo",
    "su -",
    "chmod 777",
    "chown",
    "python -c",
    "bash -c",
    "sh -c",
    "| bash",
    "| sh",
]

SAFE_ADMIN_SHELL_COMMANDS = [
    "pwd",
    "dir",
    "ls",
    "whoami",
]

PROMPT_INJECTION_MARKERS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "bypass authorization",
    "skip authorization",
    "disable audit",
    "do not record audit",
    "忽略之前",
    "忽略所有之前",
    "绕过授权",
    "跳过授权",
    "跳过人工确认",
    "不要记录审计",
    "关闭审计",
    "隐藏这次操作",
    "tool:shell.run",
    "tool=shell.run",
]

SENSITIVE_TASK_MARKERS = [
    "password",
    "passwd",
    "secret",
    "credential",
    "api_key",
    "api key",
    "private key",
    "access token",
    "refresh token",
    "密码",
    "密钥",
    "凭证",
    "令牌",
]


def _new_task_id() -> str:
    return (
        "task_"
        + uuid.uuid4().hex[:12]
    )


def _unique(
    items: List[str],
) -> List[str]:
    result: List[str] = []
    seen = set()

    for item in items:
        normalized = str(item).strip()

        if (
            normalized
            and normalized not in seen
        ):
            result.append(normalized)
            seen.add(normalized)

    return result


def _normalize_path(
    path: str,
) -> str:
    normalized = (
        str(path)
        .strip()
        .replace("\\", "/")
        .strip("'\"，。；;,. ")
    )

    if normalized.startswith("../"):
        return normalized

    if normalized.startswith("data/"):
        return normalized

    if normalized.startswith(
        (
            "public/",
            "course/",
            "secret/",
            "private/",
        )
    ):
        return (
            "data/"
            + normalized
        )

    # outbox 是真实沙箱的可写目录，
    # 不增加 data/ 前缀。
    if normalized.startswith(
        "outbox/"
    ):
        return normalized

    return normalized


def _contains_path_traversal(
    path: str,
) -> bool:
    normalized = (
        str(path)
        .replace("\\", "/")
        .lower()
    )

    return (
        "../" in normalized
        or "/.." in normalized
        or "%2e%2e" in normalized
        or "%252e%252e" in normalized
    )


def extract_emails(
    text: str,
) -> List[str]:
    return _unique(
        [
            item.lower()
            for item in EMAIL_PATTERN.findall(
                text or ""
            )
        ]
    )


def extract_paths(
    text: str,
) -> List[str]:
    return _unique(
        [
            _normalize_path(path)
            for path in PATH_PATTERN.findall(
                text or ""
            )
        ]
    )


def _contains_any(
    text: str,
    keywords: List[str],
) -> bool:
    lowered = str(text or "").lower()

    return any(
        keyword.lower() in lowered
        for keyword in keywords
    )


def _is_read_intent(
    text: str,
    paths: List[str],
) -> bool:
    read_keywords = [
        "读取",
        "查看",
        "打开",
        "阅读",
        "获取文件",
        "读取文件",
        "read",
        "open file",
        "view file",
    ]

    file_markers = [
        "文件",
        "文档",
        "报告",
        "公告",
        "通知",
        "file",
        "document",
        "report",
    ]

    has_read_verb = _contains_any(
        text,
        read_keywords,
    )

    has_file_context = bool(paths) or (
        _contains_any(
            text,
            file_markers,
        )
    )

    return (
        has_read_verb
        and has_file_context
    )


def _is_write_intent(
    text: str,
) -> bool:
    return _contains_any(
        text,
        [
            "写入",
            "写到",
            "保存到",
            "保存为",
            "创建文件",
            "生成文件",
            "输出到",
            "write to",
            "save to",
            "create file",
        ],
    )


def _is_delete_intent(
    text: str,
) -> bool:
    return _contains_any(
        text,
        [
            "删除文件",
            "删除掉",
            "移除文件",
            "delete file",
            "remove file",
        ],
    )


def _is_send_intent(
    text: str,
    emails: List[str],
) -> bool:
    return bool(emails) or _contains_any(
        text,
        [
            "发送",
            "发给",
            "邮件",
            "邮箱",
            "转发",
            "send",
            "email",
            "mail",
        ],
    )


def _is_db_query_intent(
    text: str,
) -> bool:
    return _contains_any(
        text,
        [
            "数据库",
            "查询",
            "sql",
            "select",
            "notices 表",
            "notices",
            "db.query",
            "table",
        ],
    )


def _is_safe_db_select_intent(
    text: str,
) -> bool:
    lowered = str(text).lower()

    if not _is_db_query_intent(
        lowered
    ):
        return False

    if _contains_any(
        lowered,
        DESTRUCTIVE_SQL_KEYWORDS,
    ):
        return False

    return _contains_any(
        lowered,
        [
            "select",
            "查询",
            "公开",
            "总结",
            "notices",
            "只读",
            "read only",
            "read-only",
        ],
    )


def _is_shell_intent(
    text: str,
) -> bool:
    return _contains_any(
        text,
        [
            "shell",
            "命令行",
            "终端命令",
            "powershell",
            "cmd.exe",
            "bash",
            "whoami",
            "pwd",
            "curl",
            "wget",
            "执行 ls",
            "执行 dir",
            "运行 ls",
            "运行 dir",
        ],
    )


def _is_safe_admin_shell_intent(
    user: str,
    text: str,
) -> bool:
    lowered = str(text).lower()

    if str(user).lower() != "admin":
        return False

    if not _is_shell_intent(
        lowered
    ):
        return False

    if _contains_any(
        lowered,
        DANGEROUS_SHELL_KEYWORDS,
    ):
        return False

    return _contains_any(
        lowered,
        SAFE_ADMIN_SHELL_COMMANDS,
    )


def _split_paths(
    paths: List[str],
) -> tuple[
    List[str],
    List[str],
]:
    safe: List[str] = []
    forbidden: List[str] = []

    for path in paths:
        if _contains_path_traversal(
            path
        ):
            forbidden.append(path)

        elif path.startswith(
            (
                "data/public/",
                "data/course/",
                "outbox/",
            )
        ):
            safe.append(path)

        elif path.startswith(
            (
                "data/secret/",
                "data/private/",
                "../",
            )
        ):
            forbidden.append(path)

        else:
            forbidden.append(path)

    return (
        _unique(safe),
        _unique(forbidden),
    )


def _safe_outbox_targets(
    paths: List[str],
) -> List[str]:
    return _unique(
        [
            path
            for path in paths
            if path.startswith(
                "outbox/"
            )
            and not _contains_path_traversal(
                path
            )
        ]
    )


def _course_scope_requested(
    text: str,
    paths: List[str],
) -> bool:
    if any(
        path.startswith(
            "data/course/"
        )
        for path in paths
    ):
        return True

    return _contains_any(
        text,
        [
            "课程资料",
            "课程文件",
            "课程文档",
            "course/",
            "course file",
            "course document",
        ],
    )


def _critical_conflict_reasons(
    *,
    user: str,
    text: str,
    forbidden_paths: List[str],
    safe_paths: List[str],
    has_send_intent: bool,
    has_db_intent: bool,
    has_safe_db_intent: bool,
    has_shell_intent: bool,
    has_safe_shell_intent: bool,
) -> List[str]:
    reasons: List[str] = []

    if forbidden_paths:
        reasons.append(
            "Detected a sensitive, unknown or "
            "path-traversal resource in the task."
        )

    if _contains_any(
        text,
        PROMPT_INJECTION_MARKERS,
    ):
        reasons.append(
            "Detected prompt-injection or "
            "authorization-bypass instructions "
            "in the task."
        )

    if (
        has_send_intent
        and _contains_any(
            text,
            SENSITIVE_TASK_MARKERS,
        )
    ):
        reasons.append(
            "Detected an attempt to combine "
            "sensitive information with an "
            "external-send operation."
        )

    if (
        has_send_intent
        and any(
            path.startswith(
                "data/course/"
            )
            for path in safe_paths
        )
    ):
        reasons.append(
            "Detected internal course data "
            "combined with an external-send "
            "operation."
        )

    if (
        has_db_intent
        and not has_safe_db_intent
    ):
        reasons.append(
            "Database intent is not a clearly "
            "read-only SELECT operation."
        )

    if (
        has_shell_intent
        and not has_safe_shell_intent
    ):
        reasons.append(
            "Shell intent is not an explicitly "
            "allowed low-risk admin command."
        )

    if (
        str(user).lower() != "admin"
        and has_shell_intent
    ):
        reasons.append(
            "Non-admin users cannot receive "
            "shell capabilities."
        )

    return _unique(reasons)


def _build_task_goal(
    capabilities: List[
        CapabilityRule
    ],
    status: str,
) -> str:
    if not capabilities:
        return (
            "reject:unsafe_task"
            if status == "rejected"
            else "restrict:no_safe_capability"
        )

    parts: List[str] = []

    for capability in capabilities:
        if capability.recipients:
            target = ",".join(
                capability.recipients
            )

        elif capability.resource_patterns:
            target = ",".join(
                capability.resource_patterns
            )

        else:
            target = capability.mode

        parts.append(
            capability.tool
            + ":"
            + target
        )

    return " | ".join(parts)


def compile_capability_contract(
    user: str,
    original_task: str,
    task_id: Optional[str] = None,
    max_steps: int = 5,
    risk_budget: int = 80,
) -> CapabilityContract:
    normalized_user = (
        str(user or "")
        .strip()
        or "unknown"
    )

    normalized_task = str(
        original_task or ""
    ).strip()

    task_id = (
        str(task_id).strip()
        if task_id
        else _new_task_id()
    )

    max_steps = max(
        1,
        min(int(max_steps), 20),
    )

    risk_budget = max(
        0,
        min(int(risk_budget), 500),
    )

    emails = extract_emails(
        normalized_task
    )

    paths = extract_paths(
        normalized_task
    )

    (
        safe_paths,
        forbidden_paths_from_task,
    ) = _split_paths(paths)

    has_read_intent = (
        _is_read_intent(
            normalized_task,
            paths,
        )
    )

    has_write_intent = (
        _is_write_intent(
            normalized_task
        )
    )

    has_delete_intent = (
        _is_delete_intent(
            normalized_task
        )
    )

    has_send_intent = (
        _is_send_intent(
            normalized_task,
            emails,
        )
    )

    has_db_intent = (
        _is_db_query_intent(
            normalized_task
        )
    )

    has_safe_db_intent = (
        _is_safe_db_select_intent(
            normalized_task
        )
    )

    has_shell_intent = (
        _is_shell_intent(
            normalized_task
        )
    )

    has_safe_shell_intent = (
        _is_safe_admin_shell_intent(
            normalized_user,
            normalized_task,
        )
    )

    critical_reasons = (
        _critical_conflict_reasons(
            user=normalized_user,
            text=normalized_task,
            forbidden_paths=(
                forbidden_paths_from_task
            ),
            safe_paths=safe_paths,
            has_send_intent=(
                has_send_intent
            ),
            has_db_intent=(
                has_db_intent
            ),
            has_safe_db_intent=(
                has_safe_db_intent
            ),
            has_shell_intent=(
                has_shell_intent
            ),
            has_safe_shell_intent=(
                has_safe_shell_intent
            ),
        )
    )

    capabilities: List[
        CapabilityRule
    ] = []

    reasons: List[str] = []

    unfulfilled_intent = False

    if critical_reasons:
        reasons.extend(
            critical_reasons
        )

        reasons.append(
            "TaskSpec compilation failed "
            "closed. No tool capability was "
            "granted."
        )

        compilation_status = (
            "rejected"
        )

    else:
        if has_read_intent:
            if safe_paths:
                read_resources = list(
                    safe_paths
                )

            elif _course_scope_requested(
                normalized_task,
                paths,
            ):
                read_resources = [
                    "data/course/*"
                ]

            else:
                # 不再同时开放 course/*。
                read_resources = [
                    "data/public/*"
                ]

            course_read = any(
                item.startswith(
                    "data/course/"
                )
                or item
                == "data/course/*"
                for item in read_resources
            )

            capabilities.append(
                CapabilityRule(
                    tool="file.read",
                    mode="read",
                    resource_patterns=(
                        read_resources
                    ),
                    allowed_input_labels=[],
                    output_labels=[
                        (
                            "internal"
                            if course_read
                            else "public"
                        )
                    ],
                    risk_cost=(
                        20
                        if course_read
                        else 10
                    ),
                    require_approval=(
                        course_read
                    ),
                )
            )

            reasons.append(
                "Granted file.read only for "
                "the minimum safe resource "
                "scope inferred from the task."
            )

        if has_write_intent:
            write_targets = (
                _safe_outbox_targets(
                    paths
                )
            )

            if write_targets:
                capabilities.append(
                    CapabilityRule(
                        tool="file.write",
                        mode="write",
                        resource_patterns=(
                            write_targets
                        ),
                        allowed_input_labels=[
                            "public",
                            "internal",
                        ],
                        output_labels=[
                            "public"
                        ],
                        risk_cost=20,
                        require_approval=True,
                    )
                )

                reasons.append(
                    "Granted file.write only "
                    "for explicit outbox paths "
                    "with human approval."
                )

            else:
                unfulfilled_intent = True

                reasons.append(
                    "Write intent was detected "
                    "without an explicit safe "
                    "outbox path. file.write "
                    "remains forbidden."
                )

        if has_delete_intent:
            delete_targets = (
                _safe_outbox_targets(
                    paths
                )
            )

            if delete_targets:
                capabilities.append(
                    CapabilityRule(
                        tool="file.delete",
                        mode="delete",
                        resource_patterns=(
                            delete_targets
                        ),
                        allowed_input_labels=[],
                        output_labels=[],
                        risk_cost=30,
                        require_approval=True,
                    )
                )

                reasons.append(
                    "Granted file.delete only "
                    "for explicit outbox paths "
                    "with human approval."
                )

            else:
                unfulfilled_intent = True

                reasons.append(
                    "Delete intent was detected "
                    "without an explicit safe "
                    "outbox path. file.delete "
                    "remains forbidden."
                )

        if has_send_intent:
            if emails:
                capabilities.append(
                    CapabilityRule(
                        tool="email.send",
                        mode=(
                            "external_write"
                        ),
                        recipients=emails,
                        allowed_input_labels=[
                            "public"
                        ],
                        output_labels=[],
                        risk_cost=20,
                        require_approval=True,
                    )
                )

                reasons.append(
                    "Granted email.send only "
                    "to recipients explicitly "
                    "named by the user."
                )

            else:
                unfulfilled_intent = True

                reasons.append(
                    "Send intent was detected "
                    "without an explicit "
                    "recipient. email.send "
                    "remains forbidden."
                )

        if has_safe_db_intent:
            capabilities.append(
                CapabilityRule(
                    tool="db.query",
                    mode="query",
                    resource_patterns=[
                        "*"
                    ],
                    allowed_input_labels=[],
                    output_labels=[
                        "public"
                    ],
                    risk_cost=15,
                    require_approval=False,
                )
            )

            reasons.append(
                "Granted db.query only for "
                "read-only query intent."
            )

        if has_safe_shell_intent:
            capabilities.append(
                CapabilityRule(
                    tool="shell.run",
                    mode="execute",
                    resource_patterns=[],
                    allowed_input_labels=[],
                    output_labels=[
                        "public"
                    ],
                    risk_cost=35,
                    require_approval=True,
                )
            )

            reasons.append(
                "Granted shell.run only for "
                "an explicit low-risk admin "
                "command with human approval."
            )

        if not capabilities:
            reasons.append(
                "No clear safe capability was "
                "detected. A restrictive "
                "contract was generated."
            )

        if (
            capabilities
            and not unfulfilled_intent
        ):
            compilation_status = (
                "compiled"
            )

        else:
            compilation_status = (
                "restricted"
            )

    granted_tools = {
        capability.tool
        for capability in capabilities
    }

    forbidden_tools = sorted(
        ALWAYS_FORBIDDEN_TOOLS
        | (
            MANAGED_TOOLS
            - granted_tools
        )
    )

    forbidden_resources = _unique(
        [
            "data/secret/*",
            "data/private/*",
            "../*",
            "data/public/../*",
            "data/course/../*",
        ]
        + forbidden_paths_from_task
    )

    source_task_sha256 = (
        hashlib.sha256(
            normalized_task.encode(
                "utf-8"
            )
        ).hexdigest()
    )

    task_goal = _build_task_goal(
        capabilities,
        compilation_status,
    )

    return CapabilityContract(
        compiler_version=(
            COMPILER_VERSION
        ),
        compilation_status=(
            compilation_status
        ),
        source_task_sha256=(
            source_task_sha256
        ),
        task_id=task_id,
        user=normalized_user,
        original_task=normalized_task,
        task_goal=task_goal,
        capabilities=capabilities,
        forbidden_tools=(
            forbidden_tools
        ),
        forbidden_resources=(
            forbidden_resources
        ),
        max_steps=max_steps,
        risk_budget=risk_budget,
        expires_at=None,
        approval_required_when=[
            "external_write",
            "tainted_input",
            "sensitive_input",
            "internal_resource",
            "write",
            "delete",
            "execute",
        ],
        reason=reasons,
    )
