from __future__ import annotations

from typing import Dict

from backend.schemas import ToolCallRequest
from backend.gateway.policy_loader import (
    get_dangerous_keywords,
    get_internal_email_domains,
    match_keywords,
)
from backend.gateway.security_detectors import (
    analyze_resource_path,
)
from backend.gateway.semantic_guard import (
    semantic_check_tool_call,
)
from backend.utils import (
    normalize_tool_name,
    normalize_params,
    get_path,
    get_content,
    get_command,
)


KNOWN_TOOLS = [
    "file.read",
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "db.query",
]


def _bool(value: bool) -> float:
    return 1.0 if value else 0.0


def extract_risk_features(
    request: ToolCallRequest,
) -> Dict[str, float]:
    """
    将一次工具调用转换成风险证据特征。

    注意：
    这里不计算风险分，也不做 allow / confirm / deny。

    例如：
        is_external_email = 1
    只表示目标是外部邮箱。

    它到底应该增加多少风险，
    后面由数据训练出的模型决定。
    """

    tool = normalize_tool_name(
        request.tool
    )

    params = normalize_params(
        tool,
        request.params,
    )

    path = get_path(params)
    content = get_content(params)
    command = get_command(params)
    sql = str(
        params.get("sql", "")
    )

    original_input = str(
        request.original_input or ""
    )

    detection_content = "\n".join(
        item
        for item in [
            original_input,
            content,
        ]
        if item
    )

    features: Dict[str, float] = {}

    # ---------------------------------------------------------
    # 1. 工具类型
    # 不再给工具固定风险分，只记录工具是什么
    # ---------------------------------------------------------
    for known_tool in KNOWN_TOOLS:
        feature_name = (
            "tool_"
            + known_tool
            .replace(".", "_")
        )

        features[feature_name] = _bool(
            tool == known_tool
        )

    # ---------------------------------------------------------
    # 2. 用户角色
    # ---------------------------------------------------------
    features["role_admin"] = _bool(
        str(request.user).lower()
        == "admin"
    )

    # ---------------------------------------------------------
    # 3. Agent 计划信息
    # ---------------------------------------------------------
    if request.agent_confidence is None:
        features[
            "agent_confidence_missing"
        ] = 1.0

        features[
            "agent_confidence"
        ] = 0.0

    else:
        features[
            "agent_confidence_missing"
        ] = 0.0

        features[
            "agent_confidence"
        ] = float(
            request.agent_confidence
        )

    features[
        "has_plan_warnings"
    ] = _bool(
        bool(request.plan_warnings)
    )

    features[
        "current_step"
    ] = float(
        request.current_step
    )

    # ---------------------------------------------------------
    # 4. 输入数据标签
    # ---------------------------------------------------------
    labels = {
        str(item).lower()
        for item in (
            request.input_labels or []
        )
    }

    for label in [
        "public",
        "internal",
        "sensitive",
        "secret",
        "tainted",
        "prompt_injection",
        "unknown",
    ]:
        features[
            f"input_label_{label}"
        ] = _bool(
            label in labels
        )

    # ---------------------------------------------------------
    # 5. 路径证据
    # ---------------------------------------------------------
    features[
        "has_path"
    ] = _bool(
        bool(path)
    )

    features[
        "path_traversal"
    ] = 0.0

    features[
        "path_encoded_bypass"
    ] = 0.0

    features[
        "path_absolute"
    ] = 0.0

    if path:
        path_analysis = (
            analyze_resource_path(path)
        )

        features[
            "path_traversal"
        ] = _bool(
            path_analysis.has_traversal
        )

        features[
            "path_encoded_bypass"
        ] = _bool(
            path_analysis.has_encoded_bypass
        )

        features[
            "path_absolute"
        ] = _bool(
            path_analysis.is_absolute
        )

    # ---------------------------------------------------------
    # 6. 敏感资源证据
    # 只统计命中了多少个敏感标记，
    # 不再把每个标记换算成人工风险分
    # ---------------------------------------------------------
    sensitive_path_keywords = (
        get_dangerous_keywords(
            "sensitive_path"
        )
    )

    matched_sensitive_paths = (
        match_keywords(
            path,
            sensitive_path_keywords,
        )
        if path
        else []
    )

    features[
        "sensitive_path_keyword_count"
    ] = float(
        len(matched_sensitive_paths)
    )

    # ---------------------------------------------------------
    # 7. 邮件外发证据
    # ---------------------------------------------------------
    features[
        "is_external_email"
    ] = 0.0

    features[
        "email_recipient_missing"
    ] = 0.0

    if tool == "email.send":
        recipient = str(
            params.get("to", "")
        ).strip().lower()

        if not recipient:
            features[
                "email_recipient_missing"
            ] = 1.0

        else:
            internal_domains = [
                str(domain).lower()
                for domain
                in get_internal_email_domains()
            ]

            is_internal = any(
                recipient.endswith(domain)
                for domain
                in internal_domains
            )

            features[
                "is_external_email"
            ] = _bool(
                not is_internal
            )

    # ---------------------------------------------------------
    # 8. 关键词检测证据
    # ---------------------------------------------------------
    prompt_keywords = (
        get_dangerous_keywords(
            "prompt_injection"
        )
    )

    sensitive_keywords = (
        get_dangerous_keywords(
            "sensitive_content"
        )
    )

    command_keywords = (
        get_dangerous_keywords(
            "command"
        )
    )

    sql_keywords = (
        get_dangerous_keywords(
            "sql"
        )
    )

    features[
        "prompt_injection_keyword_count"
    ] = float(
        len(
            match_keywords(
                detection_content,
                prompt_keywords,
            )
        )
    )

    features[
        "sensitive_content_keyword_count"
    ] = float(
        len(
            match_keywords(
                detection_content,
                sensitive_keywords,
            )
        )
    )

    features[
        "dangerous_command_keyword_count"
    ] = float(
        len(
            match_keywords(
                command,
                command_keywords,
            )
        )
    )

    features[
        "dangerous_sql_keyword_count"
    ] = float(
        len(
            match_keywords(
                sql,
                sql_keywords,
            )
        )
    )

    # ---------------------------------------------------------
    # 9. 语义检测证据
    #
    # 重要：
    # 不使用 semantic_guard 返回的 risk_score。
    # 我们只取它识别出的风险类别和相似度。
    # ---------------------------------------------------------
    semantic_result = (
        semantic_check_tool_call(
            user=request.user,
            role=(
                "admin"
                if str(
                    request.user
                ).lower()
                == "admin"
                else "user"
            ),
            tool=tool,
            params=params,
            path=path,
            content=detection_content,
            command=command,
            sql=sql,
        )
    )

    semantic_scores = {
        "prompt_injection": 0.0,
        "policy_bypass": 0.0,
        "data_exfiltration": 0.0,
        "credential_access": 0.0,
        "destructive_action": 0.0,
        "privilege_escalation": 0.0,
        "network_abuse": 0.0,
    }

    for match in (
        semantic_result.get(
            "matches",
            []
        )
        or []
    ):
        label = str(
            match.get(
                "label",
                "",
            )
        )

        score = float(
            match.get(
                "score",
                0.0,
            )
            or 0.0
        )

        if (
            label
            in semantic_scores
        ):
            semantic_scores[
                label
            ] = max(
                semantic_scores[
                    label
                ],
                score,
            )

    for (
        label,
        score,
    ) in semantic_scores.items():
        features[
            f"semantic_{label}"
        ] = float(score)

    return features
