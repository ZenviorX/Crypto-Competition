from __future__ import annotations

from typing import Any, Dict, List, Tuple

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


SEMANTIC_LABELS = [
    "prompt_injection",
    "policy_bypass",
    "data_exfiltration",
    "credential_access",
    "destructive_action",
    "privilege_escalation",
    "network_abuse",
]


def _bool(value: bool) -> float:
    return 1.0 if value else 0.0


def _extract_semantic_scores(
    semantic_result: Dict[str, Any],
) -> Dict[str, float]:
    """
    从 Semantic Guard 中只提取语义证据。

    不采用 Semantic Guard 的人工 risk_score。
    """

    scores = {
        label: 0.0
        for label in SEMANTIC_LABELS
    }

    for match in (
        semantic_result.get(
            "matches",
            [],
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

        if label in scores:
            scores[label] = max(
                scores[label],
                score,
            )

    return scores


def _extract_history_context(
    history: List[Dict[str, Any]],
) -> Tuple[str, int]:
    """
    把前序工具调用/外部内容整理成模型可以分析的文本。

    返回：
        history_text
        untrusted_source_count
    """

    text_parts: List[str] = []

    untrusted_source_count = 0

    for item in history or []:

        if not isinstance(
            item,
            dict,
        ):
            text_parts.append(
                str(item)
            )
            continue

        source = str(
            item.get(
                "source",
                "",
            )
        ).strip().lower()

        if (
            "untrusted" in source
            or source
            in {
                "external",
                "web",
                "website",
                "email",
                "document",
                "third_party",
            }
        ):
            untrusted_source_count += 1

        # 只提取真正的运行时内容，
        # 不读取任何 Ground Truth 字段。
        for key in [
            "content",
            "text",
            "output",
            "observation",
            "result",
            "message",
        ]:
            value = item.get(key)

            if isinstance(
                value,
                str,
            ) and value.strip():
                text_parts.append(
                    value.strip()
                )

    return (
        "\n".join(text_parts),
        untrusted_source_count,
    )


def extract_risk_features(
    request: ToolCallRequest,
) -> Dict[str, float]:
    """
    将一次工具调用转换成风险证据。

    这里只生成事实特征，
    不产生风险分，
    不做 allow / confirm / deny。
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
        params.get(
            "sql",
            "",
        )
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

    # =========================================================
    # 1. 当前工具类型
    # =========================================================
    for known_tool in KNOWN_TOOLS:

        feature_name = (
            "tool_"
            + known_tool.replace(
                ".",
                "_",
            )
        )

        features[
            feature_name
        ] = _bool(
            tool == known_tool
        )

    # =========================================================
    # 2. 用户角色
    # =========================================================
    features[
        "role_admin"
    ] = _bool(
        str(
            request.user
        ).lower()
        == "admin"
    )

    # =========================================================
    # 3. Agent 计划证据
    # =========================================================
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
        bool(
            request.plan_warnings
        )
    )

    features[
        "current_step"
    ] = float(
        request.current_step
    )

    # =========================================================
    # 4. 运行时数据标签
    #
    # 这些只能来自真实 Runtime Monitor，
    # synthetic dataset 不允许人工提前塞答案。
    # =========================================================
    labels = {
        str(item).lower()
        for item in (
            request.input_labels
            or []
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

    # =========================================================
    # 5. 当前资源路径证据
    # =========================================================
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
            analyze_resource_path(
                path
            )
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

    # =========================================================
    # 6. 当前敏感资源证据
    # =========================================================
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
        len(
            matched_sensitive_paths
        )
    )

    # =========================================================
    # 7. 外发目标证据
    # =========================================================
    features[
        "is_external_email"
    ] = 0.0

    features[
        "email_recipient_missing"
    ] = 0.0

    if tool == "email.send":

        recipient = str(
            params.get(
                "to",
                "",
            )
        ).strip().lower()

        if not recipient:

            features[
                "email_recipient_missing"
            ] = 1.0

        else:

            internal_domains = [
                str(
                    domain
                ).lower()
                for domain
                in get_internal_email_domains()
            ]

            is_internal = any(
                recipient.endswith(
                    domain
                )
                for domain
                in internal_domains
            )

            features[
                "is_external_email"
            ] = _bool(
                not is_internal
            )

    # =========================================================
    # 8. 当前调用关键词证据
    # =========================================================
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

    # =========================================================
    # 9. 当前调用语义证据
    # =========================================================
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

    current_scores = (
        _extract_semantic_scores(
            semantic_result
        )
    )

    for (
        label,
        score,
    ) in current_scores.items():

        features[
            f"semantic_{label}"
        ] = float(score)

    # =========================================================
    # 10. 跨步骤 History 证据
    #
    # 这是本版本新增的关键部分：
    #
    # 当前调用可能看起来正常，
    # 但它可能是被前一步恶意网页、邮件或文档诱导出来的。
    # =========================================================
    history = (
        request.history
        or []
    )

    (
        history_text,
        untrusted_source_count,
    ) = _extract_history_context(
        history
    )

    features[
        "history_present"
    ] = _bool(
        bool(history)
    )

    features[
        "history_step_count"
    ] = float(
        len(history)
    )

    features[
        "history_untrusted_source_count"
    ] = float(
        untrusted_source_count
    )

    features[
        "history_text_length"
    ] = float(
        len(history_text)
    )

    features[
        "history_prompt_injection_keyword_count"
    ] = float(
        len(
            match_keywords(
                history_text,
                prompt_keywords,
            )
        )
    )

    features[
        "history_sensitive_content_keyword_count"
    ] = float(
        len(
            match_keywords(
                history_text,
                sensitive_keywords,
            )
        )
    )

    # =========================================================
    # 11. History 语义分析
    # =========================================================
    history_scores = {
        label: 0.0
        for label in SEMANTIC_LABELS
    }

    if history_text:

        history_semantic_result = (
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
                path=None,
                content=history_text,
                command="",
                sql="",
            )
        )

        history_scores = (
            _extract_semantic_scores(
                history_semantic_result
            )
        )

    for (
        label,
        score,
    ) in history_scores.items():

        features[
            f"history_semantic_{label}"
        ] = float(score)

    return features
