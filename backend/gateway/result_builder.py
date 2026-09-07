"""
Gateway response building helpers.

This module contains pure helper functions for:
- risk score -> risk level conversion
- natural-language reasons -> structured explanations
- default semantic_guard response shape
- final Gateway response construction

It intentionally contains no policy loading, no semantic model calls, and no
business decision logic. Keeping response construction here makes
backend/gateway/gateway.py easier to read and reduces merge conflicts.
"""

from __future__ import annotations

from typing import Any


def get_risk_level(score: int) -> str:
    """
    Convert a numeric risk score into a stable risk level for UI, audit and tests.
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def build_explanations(reason: list[str]) -> list[dict[str, str]]:
    """
    Convert natural-language reason strings into structured explanation items.

    This preserves the existing reason text while providing a lightweight factor
    classification for dashboard/audit display.
    """
    explanations: list[dict[str, str]] = []

    for item in reason:
        text = str(item)

        if "语义检测" in text:
            factor = "semantic_guard"
        elif "路径" in text or "secret" in text or "资源风险" in text or "访问路径" in text:
            factor = "resource_path"
        elif "角色" in text or "权限" in text or "user" in text or "admin" in text:
            factor = "role_policy"
        elif "邮件" in text or "外发" in text or "接收人" in text:
            factor = "external_output"
        elif "提示注入" in text or "ignore previous" in text or "忽略" in text:
            factor = "prompt_injection"
        elif "命令" in text or "shell" in text or "高危操作" in text:
            factor = "command"
        elif "SQL" in text or "数据库" in text or "SELECT" in text:
            factor = "database"
        elif "Agent" in text or "置信度" in text or "计划" in text:
            factor = "agent_plan"
        elif "任务授权合约" in text or "Capability Contract" in text or "合约" in text:
            factor = "task_contract"
        elif "工具" in text:
            factor = "tool"
        elif "参数" in text:
            factor = "params"
        else:
            factor = "general"

        explanations.append(
            {
                "factor": factor,
                "reason": text,
            }
        )

    return explanations


def default_semantic_guard_result() -> dict[str, Any]:
    """
    Build the default semantic_guard response.

    Gateway responses should always include this field so that frontend/audit
    consumers do not need special-case checks.
    """
    return {
        "enabled": False,
        "risk_score": 0,
        "force_confirm": False,
        "hard_deny": False,
        "labels": [],
        "matches": [],
        "reasons": [],
    }


def build_gateway_result(
    decision: str,
    risk_score: int,
    reason: list[str],
    user: str,
    role: str,
    tool: str,
    params: dict[str, Any],
    semantic_guard: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a complete Gateway response.

    semantic_guard is returned as a structured field so dashboard, audit and
    tests can read semantic labels/risk/matches directly instead of parsing
    reason text.
    """
    if semantic_guard is None:
        semantic_guard = default_semantic_guard_result()

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "reason": reason,
        "explanations": build_explanations(reason),
        "semantic_guard": semantic_guard,
        "user": user,
        "role": role,
        "normalized_tool": tool,
        "normalized_params": params,
    }


# Backward-compatible private alias for existing imports/tests during refactor.
_default_semantic_guard_result = default_semantic_guard_result
