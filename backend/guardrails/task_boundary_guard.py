from __future__ import annotations

from typing import Any, Dict, List, Optional


SIDE_EFFECT_TOOLS = {
    "email.send",
    "file.write",
    "file.delete",
    "shell.run",
    "http.post",
    "db.write",
}

SENSITIVE_PATH_MARKERS = (
    "secret/",
    "private/",
    "../",
    "password",
    ".env",
    "token",
    "credential",
)

EXTERNAL_MARKERS = (
    "attacker",
    "example.com",
    "http://",
    "https://",
)

UNTRUSTED_INPUT_LABELS = {
    "untrusted",
    "external",
    "web",
    "email",
    "retrieved_content",
    "prompt_injection",
}

UNTRUSTED_SIDE_EFFECT_TOOLS = {
    "email.send",
    "http.post",
    "shell.run",
    "file.write",
    "file.delete",
    "db.write",
}

READ_ONLY_MARKERS = (
    "只读",
    "只总结",
    "仅总结",
    "只读取",
    "不要发送",
    "不要修改",
    "不允许修改",
    "read-only",
    "only read",
)

EXTERNAL_FORBID_MARKERS = (
    "不要向外部",
    "不允许向外部",
    "禁止外发",
    "不要发送邮件",
    "不得发送邮件",
    "do not send",
)

NETWORK_FORBID_MARKERS = (
    "不允许联网",
    "禁止联网",
    "不要联网",
    "no network",
)


def _text(value: Any) -> str:
    return str(value or "").lower().replace("\\", "/")


def _params_text(params: Dict[str, Any]) -> str:
    return " ".join(_text(value) for value in params.values())


def _is_sensitive_path(params: Dict[str, Any]) -> bool:
    path = _text(
        params.get("path")
        or params.get("file_path")
        or params.get("resource")
        or params.get("filename")
    )
    return any(marker in path for marker in SENSITIVE_PATH_MARKERS)


def _has_external_sink(params: Dict[str, Any]) -> bool:
    value = _params_text(params)
    return any(marker in value for marker in EXTERNAL_MARKERS)


def build_capability_contract(original_task: Optional[str]) -> Dict[str, Any]:
    task = _text(original_task)

    read_only = any(marker in task for marker in READ_ONLY_MARKERS)
    external_forbidden = any(marker in task for marker in EXTERNAL_FORBID_MARKERS)
    network_forbidden = any(marker in task for marker in NETWORK_FORBID_MARKERS)

    sensitive_read_allowed = any(
        marker in task
        for marker in ("secret", "password", "敏感", "私有", "private", "token")
    )

    return {
        "contract_version": "capability_contract_v1",
        "side_effect_tools_allowed": not read_only,
        "external_transmission_allowed": not external_forbidden,
        "network_access_allowed": not network_forbidden,
        "sensitive_path_read_allowed": sensitive_read_allowed,
        "untrusted_input_can_trigger_side_effect": False,
        "source": "original_task",
    }


def evaluate_task_boundary_policy(
    original_task: Optional[str],
    tool: str,
    params: Optional[Dict[str, Any]] = None,
    input_labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    params = params or {}
    input_labels = input_labels or []

    tool = _text(tool)
    contract = build_capability_contract(original_task)

    reasons: List[str] = [
        "Capability Contract was derived from the original task.",
        "Task Boundary Guard checked the requested tool call against this contract.",
    ]

    decision = "allow"
    risk_delta = 0

    if not contract["side_effect_tools_allowed"] and tool in SIDE_EFFECT_TOOLS:
        decision = "deny"
        risk_delta = 100
        reasons.append("Capability Contract forbids side-effect tools for this task.")

    if not contract["external_transmission_allowed"] and _has_external_sink(params):
        decision = "deny"
        risk_delta = 100
        reasons.append("Capability Contract forbids external transmission.")

    if not contract["network_access_allowed"] and (
        tool == "http.post" or (tool == "shell.run" and _has_external_sink(params))
    ):
        decision = "deny"
        risk_delta = 100
        reasons.append("Capability Contract forbids network access.")

    if tool == "file.read" and _is_sensitive_path(params) and not contract["sensitive_path_read_allowed"]:
        decision = "deny"
        risk_delta = 100
        reasons.append("Capability Contract does not allow sensitive path reading.")

    normalized_labels = {label.lower() for label in input_labels}

    if "sensitive" in normalized_labels and tool in {"email.send", "http.post"}:
        decision = "deny"
        risk_delta = 100
        reasons.append("Sensitive labeled data is being sent to an external sink tool.")

    if normalized_labels & UNTRUSTED_INPUT_LABELS and tool in UNTRUSTED_SIDE_EFFECT_TOOLS:
        decision = "deny"
        risk_delta = 100
        reasons.append(
            "Untrusted or prompt-injected input is not allowed to trigger side-effect tools."
        )

    return {
        "decision": decision,
        "risk_delta": risk_delta,
        "reason": reasons,
        "policy": "task_boundary_guard_v1",
        "capability_contract": contract,
    }
