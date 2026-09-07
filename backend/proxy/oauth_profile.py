from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set


TOOL_SCOPE_MAP: Dict[str, List[str]] = {
    "file.read": ["tool:file:read"],
    "file.write": ["tool:file:write"],
    "file.delete": ["tool:file:delete"],
    "email.send": ["tool:email:send"],
    "shell.run": ["tool:shell:run"],
    "db.query": ["tool:db:query"],
    "http.post": ["tool:http:post"],
}

SIDE_EFFECT_TOOLS = {
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "http.post",
    "db.write",
}

SENSITIVE_PATH_MARKERS = (
    "secret/",
    "private/",
    "../",
    "password",
    "credential",
)

INTERNAL_EMAIL_DOMAINS = (
    "sdu.edu.cn",
)


def _get_value(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default

    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def _model_to_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}

    if isinstance(obj, dict):
        return dict(obj)

    if hasattr(obj, "model_dump"):
        return obj.model_dump()

    if hasattr(obj, "dict"):
        return obj.dict()

    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)

    return {}


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    if isinstance(value, tuple) or isinstance(value, set):
        return [str(item).strip() for item in value if str(item).strip()]

    if isinstance(value, str):
        normalized = value.replace(",", " ")
        return [item.strip() for item in normalized.split() if item.strip()]

    return [str(value).strip()] if str(value).strip() else []


def _unique(items: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()

    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)

    return result


def _is_sensitive_path(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    return any(marker in lowered for marker in SENSITIVE_PATH_MARKERS)


def _extract_recipient(params: Dict[str, Any]) -> str:
    for key in ["to", "recipient", "email", "to_email"]:
        value = params.get(key)
        if value:
            return str(value).strip()

    return ""


def _is_external_email(recipient: str) -> bool:
    if not recipient or "@" not in recipient:
        return True

    domain = recipient.split("@")[-1].lower().strip()

    return domain not in INTERNAL_EMAIL_DOMAINS


def extract_declared_scopes(request: Any) -> List[str]:
    """
    从 Tool Proxy 请求中提取外部 Agent 声明的 scopes。

    来源包括：
    1. request.requested_scopes
    2. request.oauth_token_claims.scope
    3. request.oauth_token_claims.scp
    4. request.oauth_token_claims.scopes
    """

    requested_scopes = _as_list(_get_value(request, "requested_scopes", []))
    claims = _get_value(request, "oauth_token_claims", {}) or {}

    token_scopes: List[str] = []
    token_scopes.extend(_as_list(claims.get("scope")))
    token_scopes.extend(_as_list(claims.get("scp")))
    token_scopes.extend(_as_list(claims.get("scopes")))

    return _unique(requested_scopes + token_scopes)


def get_required_scopes(tool: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    根据工具和参数推导本次调用需要的 scopes。
    """

    params = params or {}

    required: List[str] = []
    required.extend(TOOL_SCOPE_MAP.get(tool, [f"tool:{tool}"]))

    if tool in SIDE_EFFECT_TOOLS:
        required.append("sink:side-effect")

    if tool == "email.send":
        recipient = _extract_recipient(params)

        if _is_external_email(recipient):
            required.append("sink:external-email")

    if tool in {"file.read", "file.write", "file.delete"}:
        path = str(
            params.get("path")
            or params.get("file_path")
            or params.get("resource")
            or params.get("filename")
            or ""
        )

        if _is_sensitive_path(path):
            required.append("source:sensitive-file")

    return _unique(required)


def _build_principal(request: Any) -> Dict[str, Any]:
    claims = _get_value(request, "oauth_token_claims", {}) or {}

    return {
        "subject": claims.get("sub", "-"),
        "client_id": claims.get("client_id", "-"),
        "issuer": claims.get("iss", "-"),
        "audience": claims.get("aud", "-"),
    }


def _summarize_contract(contract: Any) -> Dict[str, Any]:
    contract_dict = _model_to_dict(contract)

    capabilities = contract_dict.get("capabilities", []) or []
    capability_tools: List[str] = []

    for capability in capabilities:
        if isinstance(capability, dict):
            tool = capability.get("tool")
        else:
            tool = getattr(capability, "tool", None)

        if tool:
            capability_tools.append(str(tool))

    return {
        "contract_version": contract_dict.get("contract_version", "capability_contract_v2"),
        "task_id": contract_dict.get("task_id"),
        "user": contract_dict.get("user"),
        "capability_tools": _unique(capability_tools),
        "forbidden_tools": contract_dict.get("forbidden_tools", []),
        "forbidden_resources": contract_dict.get("forbidden_resources", []),
        "max_steps": contract_dict.get("max_steps"),
        "risk_budget": contract_dict.get("risk_budget"),
    }


def build_agent_auth_profile(
    request: Any,
    contract: Any,
) -> Dict[str, Any]:
    """
    生成外部 Agent 授权画像。

    该函数用于说明：
    - 外部 Agent 是谁；
    - 它声明了哪些 scope；
    - 当前工具调用实际需要哪些 scope；
    - scope 是否足够；
    - 该调用被放入什么沙箱 profile。
    """

    tool = str(_get_value(request, "tool", ""))
    params = _get_value(request, "params", {}) or {}
    auth_mode = str(_get_value(request, "auth_mode", "none") or "none")

    required_scopes = get_required_scopes(tool, params)
    declared_scopes = extract_declared_scopes(request)

    missing_scopes = [
        scope for scope in required_scopes
        if scope not in declared_scopes
    ]

    scope_gate_enabled = (
        auth_mode == "oauth_scope"
        or bool(_get_value(request, "requested_scopes", []))
        or bool(_get_value(request, "oauth_token_claims", {}))
    )

    if scope_gate_enabled and missing_scopes:
        scope_decision = "deny"
    else:
        scope_decision = "pass"

    return {
        "model": "oauth_style_agent_authorization_profile",
        "auth_mode": auth_mode,
        "agent_platform": _get_value(request, "agent_platform", "custom"),
        "sandbox_profile": _get_value(request, "sandbox_profile", "default"),
        "principal": _build_principal(request),
        "required_scopes": required_scopes,
        "declared_scopes": declared_scopes,
        "missing_scopes": missing_scopes,
        "scope_gate_enabled": scope_gate_enabled,
        "scope_decision": scope_decision,
        "contract_summary": _summarize_contract(contract),
        "explanation": (
            "OAuth-style scope controls what an external Agent claims it may access; "
            "AgentGuard additionally checks task boundary, capability contract, "
            "runtime data flow, sandbox policy, and human approval requirements."
        ),
    }
