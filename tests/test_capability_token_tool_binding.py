from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.two_phase_tool_proxy_service import (
    execute_tool_with_capability,
    prepare_tool_authorization,
)


def _request(tool: str, params: dict, capability_token: str = "") -> ToolProxyAuthorizeRequest:
    return ToolProxyAuthorizeRequest(
        user="user",
        original_task="请读取 public/notice.txt 并总结",
        tool=tool,
        params=params,
        requested_scopes=["tool:file:read", "tool:file:write", "sink:side-effect"],
        oauth_token_claims={"scope": "tool:file:read tool:file:write sink:side-effect"},
        auth_mode="oauth_scope",
        agent_platform="openclaw",
        sandbox_profile="default",
        execute=False,
        capability_token=capability_token,
    )


def test_capability_token_cannot_be_reused_with_different_tool():
    phase1 = prepare_tool_authorization(
        _request(
            tool="file.read",
            params={"path": "public/notice.txt"},
        )
    )

    assert phase1.decision == "allow"
    token = phase1.capability_token["token"]

    phase2 = execute_tool_with_capability(
        _request(
            tool="file.write",
            params={"path": "public/notice.txt", "content": "tampered"},
            capability_token=token,
        )
    )

    assert phase2.decision == "deny"

    token_stage = next(
        item for item in phase2.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"

    reasons = " ".join(token_stage["reason"])
    assert "different tool" in reasons
