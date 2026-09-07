from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.two_phase_tool_proxy_service import (
    execute_tool_with_capability,
    prepare_tool_authorization,
)


def _request(path: str, capability_token: str = "") -> ToolProxyAuthorizeRequest:
    return ToolProxyAuthorizeRequest(
        user="user",
        original_task="请读取 public/notice.txt 并总结",
        tool="file.read",
        params={"path": path},
        requested_scopes=["tool:file:read"],
        oauth_token_claims={"scope": "tool:file:read"},
        auth_mode="oauth_scope",
        agent_platform="openclaw",
        sandbox_profile="local_readonly",
        execute=False,
        capability_token=capability_token,
    )


def test_capability_token_cannot_be_reused_with_different_params():
    phase1 = prepare_tool_authorization(
        _request("public/notice.txt")
    )

    token = phase1.capability_token["token"]

    phase2 = execute_tool_with_capability(
        _request(
            path="public/readme.txt",
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
    assert "different tool parameters" in reasons
