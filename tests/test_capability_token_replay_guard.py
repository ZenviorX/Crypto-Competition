from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.two_phase_tool_proxy_service import (
    execute_tool_with_capability,
    prepare_tool_authorization,
)


def _request(capability_token: str = "") -> ToolProxyAuthorizeRequest:
    return ToolProxyAuthorizeRequest(
        user="user",
        original_task="请读取 public/notice.txt 并总结",
        tool="file.read",
        params={"path": "public/notice.txt"},
        requested_scopes=["tool:file:read"],
        oauth_token_claims={"scope": "tool:file:read"},
        auth_mode="oauth_scope",
        agent_platform="openclaw",
        sandbox_profile="local_readonly",
        execute=False,
        capability_token=capability_token,
    )


def test_capability_token_cannot_be_replayed_after_successful_execution():
    phase1 = prepare_tool_authorization(_request())

    assert phase1.decision == "allow"

    token = phase1.capability_token["token"]

    first_execution = execute_tool_with_capability(
        _request(capability_token=token)
    )

    assert first_execution.decision == "allow"

    second_execution = execute_tool_with_capability(
        _request(capability_token=token)
    )

    assert second_execution.decision == "deny"

    token_stage = next(
        item for item in second_execution.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"

    reasons = " ".join(token_stage["reason"])
    assert "already been consumed" in reasons
