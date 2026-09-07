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


def test_two_phase_authorization_then_execution_succeeds():
    phase1 = prepare_tool_authorization(_request())

    assert phase1.decision == "allow"
    assert phase1.capability_token["issued"] is True

    token = phase1.capability_token["token"]

    phase2 = execute_tool_with_capability(
        _request(capability_token=token)
    )

    assert phase2.decision == "allow"

    token_stage = next(
        item for item in phase2.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "allow"
    assert token_stage["extra"]["provided"] is True


def test_two_phase_execution_without_token_is_denied():
    result = execute_tool_with_capability(_request())

    assert result.decision == "deny"

    token_stage = next(
        item for item in result.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"


def test_prepare_phase_never_executes_tool():
    result = prepare_tool_authorization(_request())

    assert result.decision == "allow"
    assert result.executed is False
