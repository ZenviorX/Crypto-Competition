from backend.guardrails.capability_token_ledger import reset_token_ledger
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


def test_prepare_phase_issues_token_but_execute_phase_does_not_issue_new_token():
    reset_token_ledger()

    phase1 = prepare_tool_authorization(_request())

    assert phase1.decision == "allow"
    assert phase1.executed is False
    assert phase1.capability_token["issued"] is True
    assert "token" in phase1.capability_token

    token = phase1.capability_token["token"]

    phase2 = execute_tool_with_capability(
        _request(capability_token=token)
    )

    assert phase2.decision == "allow"
    assert phase2.executed is True
    assert phase2.capability_token["issued"] is False
    assert "token" not in phase2.capability_token
    assert "does not issue a new token" in phase2.capability_token["reason"]
