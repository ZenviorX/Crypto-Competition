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


def test_authorization_trace_contains_capability_token_ledger_status():
    reset_token_ledger()

    phase1 = prepare_tool_authorization(_request())
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
    assert token_stage["extra"]["ledger_status"] == "issued"
    assert token_stage["extra"]["consumption"]["consumed"] is True


def test_authorization_trace_marks_consumed_token_replay():
    reset_token_ledger()

    phase1 = prepare_tool_authorization(_request())
    token = phase1.capability_token["token"]

    first = execute_tool_with_capability(_request(capability_token=token))
    assert first.decision == "allow"

    second = execute_tool_with_capability(_request(capability_token=token))
    assert second.decision == "deny"

    token_stage = next(
        item for item in second.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"
    assert token_stage["extra"]["ledger_status"] == "consumed"
