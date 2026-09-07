from backend.guardrails.capability_token import verify_capability_token
from backend.guardrails.capability_token_ledger import get_token_status, reset_token_ledger
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


def test_capability_token_ledger_records_issue_and_consume():
    reset_token_ledger()

    phase1 = prepare_tool_authorization(_request())

    token = phase1.capability_token["token"]
    verified = verify_capability_token(token)
    token_id = verified["payload"]["token_id"]

    issued_status = get_token_status(token_id)

    assert issued_status["status"] == "issued"
    assert issued_status["token_id"] == token_id

    phase2 = execute_tool_with_capability(
        _request(capability_token=token)
    )

    assert phase2.decision == "allow"

    consumed_status = get_token_status(token_id)

    assert consumed_status["status"] == "consumed"
    assert consumed_status["consumed_at"] is not None
