from fastapi.testclient import TestClient

from backend.guardrails.capability_token_ledger import reset_token_ledger
from backend.main import app

client = TestClient(app)


def _body(capability_token: str = "", execute: bool = False) -> dict:
    return {
        "user": "user",
        "original_task": "请读取 public/notice.txt 并总结",
        "tool": "file.read",
        "params": {
            "path": "public/notice.txt",
        },
        "requested_scopes": ["tool:file:read"],
        "oauth_token_claims": {
            "scope": "tool:file:read",
        },
        "auth_mode": "oauth_scope",
        "agent_platform": "openclaw",
        "sandbox_profile": "local_readonly",
        "execute": execute,
        "capability_token": capability_token,
    }


def test_revoked_capability_token_cannot_execute_tool():
    reset_token_ledger()

    prepare_resp = client.post(
        "/tool-proxy/two-phase/prepare",
        json=_body(),
    )

    assert prepare_resp.status_code == 200

    token = prepare_resp.json()["capability_token"]["token"]

    revoke_resp = client.post(
        "/tool-proxy/capability-token/revoke",
        json={
            "token": token,
            "reason": "user cancelled task",
        },
    )

    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["success"] is True
    assert revoke_resp.json()["ledger_status"] == "revoked"

    execute_resp = client.post(
        "/tool-proxy/two-phase/execute",
        json=_body(capability_token=token, execute=True),
    )

    assert execute_resp.status_code == 200

    result = execute_resp.json()

    assert result["decision"] == "deny"
    assert result["executed"] is False

    token_stage = next(
        item for item in result["authorization_trace"]
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"

    reasons = " ".join(token_stage["reason"])
    assert "revoked" in reasons
