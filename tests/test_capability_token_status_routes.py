from fastapi.testclient import TestClient

from backend.main import app
from backend.guardrails.capability_token_ledger import reset_token_ledger

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


def test_capability_token_status_api_changes_from_issued_to_consumed():
    reset_token_ledger()

    prepare_resp = client.post(
        "/tool-proxy/two-phase/prepare",
        json=_body(),
    )

    assert prepare_resp.status_code == 200

    phase1 = prepare_resp.json()
    token = phase1["capability_token"]["token"]

    issued_status_resp = client.post(
        "/tool-proxy/capability-token/status",
        json={"token": token},
    )

    assert issued_status_resp.status_code == 200

    issued_status = issued_status_resp.json()

    assert issued_status["valid"] is True
    assert issued_status["ledger_status"] == "issued"

    execute_resp = client.post(
        "/tool-proxy/two-phase/execute",
        json=_body(capability_token=token, execute=True),
    )

    assert execute_resp.status_code == 200
    assert execute_resp.json()["decision"] == "allow"

    consumed_status_resp = client.post(
        "/tool-proxy/capability-token/status",
        json={"token": token},
    )

    assert consumed_status_resp.status_code == 200

    consumed_status = consumed_status_resp.json()

    assert consumed_status["valid"] is True
    assert consumed_status["ledger_status"] == "consumed"
    assert consumed_status["consumed_at"] is not None


def test_capability_token_status_api_rejects_tampered_token():
    reset_token_ledger()

    prepare_resp = client.post(
        "/tool-proxy/two-phase/prepare",
        json=_body(),
    )

    token = prepare_resp.json()["capability_token"]["token"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    status_resp = client.post(
        "/tool-proxy/capability-token/status",
        json={"token": tampered},
    )

    assert status_resp.status_code == 200

    result = status_resp.json()

    assert result["valid"] is False
    assert result["ledger_status"] == "invalid"
