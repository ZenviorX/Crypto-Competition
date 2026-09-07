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


def test_capability_token_events_record_issue_and_consume():
    reset_token_ledger()

    prepare_resp = client.post(
        "/tool-proxy/two-phase/prepare",
        json=_body(),
    )

    token = prepare_resp.json()["capability_token"]["token"]

    execute_resp = client.post(
        "/tool-proxy/two-phase/execute",
        json=_body(capability_token=token, execute=True),
    )

    assert execute_resp.json()["decision"] == "allow"

    events_resp = client.post(
        "/tool-proxy/capability-token/events",
        json={"token": token},
    )

    assert events_resp.status_code == 200

    events = events_resp.json()["events"]
    event_names = [item["event"] for item in events]

    assert "issued" in event_names
    assert "consumed" in event_names


def test_capability_token_events_record_revoke():
    reset_token_ledger()

    prepare_resp = client.post(
        "/tool-proxy/two-phase/prepare",
        json=_body(),
    )

    token = prepare_resp.json()["capability_token"]["token"]

    revoke_resp = client.post(
        "/tool-proxy/capability-token/revoke",
        json={
            "token": token,
            "reason": "manual test revoke",
        },
    )

    assert revoke_resp.json()["ledger_status"] == "revoked"

    events_resp = client.post(
        "/tool-proxy/capability-token/events",
        json={"token": token},
    )

    events = events_resp.json()["events"]
    event_names = [item["event"] for item in events]

    assert "issued" in event_names
    assert "revoked" in event_names
