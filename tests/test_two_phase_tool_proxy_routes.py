from fastapi.testclient import TestClient

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


def test_two_phase_api_prepare_then_execute():
    prepare_resp = client.post(
        "/tool-proxy/two-phase/prepare",
        json=_body(),
    )

    assert prepare_resp.status_code == 200

    phase1 = prepare_resp.json()

    assert phase1["decision"] == "allow"
    assert phase1["executed"] is False
    assert phase1["capability_token"]["issued"] is True

    token = phase1["capability_token"]["token"]

    execute_resp = client.post(
        "/tool-proxy/two-phase/execute",
        json=_body(capability_token=token, execute=True),
    )

    assert execute_resp.status_code == 200

    phase2 = execute_resp.json()

    assert phase2["decision"] == "allow"
    assert phase2["executed"] is True


def test_two_phase_api_execute_without_token_is_denied():
    execute_resp = client.post(
        "/tool-proxy/two-phase/execute",
        json=_body(execute=True),
    )

    assert execute_resp.status_code == 200

    result = execute_resp.json()

    assert result["decision"] == "deny"
    assert result["executed"] is False
