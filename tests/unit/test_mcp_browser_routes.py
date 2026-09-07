from fastapi.testclient import TestClient

from backend.main import app as agentguard_app
from backend.oauth.demo_authorization_server import app as oauth_app


agentguard_client = TestClient(agentguard_app)
oauth_client = TestClient(oauth_app)


def test_browser_get_mcp_renders_information_page():
    response = agentguard_client.get(
        "/mcp",
        headers={"Accept": "text/html"},
    )

    assert response.status_code == 200
    assert "AgentGuard MCP Security Gateway" in response.text
    assert "POST" in response.text
    assert "/mcp/status" in response.text


def test_non_browser_get_mcp_keeps_protocol_method_guard():
    response = agentguard_client.get(
        "/mcp",
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.json()["status_endpoint"] == "/mcp/status"


def test_mcp_status_is_browser_and_curl_safe():
    response = agentguard_client.get("/mcp/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["protocol_method"] == "POST"
    assert payload["protocol_endpoint"].endswith("/mcp")
    assert "tools/call" in payload["supported_methods"]


def test_oauth_demo_root_renders_console_page():
    response = oauth_client.get("/")

    assert response.status_code == 200
    assert "AgentGuard Demo OAuth Authorization Server" in response.text
    assert "/.well-known/oauth-authorization-server" in response.text
    assert "/health" in response.text
