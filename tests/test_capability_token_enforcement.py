from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.tool_proxy_service import authorize_tool_call


def _normal_request(capability_token: str = "") -> ToolProxyAuthorizeRequest:
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


def test_valid_capability_token_can_be_reused_for_same_task():
    first = authorize_tool_call(_normal_request())
    token = first.capability_token["token"]

    second = authorize_tool_call(_normal_request(capability_token=token))

    assert second.decision == "allow"

    token_stage = next(
        item for item in second.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "allow"
    assert token_stage["extra"]["provided"] is True


def test_tampered_capability_token_is_denied():
    first = authorize_tool_call(_normal_request())
    token = first.capability_token["token"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    result = authorize_tool_call(_normal_request(capability_token=tampered))

    assert result.decision == "deny"

    token_stage = next(
        item for item in result.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"
