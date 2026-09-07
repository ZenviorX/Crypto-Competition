from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.tool_proxy_service import authorize_tool_call


def _request(original_task: str, capability_token: str = "") -> ToolProxyAuthorizeRequest:
    return ToolProxyAuthorizeRequest(
        user="user",
        original_task=original_task,
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


def test_capability_token_cannot_be_replayed_across_tasks():
    first = authorize_tool_call(
        _request("请读取 public/notice.txt 并总结")
    )

    token = first.capability_token["token"]

    second = authorize_tool_call(
        _request(
            original_task="请读取 public/readme.txt 并总结",
            capability_token=token,
        )
    )

    assert second.decision == "deny"

    token_stage = next(
        item for item in second.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"

    reasons = " ".join(token_stage["reason"])
    assert "different original task" in reasons
