from backend.schemas import ToolCallRequest
from backend.gateway.gateway import check_tool_call


def test_unknown_tool_is_denied():
    result = check_tool_call(
        ToolCallRequest(
            user="user",
            tool="camera.capture",
            params={},
        )
    )

    assert result["decision"] == "deny"


def test_low_confidence_is_denied():
    result = check_tool_call(
        ToolCallRequest(
            user="user",
            tool="file.read",
            params={"path": "public/notice.txt"},
            agent_confidence=0.3,
        )
    )

    assert result["decision"] == "deny"


def test_missing_param_is_denied_by_fail_closed_policy():
    result = check_tool_call(
        ToolCallRequest(
            user="user",
            tool="email.send",
            params={"to": "unknown", "content": ""},
            agent_confidence=0.9,
        )
    )

    assert result["decision"] == "deny"
    assert any(
        "失败关闭" in item
        for item in result["reason"]
    )
