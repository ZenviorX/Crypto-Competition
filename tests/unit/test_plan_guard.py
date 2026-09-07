from backend.schemas import AgentPlanResult, ToolCallPlan
from backend.agents.plan_guard import inspect_agent_plan


def test_unsupported_plan_is_denied():
    plan = AgentPlanResult(
        agent="FakeAgent",
        status="unsupported",
        original_input="帮我控制摄像头",
        confidence=0.0,
        tool_call=None,
        unsupported_reason="unsupported tool",
    )

    result = inspect_agent_plan(plan)

    assert result["decision"] == "deny"
    assert result["pass_to_gateway"] is False


def test_missing_param_requires_confirm():
    plan = AgentPlanResult(
        agent="FakeAgent",
        status="planned",
        original_input="帮我发邮件",
        confidence=0.8,
        tool_call=ToolCallPlan(
            tool_name="email.send",
            description="发送邮件",
            arguments={
                "to": "unknown",
                "content": "",
            },
            need_auth=True,
        ),
    )

    result = inspect_agent_plan(plan)

    assert result["decision"] == "confirm"
    assert result["pass_to_gateway"] is False


def test_valid_plan_passes_to_gateway():
    plan = AgentPlanResult(
        agent="FakeAgent",
        status="planned",
        original_input="读取文件 public/notice.txt",
        confidence=0.95,
        tool_call=ToolCallPlan(
            tool_name="file.read",
            description="读取文件",
            arguments={
                "file_path": "public/notice.txt",
            },
            need_auth=True,
        ),
    )

    result = inspect_agent_plan(plan)

    assert result["pass_to_gateway"] is True
    assert result["decision"] == "allow"