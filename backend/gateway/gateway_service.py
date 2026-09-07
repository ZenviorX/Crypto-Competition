from typing import Optional, Dict, Any

from backend.schemas import ToolCallRequest
from backend.gateway.gateway import check_tool_call
from backend.tools.tool_executor import execute_tool
from backend.audit.audit_logger import write_log
from backend.utils import normalize_tool_name, normalize_params
from backend.approval.approval_store import create_pending_request


def handle_tool_request(
    request: ToolCallRequest,
    original_input: Optional[str] = None,
    agent_result: Optional[Dict[str, Any]] = None,
):
    """
    统一处理所有工具调用请求。

    注意：
    只接收结构化 ToolCallRequest，然后执行：

    1. 工具名和参数规范化
    2. 授权网关风险检查
    3. allow：执行工具
    4. confirm：进入人工确认队列
    5. deny：直接拦截
    6. 写入审计日志
    """

    normalized_tool = normalize_tool_name(request.tool)
    normalized_params = normalize_params(normalized_tool, request.params)

    normalized_request = ToolCallRequest(
        user=request.user,
        tool=normalized_tool,
        params=normalized_params,
        task_contract=request.task_contract,
        input_labels=request.input_labels,
        current_step=request.current_step,
        used_risk=request.used_risk,
        agent_confidence=request.agent_confidence,
        plan_status=request.plan_status,
        plan_warnings=request.plan_warnings,
        original_input=request.original_input or original_input,
    )
    check_result = check_tool_call(normalized_request)

    # deny：直接拦截
    if check_result["decision"] == "deny":
        write_log(
            user=normalized_request.user,
            tool=normalized_request.tool,
            params=normalized_request.params,
            gateway_result=check_result,
            executed=False,
            original_input=original_input,
            message="工具调用已被安全网关拦截",
        )

        return {
            "success": True,
            "executed": False,
            "message": "工具调用已被安全网关拦截",
            "source": "gateway",
            "agent_result": agent_result,
            "gateway_result": check_result,
            "tool_result": None,
            "pending_id": None
        }

    # confirm：进入人工确认队列
    if check_result["decision"] == "confirm":
        pending_id = create_pending_request(
            tool_request=normalized_request,
            gateway_result=check_result,
            original_input=original_input,
            agent_result=agent_result,
        )

        write_log(
            user=normalized_request.user,
            tool=normalized_request.tool,
            params=normalized_request.params,
            gateway_result=check_result,
            executed=False,
            original_input=original_input,
            message="工具调用需要人工确认，已进入 pending 队列",
            pending_id=pending_id,
        )

        return {
            "success": True,
            "executed": False,
            "message": "工具调用需要人工确认，已进入 pending 队列",
            "source": "gateway",
            "agent_result": agent_result,
            "gateway_result": check_result,
            "tool_result": None,
            "pending_id": pending_id
        }

    # allow：直接执行
    tool_result = execute_tool(
        normalized_request.tool,
        normalized_request.params
    )

    write_log(
        user=normalized_request.user,
        tool=normalized_request.tool,
        params=normalized_request.params,
        gateway_result=check_result,
        executed=True,
        original_input=original_input,
        message="工具调用已通过安全检查并执行",
        tool_result=tool_result,
    )

    return {
        "success": True,
        "executed": True,
        "message": "工具调用已通过安全检查并执行",
        "source": "gateway",
        "agent_result": agent_result,
        "gateway_result": check_result,
        "tool_result": tool_result,
        "pending_id": None
    }
