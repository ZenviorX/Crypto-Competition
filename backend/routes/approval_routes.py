from fastapi import APIRouter

from backend.approval import list_pending_requests, pop_pending_request, get_pending_request
from backend.audit import write_log
from backend.gateway import check_tool_call
from backend.schemas import ApprovalRejectRequest, ToolCallRequest
from backend.tools import execute_tool


router = APIRouter()


@router.get("/approval/pending")
def approval_pending(limit: int = 50):
    return {
        "pending": list_pending_requests(limit),
    }


@router.post("/approval/confirm/{pending_id}")
def approval_confirm(pending_id: str):
    pending = get_pending_request(pending_id)

    if pending is None:
        return {
            "success": False,
            "message": "pending_id does not exist or has already been handled",
        }

    tool_request_data = pending["tool_request"]
    tool_request = ToolCallRequest(
        user=tool_request_data["user"],
        tool=tool_request_data["tool"],
        params=tool_request_data["params"],
    )

    recheck_result = check_tool_call(tool_request)

    if recheck_result["decision"] == "deny":
        pop_pending_request(pending_id)
        write_log(
            user=tool_request.user,
            tool=tool_request.tool,
            params=tool_request.params,
            gateway_result=recheck_result,
            executed=False,
            original_input=pending.get("original_input"),
            message="Manual confirmation blocked by second Gateway check",
            pending_id=pending_id,
        )

        return {
            "success": True,
            "executed": False,
            "message": "Second Gateway check denied this pending request; tool was not executed",
            "pending_id": pending_id,
            "tool_request": tool_request_data,
            "gateway_result": recheck_result,
            "tool_result": None,
        }

    normalized_tool = recheck_result.get("normalized_tool", tool_request.tool)
    normalized_params = recheck_result.get("normalized_params", tool_request.params)
    tool_result = execute_tool(normalized_tool, normalized_params)

    pop_pending_request(pending_id)

    gateway_result = dict(recheck_result)
    gateway_result["decision"] = "confirmed"

    write_log(
        user=tool_request.user,
        tool=normalized_tool,
        params=normalized_params,
        gateway_result=gateway_result,
        executed=True,
        original_input=pending.get("original_input"),
        message="Tool executed after manual confirmation and second Gateway check",
        pending_id=pending_id,
        tool_result=tool_result,
    )

    return {
        "success": True,
        "executed": True,
        "message": "Manual confirmation succeeded; tool was executed after second Gateway check",
        "pending_id": pending_id,
        "tool_request": tool_request_data,
        "gateway_result": gateway_result,
        "tool_result": tool_result,
    }


@router.post("/approval/reject/{pending_id}")
def approval_reject(pending_id: str, request: ApprovalRejectRequest):
    pending = pop_pending_request(pending_id)

    if pending is None:
        return {
            "success": False,
            "message": "pending_id does not exist or has already been handled",
        }

    tool_request_data = pending["tool_request"]
    gateway_result = pending["gateway_result"]
    gateway_result["decision"] = "rejected"

    write_log(
        user=tool_request_data["user"],
        tool=tool_request_data["tool"],
        params=tool_request_data["params"],
        gateway_result=gateway_result,
        executed=False,
        original_input=pending.get("original_input"),
        message=request.reason,
        pending_id=pending_id,
    )

    return {
        "success": True,
        "message": "Pending tool call rejected manually",
        "pending_id": pending_id,
        "reason": request.reason,
    }
