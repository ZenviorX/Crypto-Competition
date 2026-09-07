from fastapi import APIRouter

from backend.gateway import check_tool_call, handle_tool_request
from backend.schemas import GatewayResponse, ToolCallRequest


router = APIRouter()


@router.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(request: ToolCallRequest):
    result = check_tool_call(request)

    return {
        "decision": result["decision"],
        "risk_score": result["risk_score"],
        "risk_level": result.get("risk_level", "low"),
        "reason": result["reason"],
        "explanations": result.get("explanations", []),
    }


@router.post("/gateway/call")
def gateway_call(request: ToolCallRequest):
    return handle_tool_request(request=request)


@router.post("/agent/call")
def agent_call(request: ToolCallRequest):
    return handle_tool_request(request=request)