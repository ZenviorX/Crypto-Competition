from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.proxy.proxy_models import (
    ToolProxyAuthorizeRequest,
    ToolProxyAuthorizeResponse,
)
from backend.proxy.tool_proxy_service import authorize_tool_call


router = APIRouter(
    prefix="/tool-proxy",
    tags=["Tool Proxy"],
)


@router.get("/health")
def tool_proxy_health():
    """
    Tool Proxy 健康检查接口。

    用于确认 Tool Proxy 路由已经成功注册。
    """

    return {
        "success": True,
        "message": "AgentGuard Tool Proxy is ready.",
        "routes": [
            "GET /tool-proxy/health",
            "POST /tool-proxy/authorize",
        ],
    }


@router.post(
    "/authorize",
    response_model=ToolProxyAuthorizeResponse,
)
def authorize_tool_proxy_request(
    request: ToolProxyAuthorizeRequest,
) -> ToolProxyAuthorizeResponse:
    """
    外部 Agent 工具调用安全检查接口。

    前端或第三方 Agent 可以把 tool + params 发到这里，
    AgentGuard 会返回 allow / confirm / deny。
    """

    try:
        return authorize_tool_call(request)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Tool Proxy authorize failed: {exc}",
        ) from exc
