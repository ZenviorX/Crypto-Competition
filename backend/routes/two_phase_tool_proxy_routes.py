from __future__ import annotations

from fastapi import APIRouter

from backend.proxy.proxy_models import ToolProxyAuthorizeRequest, ToolProxyAuthorizeResponse
from backend.proxy.two_phase_tool_proxy_service import (
    execute_tool_with_capability,
    prepare_tool_authorization,
)

router = APIRouter(
    prefix="/tool-proxy/two-phase",
    tags=["Two Phase Tool Proxy"],
)


@router.post("/prepare", response_model=ToolProxyAuthorizeResponse)
def prepare_tool_call(request: ToolProxyAuthorizeRequest) -> ToolProxyAuthorizeResponse:
    return prepare_tool_authorization(request)


@router.post("/execute", response_model=ToolProxyAuthorizeResponse)
def execute_tool_call(request: ToolProxyAuthorizeRequest) -> ToolProxyAuthorizeResponse:
    return execute_tool_with_capability(request)
