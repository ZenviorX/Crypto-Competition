from __future__ import annotations

from backend.proxy.proxy_models import ToolProxyAuthorizeRequest, ToolProxyAuthorizeResponse
from backend.proxy.tool_proxy_service import authorize_tool_call


def prepare_tool_authorization(
    request: ToolProxyAuthorizeRequest,
) -> ToolProxyAuthorizeResponse:
    """
    Phase 1:
    Only authorize the request and issue a task-scoped capability token.
    The tool is not executed in this phase.
    """
    prepared_request = request.model_copy(
        update={
            "execute": False,
            "capability_token": "",
        }
    )
    return authorize_tool_call(prepared_request)


def execute_tool_with_capability(
    request: ToolProxyAuthorizeRequest,
) -> ToolProxyAuthorizeResponse:
    """
    Phase 2:
    Execute the tool only when the request carries a valid task-scoped
    capability token issued in Phase 1.
    """
    execution_request = request.model_copy(
        update={
            "execute": True,
        }
    )
    return authorize_tool_call(execution_request)
