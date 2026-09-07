"""MCP protocol adapter for the AgentGuard authorization and sandbox pipeline."""

from backend.mcp.service import (
    InsufficientScopeError,
    McpProtocolError,
    handle_mcp_request,
)

__all__ = [
    "InsufficientScopeError",
    "McpProtocolError",
    "handle_mcp_request",
]
