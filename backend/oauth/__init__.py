"""OAuth support for the AgentGuard MCP protected resource and local demo server."""

from backend.oauth.token_service import (
    issue_access_token,
    normalize_scopes,
    verify_access_token,
)

__all__ = [
    "issue_access_token",
    "normalize_scopes",
    "verify_access_token",
]
