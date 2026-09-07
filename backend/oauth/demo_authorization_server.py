from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import time
from typing import Any, Dict
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from backend.oauth.token_service import issue_access_token, mcp_resource, normalize_scopes, oauth_issuer


app = FastAPI(
    title="AgentGuard Demo OAuth Authorization Server",
    description=(
        "Local competition/demo OAuth 2.1 Authorization Code + PKCE server. "
        "It is intentionally minimal and must not be used as a production identity provider."
    ),
    version="0.1.0",
)

_AUTHORIZATION_CODES: Dict[str, Dict[str, Any]] = {}

_CLIENT_STORE_PATH = Path("runtime_workspace/oauth_registered_clients.json")

def _load_registered_clients() -> Dict[str, Dict[str, Any]]:
    try:
        if _CLIENT_STORE_PATH.exists():
            return json.loads(_CLIENT_STORE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def _save_registered_clients() -> None:
    _CLIENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CLIENT_STORE_PATH.write_text(
        json.dumps(_REGISTERED_CLIENTS, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

_REGISTERED_CLIENTS: Dict[str, Dict[str, Any]] = _load_registered_clients()
DEMO_CLIENT_ID = os.getenv("AGENTGUARD_OAUTH_DEMO_CLIENT_ID", "agentguard-demo-client")
DEMO_USER = os.getenv("AGENTGUARD_OAUTH_DEMO_USER", "demo-user")
CODE_TTL_SECONDS = 120
SUPPORTED_SCOPES = [
    "mcp:tools:list",
    "mcp:tasks:manage",
    "mcp:approvals:read",
    "mcp:approvals:decide",
    "mcp:revocations:read",
    "mcp:revocations:write",
    "tool:file:read",
    "tool:file:write",
    "tool:file:delete",
    "tool:email:send",
    "tool:shell:run",
    "tool:db:query",
    "sink:side-effect",
    "sink:external-email",
    "source:sensitive-file",
]


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": error,
            "error_description": description,
        },
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


def _is_local_redirect_uri(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return False

    return (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.port is not None
        and bool(parsed.path)
    )


def _redirect_with_params(redirect_uri: str, params: Dict[str, str]) -> RedirectResponse:
    parsed = urlparse(redirect_uri)
    existing = parse_qs(parsed.query, keep_blank_values=True)

    for key, value in params.items():
        existing[key] = [value]

    query = urlencode(
        [(key, item) for key, values in existing.items() for item in values]
    )
    target = urlunparse(parsed._replace(query=query))
    return RedirectResponse(target, status_code=302)


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@app.get("/", response_class=HTMLResponse)
def browser_console() -> HTMLResponse:
    issuer = html.escape(oauth_issuer())
    resource = html.escape(mcp_resource())
    metadata = f"{issuer}/.well-known/oauth-authorization-server"
    health_url = f"{issuer}/health"

    content = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentGuard Demo OAuth Server</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
    main {{ max-width: 860px; margin: 48px auto; padding: 0 24px; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 16px; padding: 28px; box-shadow: 0 18px 45px rgba(0,0,0,.25); }}
    h1 {{ margin-top: 0; color: #f8fafc; }}
    .ok {{ display: inline-block; padding: 5px 10px; border-radius: 999px; background: #064e3b; color: #a7f3d0; font-weight: 700; }}
    code {{ background: #020617; padding: 3px 7px; border-radius: 6px; color: #93c5fd; }}
    a {{ color: #7dd3fc; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 22px; }}
    td {{ border-top: 1px solid #334155; padding: 12px 8px; vertical-align: top; }}
    td:first-child {{ width: 220px; color: #94a3b8; }}
    .warning {{ margin-top: 22px; padding: 14px 16px; border-left: 4px solid #f59e0b; background: #78350f55; }}
  </style>
</head>
<body>
<main>
  <section class="card">
    <span class="ok">RUNNING</span>
    <h1>AgentGuard Demo OAuth Authorization Server</h1>
    <p>本页面用于确认本地 OAuth 演示进程已经启动。</p>
    <table>
      <tr><td>Issuer</td><td><code>{issuer}</code></td></tr>
      <tr><td>受保护资源</td><td><code>{resource}</code></td></tr>
      <tr><td>演示 Client ID</td><td><code>{html.escape(DEMO_CLIENT_ID)}</code></td></tr>
      <tr><td>Authorization Server Metadata</td><td><a href="{metadata}">{metadata}</a></td></tr>
      <tr><td>Health</td><td><a href="{health_url}">{health_url}</a></td></tr>
    </table>
    <div class="warning">
      这是 localhost 决赛演示组件，不是生产级身份提供方。完整授权流程请运行 <code>python examples/mcp_oauth_demo_client.py</code>。
    </div>
  </section>
</main>
</body>
</html>"""
    return HTMLResponse(content, headers={"Cache-Control": "no-store"})


@app.get("/.well-known/oauth-authorization-server")
def authorization_server_metadata() -> Dict[str, Any]:
    issuer = oauth_issuer()
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "registration_endpoint": f"{issuer}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": SUPPORTED_SCOPES,
    }


@app.post("/register")
async def register_client(request: Request):
    try:
        metadata = await request.json()
    except Exception:
        return _oauth_error("invalid_client_metadata", "Client metadata must be valid JSON.")

    redirect_uris = metadata.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _oauth_error("invalid_redirect_uri", "At least one redirect_uri is required.")

    for uri in redirect_uris:
        if not _is_local_redirect_uri(str(uri)):
            return _oauth_error(
                "invalid_redirect_uri",
                "Only explicit localhost HTTP redirect URIs are accepted by the demo server.",
            )

    client_id = "agentguard-" + secrets.token_urlsafe(24)

    record = {
        "client_id": client_id,
        "redirect_uris": [str(uri) for uri in redirect_uris],
        "client_name": str(metadata.get("client_name") or "Dynamic MCP Client"),
        "client_uri": str(metadata.get("client_uri") or ""),
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }

    _REGISTERED_CLIENTS[client_id] = record
    _save_registered_clients()

    return JSONResponse(
        status_code=201,
        content={
            **record,
            "client_id_issued_at": int(time.time()),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/authorize")
def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default=""),
    state: str = Query(default=""),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(default="S256"),
    resource: str = Query(...),
    approve: bool = Query(default=True),
    user: str = Query(default=DEMO_USER),
):
    if response_type != "code":
        return _oauth_error("unsupported_response_type", "The demo server only supports response_type=code.")

    if client_id != DEMO_CLIENT_ID and client_id not in _REGISTERED_CLIENTS:
        return _oauth_error("unauthorized_client", "Unknown OAuth client_id.")

    if client_id in _REGISTERED_CLIENTS:
        allowed_redirects = _REGISTERED_CLIENTS[client_id].get("redirect_uris", [])
        if redirect_uri not in allowed_redirects:
            return _oauth_error("invalid_request", "redirect_uri is not registered for this client.")

    if not _is_local_redirect_uri(redirect_uri):
        return _oauth_error("invalid_request", "Only explicit localhost HTTP redirect URIs are accepted by the demo server.")

    if resource.rstrip("/") != mcp_resource().rstrip("/"):
        return _oauth_error("invalid_target", "The requested resource is not the configured AgentGuard MCP endpoint.")

    if code_challenge_method != "S256" or not code_challenge:
        return _oauth_error("invalid_request", "PKCE with code_challenge_method=S256 is required.")

    requested_scopes = normalize_scopes(scope)
    unsupported = [item for item in requested_scopes if item not in SUPPORTED_SCOPES]
    if unsupported:
        return _oauth_error("invalid_scope", "Unsupported scope(s): " + ", ".join(unsupported))

    if not approve:
        return _redirect_with_params(
            redirect_uri,
            {
                "error": "access_denied",
                "error_description": "The local demo user denied authorization.",
                "state": state,
            },
        )

    code = secrets.token_urlsafe(32)
    _AUTHORIZATION_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": requested_scopes,
        "resource": resource.rstrip("/"),
        "subject": user,
        "code_challenge": code_challenge,
        "expires_at": time.time() + CODE_TTL_SECONDS,
    }

    return _redirect_with_params(
        redirect_uri,
        {
            "code": code,
            "state": state,
        },
    )


@app.post("/token")
async def token(request: Request):
    raw_body = (await request.body()).decode("utf-8", errors="replace")
    form = {key: values[-1] for key, values in parse_qs(raw_body).items() if values}

    grant_type = form.get("grant_type", "")
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    client_id = form.get("client_id", "")
    code_verifier = form.get("code_verifier", "")
    resource = form.get("resource", "").rstrip("/")

    if grant_type != "authorization_code":
        return _oauth_error("unsupported_grant_type", "The demo server only supports authorization_code.")

    record = _AUTHORIZATION_CODES.pop(code, None)
    if record is None:
        return _oauth_error("invalid_grant", "Authorization code is invalid or has already been used.")

    if float(record.get("expires_at", 0)) < time.time():
        return _oauth_error("invalid_grant", "Authorization code has expired.")

    if client_id != record.get("client_id") or redirect_uri != record.get("redirect_uri"):
        return _oauth_error("invalid_grant", "Authorization code is not bound to this client or redirect URI.")

    if resource != str(record.get("resource", "")):
        return _oauth_error("invalid_target", "Token request resource does not match the authorization request.")

    if not code_verifier or _pkce_s256(code_verifier) != record.get("code_challenge"):
        return _oauth_error("invalid_grant", "PKCE code_verifier validation failed.")

    token_response = issue_access_token(
        subject=str(record.get("subject", DEMO_USER)),
        scopes=record.get("scope", []),
        audience=resource,
        client_id=client_id,
        ttl_seconds=3600,
    )
    token_response.pop("payload", None)

    return JSONResponse(
        content=token_response,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "mode": "local_demo_only",
        "issuer": oauth_issuer(),
        "resource": mcp_resource(),
        "client_id": DEMO_CLIENT_ID,
        "warning": "This minimal OAuth server is for local competition demonstration, not production deployment.",
    }