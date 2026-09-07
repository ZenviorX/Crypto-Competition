from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict


DEFAULT_AUTH_SERVER = "http://127.0.0.1:9000"
DEFAULT_MCP_ENDPOINT = "http://127.0.0.1:8000/mcp"
DEFAULT_CLIENT_ID = "agentguard-demo-client"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8765/callback"
DEFAULT_SCOPES = "mcp:tools:list mcp:tasks:manage tool:file:read"

PROTOCOL_VERSION = "2025-11-25"

# ---------------------------------------------------------
# Competition demo output
# ---------------------------------------------------------

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"


def _line(char: str = "═", width: int = 62) -> None:
    print(char * width)


def _stage(index: int, title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}[{index}/4] {title}{RESET}")


def _ok(message: str) -> None:
    print(f"  {GREEN}✓{RESET} {message}")


def _short(value: str, head: int = 10, tail: int = 6) -> str:
    value = str(value or "")
    if len(value) <= head + tail + 3:
        return value
    return value[:head] + "..." + value[-tail:]


def _cn_scope(scope: str) -> str:
    mapping = {
        "mcp:tools:list": "MCP 工具发现",
        "mcp:tasks:manage": "可信任务管理",
        "tool:email:send": "邮件发送",
        "sink:side-effect": "副作用操作",
        "sink:external-email": "外部发送",
        "tool:file:read": "文件读取",
        "tool:file:write": "文件写入",
        "tool:file:delete": "文件删除",
        "source:sensitive-file": "敏感文件访问",
    }
    return mapping.get(scope, scope)


def _reason_cn(reason: str) -> str:
    text = str(reason or "")

    mapping = [
        (
            "Tool email.send is explicitly forbidden by the capability contract.",
            "邮件发送超出当前可信任务边界",
        ),
        (
            "Capability Contract forbids side-effect tools for this task.",
            "当前任务禁止副作用工具",
        ),
        (
            "Capability Contract forbids external transmission.",
            "当前任务禁止外部传输",
        ),
        (
            "Task Boundary Guard evaluated this tool call.",
            "已根据可信任务边界检查本次工具调用",
        ),
        (
            "Capability Contract was derived from the original task.",
            "授权约束由用户原始任务生成",
        ),
        (
            "Task Boundary Guard checked the requested tool call against this contract.",
            "已依据授权约束检查实际工具请求",
        ),
    ]

    for source, target in mapping:
        if text == source:
            return target

    if text == "Attack chain detector:":
        return ""

    return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _authorization_code(
    *,
    auth_server: str,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    resource: str,
) -> tuple[str, str]:
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scopes,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
            "approve": "true",
        }
    )
    request = urllib.request.Request(f"{auth_server.rstrip('/')}/authorize?{query}")
    opener = urllib.request.build_opener(_NoRedirect)

    location = ""
    try:
        response = opener.open(request, timeout=10)
        location = response.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise
        location = exc.headers.get("Location", "")

    if not location:
        raise RuntimeError("OAuth authorization endpoint did not return a redirect URI.")

    parsed = urllib.parse.urlparse(location)
    values = urllib.parse.parse_qs(parsed.query)

    returned_state = values.get("state", [""])[0]
    if returned_state != state:
        raise RuntimeError("OAuth state mismatch.")

    if values.get("error"):
        raise RuntimeError(
            f"OAuth authorization failed: {values.get('error', [''])[0]} "
            f"{values.get('error_description', [''])[0]}"
        )

    code = values.get("code", [""])[0]
    if not code:
        raise RuntimeError("OAuth authorization redirect did not contain a code.")

    return code, verifier


def _exchange_token(
    *,
    auth_server: str,
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    resource: str,
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": code_verifier,
            "resource": resource,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{auth_server.rstrip('/')}/token",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _mcp_request(
    *,
    endpoint: str,
    access_token: str,
    payload: Dict[str, Any],
) -> Dict[str, Any] | None:
    method = str(payload.get("method") or "")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }

    if method == "tools/call":
        params = payload.get("params", {}) or {}
        headers["Mcp-Name"] = str(params.get("name") or "")

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers=headers,
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        challenge = exc.headers.get("WWW-Authenticate", "")
        raise RuntimeError(
            f"MCP HTTP {exc.code}: {raw}\nWWW-Authenticate: {challenge}"
        ) from exc


def run_demo(args: argparse.Namespace) -> int:
    code, verifier = _authorization_code(
        auth_server=args.auth_server,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        scopes=args.scopes,
        resource=args.mcp_endpoint,
    )
    token_response = _exchange_token(
        auth_server=args.auth_server,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        code=code,
        code_verifier=verifier,
        resource=args.mcp_endpoint,
    )
    access_token = str(token_response.get("access_token") or "")
    if not access_token:
        raise RuntimeError(f"OAuth token response does not contain access_token: {token_response}")

    _line()
    print(f"{BOLD}  AgentGuard · OAuth + MCP 动态授权演示{RESET}")
    _line()

    _stage(1, "OAuth 授权")
    _ok("访问令牌获取成功")
    print("  权限：")
    for scope in str(token_response.get("scope") or "").split():
        print(f"    • {_cn_scope(scope)}")

    initialize = _mcp_request(
        endpoint=args.mcp_endpoint,
        access_token=access_token,
        payload={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "agentguard-python-demo-client",
                    "version": "0.1.0",
                },
            },
        },
    )
    _stage(2, "MCP 接入")
    server_info = ((initialize or {}).get("result") or {}).get("serverInfo") or {}
    _ok(
        "AgentGuard MCP Gateway 连接成功"
        + (
            f"（v{server_info.get('version')}）"
            if server_info.get("version")
            else ""
        )
    )

    _mcp_request(
        endpoint=args.mcp_endpoint,
        access_token=access_token,
        payload={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        },
    )

    tools = _mcp_request(
        endpoint=args.mcp_endpoint,
        access_token=access_token,
        payload={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
    )
    visible_tools = (
        ((tools or {}).get("result") or {}).get("tools")
        or []
    )
    visible_names = [
        str(item.get("name") or "")
        for item in visible_tools
        if isinstance(item, dict) and item.get("name")
    ]

    if visible_names:
        _ok(
            "当前 OAuth 权限允许发现工具："
            + ", ".join(visible_names)
        )
    else:
        _ok("OAuth 工具过滤完成")

    if args.discover_only:
        return 0

    task_response = _mcp_request(
        endpoint=args.mcp_endpoint,
        access_token=access_token,
        payload={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "agentguard/tasks/create",
            "params": {
                "originalTask": args.task,
            },
        },
    )

    _stage(3, "可信任务")
    _ok("服务端已创建可信任务")
    print(f"  任务：{args.task}")

    task_handle = str(
        ((task_response or {}).get("result") or {}).get("taskHandle")
        or ""
    )

    if not task_handle:
        raise RuntimeError(
            "agentguard/tasks/create did not return taskHandle."
        )

    print(f"  Task Handle：{_short(task_handle)}")

    try:
        arguments = json.loads(args.arguments_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"--arguments-json is invalid JSON: {exc}") from exc

    if not isinstance(arguments, dict):
        raise RuntimeError("--arguments-json must decode to a JSON object.")

    call_result = _mcp_request(
        endpoint=args.mcp_endpoint,
        access_token=access_token,
        payload={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": args.tool,
                "arguments": arguments,
                "_meta": {
                    "agentguard/taskHandle": task_handle,
                    "agentguard/sandboxProfile": args.sandbox_profile,
                    "agentguard/agentPlatform": "python-demo-client",
                },
            },
        },
    )
    _stage(4, "AgentGuard 动态裁定")

    structured = (
        ((call_result or {}).get("result") or {})
        .get("structuredContent")
        or {}
    )

    decision = str(
        structured.get("decision") or "unknown"
    ).lower()

    risk_score = int(
        structured.get("risk_score") or 0
    )

    executed = bool(
        structured.get("executed")
    )

    print()
    print(f"  请求工具：{args.tool}")

    if args.tool == "email.send":
        print(
            "  目标地址："
            + str(arguments.get("to") or "")
        )
    elif args.tool.startswith("file."):
        print(
            "  目标资源："
            + str(arguments.get("path") or "")
        )

    print()

    labels = {
        "allow": ("ALLOW  允许执行", GREEN),
        "confirm": ("CONFIRM  等待确认", YELLOW),
        "deny": ("DENY  拒绝执行", RED),
    }

    label, color = labels.get(
        decision,
        (decision.upper(), CYAN),
    )

    print("  ┌─────────────────────────────────────────┐")
    print(
        f"  │{color}{BOLD}"
        + label.center(41)
        + f"{RESET}│"
    )
    print("  └─────────────────────────────────────────┘")

    print()
    print(f"  风险分数：{risk_score} / 100")
    print(
        "  是否执行："
        + (
            f"{GREEN}是{RESET}"
            if executed
            else f"{RED}否{RESET}"
        )
    )

    reasons = structured.get("reason") or []

    clean_reasons = []
    for reason in reasons:
        converted = _reason_cn(str(reason))
        if converted and converted not in clean_reasons:
            clean_reasons.append(converted)

    if clean_reasons:
        print()
        print("  裁定依据：")
        for reason in clean_reasons[:5]:
            print(f"    • {reason}")

    print()
    _line()

    if decision == "deny" and not executed:
        print(
            f"{BOLD}"
            "  OAuth 权限已通过，但 AgentGuard 阻止了任务越界行为"
            f"{RESET}"
        )
    elif decision == "allow" and executed:
        print(
            f"{BOLD}"
            "  授权通过，并已进入受控执行环境"
            f"{RESET}"
        )
    elif decision == "confirm":
        print(
            f"{BOLD}"
            "  高副作用操作已暂停，等待人工确认"
            f"{RESET}"
        )

    _line()

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the localhost OAuth + MCP + AgentGuard competition demo."
    )
    parser.add_argument("--auth-server", default=DEFAULT_AUTH_SERVER)
    parser.add_argument("--mcp-endpoint", default=DEFAULT_MCP_ENDPOINT)
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI)
    parser.add_argument("--scopes", default=DEFAULT_SCOPES)
    parser.add_argument(
        "--task",
        default="读取 public/notice.txt 并总结，不要修改或向外发送任何内容。",
    )
    parser.add_argument("--tool", default="file.read")
    parser.add_argument("--arguments-json", default='{"path": "public/notice.txt"}')
    parser.add_argument("--sandbox-profile", default="default")
    parser.add_argument("--discover-only", action="store_true")
    return parser


def main() -> int:
    try:
        return run_demo(build_parser().parse_args())
    except Exception as exc:
        print(f"[demo-error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
