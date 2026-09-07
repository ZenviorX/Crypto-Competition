# AgentGuard MCP + OAuth 本地演示

本页用于决赛演示。它把项目拆成三个真实、独立的软件进程：

```text
Demo OAuth Authorization Server :9000
                  ↓ Authorization Code + PKCE / Access Token
Demo MCP Client
                  ↓ MCP Streamable HTTP + Bearer Token
AgentGuard MCP Security Gateway :8000/mcp
                  ↓ Tool Proxy / Task Boundary / Capability Token / Runtime / Sandbox
AgentGuard runtime_workspace
```

> `backend.oauth.demo_authorization_server` 是 localhost 竞赛演示服务器，不是生产级身份平台。生产部署应改接成熟 OAuth/OIDC Provider，并改用其 JWKS、token introspection 或受信任 JWT 验证配置。

## 1. 安装依赖

```powershell
python -m pip install -r requirements.txt
```

本次 MCP/OAuth 演示没有新增第三方 Python 依赖，JWT、PKCE 和 HTTP Demo Client 均使用 Python 标准库实现。

## 2. 一键启动后端、前端和 OAuth Demo Server

```powershell
python .\start_project.py --clean --with-oauth
```

启动后：

```text
AgentGuard API:       http://127.0.0.1:8000
MCP endpoint:         http://127.0.0.1:8000/mcp
Protected metadata:   http://127.0.0.1:8000/.well-known/oauth-protected-resource
OAuth demo server:    http://127.0.0.1:9000
OAuth metadata:       http://127.0.0.1:9000/.well-known/oauth-authorization-server
Frontend:             http://127.0.0.1:5173
```

也可以分别启动：

```powershell
python -m uvicorn backend.oauth.demo_authorization_server:app --host 127.0.0.1 --port 9000
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

## 3. 正常读取演示

第三个终端运行：

```powershell
python .\examples\mcp_oauth_demo_client.py
```

默认流程：

```text
1. Demo Client 生成 PKCE verifier/challenge
2. 请求 OAuth /authorize
3. 使用 authorization code + verifier 请求 /token
4. 携带 Bearer token 调用 MCP initialize
5. 调用 tools/list，只看到 token scopes 允许的工具
6. 调用 file.read public/notice.txt
7. AgentGuard 内部执行两阶段 Capability Token 授权
8. allow 后进入 Hybrid Sandbox
9. 返回 MCP Tool Result，并写入 Audit Evidence
```

默认 scopes：

```text
mcp:tools:list tool:file:read
```

## 4. OAuth 权限不足演示

只给工具发现权限，却尝试读取文件：

```powershell
python .\examples\mcp_oauth_demo_client.py `
  --scopes "mcp:tools:list" `
  --tool "file.read" `
  --arguments-json '{"path":"public/notice.txt"}'
```

预期结果：HTTP `403 insufficient_scope`，并在 `WWW-Authenticate` 中返回所需 scope。

## 5. OAuth 权限足够，但任务边界拒绝

OAuth token 允许邮件发送和副作用，但原始任务明确禁止外发：

```powershell
python .\examples\mcp_oauth_demo_client.py `
  --scopes "mcp:tools:list tool:email:send sink:side-effect sink:external-email" `
  --task "只读取并总结公开通知，不要发送邮件或向外部传输。" `
  --tool "email.send" `
  --arguments-json '{"to":"outside@example.com","content":"公开通知摘要"}'
```

预期结果：OAuth scope 检查通过，但 Task Boundary Guard 返回 `deny`。这用于说明：

```text
OAuth：用户/客户端是否拥有某类工具权限
AgentGuard：当前具体工具调用是否符合原始任务、参数和数据流边界
```

## 6. 工具发现范围

MCP `tools/list` 根据 Access Token scopes 动态过滤。当前工具及基础 scopes：

| MCP Tool | 基础 scope |
|---|---|
| `file.read` | `tool:file:read` |
| `file.write` | `tool:file:write sink:side-effect` |
| `file.delete` | `tool:file:delete sink:side-effect` |
| `email.send` | `tool:email:send sink:side-effect` |
| `shell.run` | `tool:shell:run sink:side-effect` |
| `db.query` | `tool:db:query` |

参数相关 scope 会在 `tools/call` 时动态补充，例如：

```text
外部邮箱：sink:external-email
敏感文件：source:sensitive-file
```

## 7. MCP 扩展任务上下文

标准 MCP `tools/call` 参数中没有 AgentGuard 的原始任务字段。本项目通过 MCP `_meta` 扩展传递：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "file.read",
    "arguments": {
      "path": "public/notice.txt"
    },
    "_meta": {
      "agentguard/originalTask": "读取 public/notice.txt 并总结，不要修改或外发。",
      "agentguard/sandboxProfile": "default"
    }
  }
}
```

HTTP Client 也可以通过 `X-AgentGuard-Task` 传递原始任务。

## 8. 环境变量

复制 `.env.example` 中的 MCP/OAuth 配置。至少应在本地改掉：

```text
AGENTGUARD_OAUTH_DEMO_SECRET
AGENTGUARD_CAPABILITY_SECRET
```

## 9. 测试

```powershell
pytest tests/unit/test_oauth_access_token.py -q
pytest tests/unit/test_mcp_tool_registry.py -q
pytest tests/unit/test_mcp_service.py -q
```

完整回归：

```powershell
python scripts/run_backend_authorization_tests.py
python -m test.run
```

## 10. 当前实现边界

已完成：

```text
MCP initialize / notifications/initialized / ping
MCP tools/list / tools/call
HTTP Bearer Token
OAuth Protected Resource Metadata
OAuth Authorization Server Metadata
Authorization Code + PKCE 本地演示
issuer / audience / expiry / signature 校验
OAuth scope 过滤和 insufficient_scope challenge
AgentGuard 两阶段 Capability Token 执行
Hybrid Sandbox 和 Audit Evidence
Origin 基础校验
```

未声称完成：

```text
生产级用户身份库和登录系统
动态客户端注册
refresh token
JWKS / asymmetric signing
第三方企业 IdP 集成
完整 SSE 流式传输
通用多下游 MCP Server 反向代理
```
