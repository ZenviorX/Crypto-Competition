# AgentGuard：面向 MCP 与 AI Agent 工具调用的动态授权安全网关

> AgentGuard 位于 AI Agent 与真实工具执行之间。项目现已提供 OAuth 保护的 MCP Streamable HTTP 入口，并复用原有 Task Boundary、Capability Contract、Capability Token、Runtime Monitor、Attack Chain Detector、Hybrid Sandbox 和 Audit Evidence 安全链。

## 1. 项目定位

AI Agent 从“生成文本”发展到“调用文件、邮件、数据库、命令行和网络工具”之后，传统权限判断还不够。系统不仅要回答：

```text
用户和客户端是否拥有某类工具权限？
```

还要继续回答：

```text
当前工具调用是否符合用户原始任务？
工具参数是否越权？
数据是否从低可信来源流向危险工具？
是否形成提示注入、敏感访问和外发组合攻击链？
是否需要人工确认？
是否能够留下可复盘证据？
```

AgentGuard 的原则是：

```text
Agent 负责提出工具调用计划；
OAuth 负责外层身份与 scope；
AgentGuard 负责当前任务下的动态授权；
Capability Token 绑定单次执行；
Sandbox 负责受控执行；
Audit Evidence 负责复盘。
```

## 2. 当前主链路

```text
MCP Client / External Agent
        ↓
OAuth Authorization Code + PKCE
        ↓ Bearer Access Token
AgentGuard /mcp
        ↓
OAuth Resource Server 校验
  ├─ signature
  ├─ issuer
  ├─ audience/resource
  ├─ expiry
  └─ scopes
        ↓
MCP Adapter
  ├─ initialize
  ├─ tools/list
  └─ tools/call
        ↓
Tool Proxy Prepare
        ↓
Task Boundary / Capability Contract / Runtime Monitor
        ↓
allow / confirm / deny
        ↓ allow
Task-scoped Capability Token
        ↓
Tool Proxy Execute
        ↓
Hybrid Sandbox
        ↓
Tool Result + Sandbox Evidence + Audit Hash Chain
        ↓
MCP Tool Result
```

## 3. OAuth 与 AgentGuard 的分工

| 层 | 判断问题 | 示例 |
|---|---|---|
| OAuth Access Token | 调用方能否使用某类工具 | 是否拥有 `tool:file:read` |
| Task Boundary | 当前动作是否符合原始任务 | “只总结”任务是否允许发邮件 |
| Capability Contract | 工具、资源、步骤和风险是否在任务授权范围 | 是否只能读取 `public/*` |
| Capability Token | 授权后的具体任务、工具、参数是否被篡改或重放 | `file.read(A)` 不能换成 `file.read(B)` |
| Runtime / Attack Chain | 多步数据流是否形成组合风险 | 提示注入 → 敏感读取 → 外发 |
| Sandbox | 允许的调用能否在受控环境中执行 | 路径、命令、网络和副作用限制 |

一句话：

```text
OAuth 决定“能否使用某类 MCP 工具”；
AgentGuard 决定“这一次具体调用能否安全执行”。
```

## 4. 核心能力

| 能力 | 当前实现 |
|---|---|
| MCP Streamable HTTP | `POST /mcp`，支持 `initialize`、`notifications/initialized`、`ping`、`tools/list`、`tools/call` |
| OAuth Protected Resource | `/.well-known/oauth-protected-resource`，Bearer Token 校验和 scope challenge |
| Demo OAuth Server | 独立 localhost Authorization Code + PKCE 进程，提供 Authorization Server Metadata |
| Scope-aware Tool Discovery | `tools/list` 根据 Access Token scopes 动态过滤工具 |
| Dynamic Scope Check | 根据收件人和路径等参数补充 `sink:external-email`、`source:sensitive-file` |
| Tool Proxy | 外部 Agent 与 MCP 调用的统一授权入口 |
| Task Boundary Guard | 判断工具调用是否偏离用户原始任务 |
| Capability Contract | 将任务编译为工具、资源、步骤和风险预算约束 |
| Capability Token | 两阶段授权，绑定用户、Agent、任务、工具、参数和 sandbox profile |
| Runtime Monitor | 多步状态、数据标签、风险预算和数据流图 |
| Attack Chain Detector | 检测提示注入、敏感访问、外发和命令执行组合链 |
| Hybrid Sandbox | Docker 优先，无 Docker 时 fallback 到 Native Subprocess Sandbox |
| Audit Evidence | 日志脱敏、`prev_hash`、`record_hash` 和哈希链校验 |
| React/Vite 前端 | 授权演示、运行证据、测试报告和项目说明 |
| CI / Tests | 后端授权回归、独立 Gateway 样例测试和前端构建 |

## 5. 快速启动

### 5.1 安装依赖

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
npm install --prefix ".\frontend"
```

### 5.2 启动原项目

```powershell
python .\start_project.py --clean
```

### 5.3 启动 MCP + OAuth 决赛演示

```powershell
python .\start_project.py --clean --with-oauth
```

服务地址：

```text
Frontend:                http://127.0.0.1:5173
AgentGuard API:          http://127.0.0.1:8000
MCP endpoint:            http://127.0.0.1:8000/mcp
Protected metadata:      http://127.0.0.1:8000/.well-known/oauth-protected-resource
OAuth demo server:       http://127.0.0.1:9000
OAuth server metadata:   http://127.0.0.1:9000/.well-known/oauth-authorization-server
API docs:                http://127.0.0.1:8000/docs
```

第三个终端运行独立 Demo Client：

```powershell
python .\examples\mcp_oauth_demo_client.py
```

详细命令和演示案例见：[MCP_OAUTH_QUICKSTART.md](MCP_OAUTH_QUICKSTART.md)。

## 6. MCP 工具与 scopes

| MCP Tool | 工具发现所需 scope |
|---|---|
| `file.read` | `mcp:tools:list tool:file:read` |
| `file.write` | `mcp:tools:list tool:file:write sink:side-effect` |
| `file.delete` | `mcp:tools:list tool:file:delete sink:side-effect` |
| `email.send` | `mcp:tools:list tool:email:send sink:side-effect` |
| `shell.run` | `mcp:tools:list tool:shell:run sink:side-effect` |
| `db.query` | `mcp:tools:list tool:db:query` |

调用阶段还会根据参数动态增加 scope：

```text
外部邮箱 → sink:external-email
敏感文件 → source:sensitive-file
```

拥有 scope 不表示一定执行。调用仍要经过任务边界、Capability Token、Runtime、Sandbox 和 Audit。

## 7. MCP 任务上下文扩展

AgentGuard 需要原始用户任务来判断当前工具调用是否越界。MCP Client 可通过 `_meta` 传递：

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

也可以使用 HTTP Header：

```text
X-AgentGuard-Task: 读取 public/notice.txt 并总结，不要修改或外发。
```

## 8. 项目结构

```text
Agent-Authorization/
├── backend/
│   ├── main.py                     # FastAPI 主应用
│   ├── mcp/                        # MCP 协议适配层
│   │   ├── service.py              # JSON-RPC 生命周期和 tools 方法
│   │   └── tool_registry.py        # Tool Schema、注解和 scope 可见性
│   ├── oauth/                      # OAuth 资源服务器公共逻辑和 Demo AS
│   │   ├── token_service.py        # Demo JWT Access Token 签发/校验
│   │   └── demo_authorization_server.py
│   ├── gateway/                    # 单次工具调用风险评分
│   ├── proxy/                      # Tool Proxy 统一授权入口
│   ├── capability/                 # Capability Contract
│   ├── guardrails/                 # Task Boundary / Capability Token
│   ├── runtime/                    # Runtime Monitor / Security Graph
│   ├── attack_chain/               # 多步攻击链检测
│   ├── sandbox/                    # Docker / Native / Hybrid Sandbox
│   ├── tools/                      # 受控工具执行
│   ├── audit/                      # 审计日志和哈希链
│   ├── approval/                   # 人工确认
│   └── routes/                     # HTTP API 路由
│
├── examples/
│   └── mcp_oauth_demo_client.py    # 独立 OAuth Client + MCP Client
│
├── config/                         # Gateway 和 Semantic Guard 策略
├── frontend/                       # React + Vite
├── test/                           # 独立 Gateway 样例评测
├── tests/                          # pytest 回归测试
├── runtime_workspace/              # 本地沙箱工作区
├── docs/architecture/              # 架构与边界文档
├── start_project.py                # 一键启动，可选 --with-oauth
├── MCP_OAUTH_QUICKSTART.md
└── README.md
```

更详细的职责划分见：[docs/architecture/MCP_OAUTH_GATEWAY.md](docs/architecture/MCP_OAUTH_GATEWAY.md)。

## 9. 关键 API

| 模块 | 接口 | 说明 |
|---|---|---|
| MCP | `POST /mcp` | OAuth 保护的 MCP JSON-RPC 入口 |
| MCP | `GET /mcp` | 返回当前实现不启用 GET/SSE 的说明 |
| OAuth Resource | `GET /.well-known/oauth-protected-resource` | MCP Resource Metadata |
| OAuth Demo AS | `GET /.well-known/oauth-authorization-server` | Authorization Server Metadata，端口 9000 |
| OAuth Demo AS | `GET /authorize` | Authorization Code + PKCE 授权端点 |
| OAuth Demo AS | `POST /token` | Access Token 端点 |
| Gateway | `POST /gateway/check` | 单次 allow / confirm / deny 判断 |
| Gateway | `POST /gateway/call` | 判断并执行、确认或拒绝 |
| Tool Proxy | `POST /tool-proxy/authorize` | 外部 Agent 统一授权入口 |
| Two Phase | `POST /tool-proxy/two-phase/prepare` | 授权并签发 Capability Token |
| Two Phase | `POST /tool-proxy/two-phase/execute` | 校验 Token 并执行 |
| Native Sandbox | `POST /sandbox-native/execute` | Native Subprocess Sandbox |
| Docker Sandbox | `POST /sandbox-docker/execute` | Docker Sandbox |
| Audit / Frontend | `GET /api/overview` | 聚合 Audit、Sandbox Evidence 和测试摘要 |

## 10. 测试

后端授权回归：

```powershell
python scripts/run_backend_authorization_tests.py
```

独立 Gateway 样例评测：

```powershell
python -m test.run
```

MCP/OAuth 单元测试：

```powershell
pytest tests/unit/test_oauth_access_token.py -q
pytest tests/unit/test_mcp_tool_registry.py -q
pytest tests/unit/test_mcp_service.py -q
```

前端构建：

```powershell
npm --prefix ".\frontend" run build
```



## 11. 系统边界


```text
1. backend.oauth.demo_authorization_server 是 localhost 竞赛演示组件，不是生产级 IdP。
2. Demo Access Token 使用共享 HMAC Secret；生产环境应使用成熟 Provider、HTTPS、JWKS 或 introspection。
3. 当前 MCP 层是“受保护 MCP Tool Server + AgentGuard Gateway”，不是通用多下游 MCP 反向代理。
4. 当前实现采用非流式 Streamable HTTP POST；GET/SSE 返回 405 说明。
5. Native Subprocess Sandbox 是轻量 fallback，不等同于 Docker、gVisor 或 Firecracker 强隔离。
6. 样例测试通过率只说明当前测试集，不代表真实世界绝对安全。
```

## 12. 项目总结

AgentGuard 的工程路径是：

```text
使用 MCP 标准化 Agent 与工具之间的调用；
使用 OAuth 标准化客户端身份与 scope；
使用 Task Boundary 和 Capability Contract 约束当前任务；
使用一次性 Capability Token 绑定具体执行；
使用 Runtime Monitor 和 Attack Chain 检测多步风险；
使用 Hybrid Sandbox 限制真实执行；
使用 Audit Evidence 形成可验证复盘材料。
```

这使项目从“自定义规则判断后端”升级为一个能够由独立 MCP Client 和 OAuth Authorization Server真实调用的 Agent 工具安全网关原型。
