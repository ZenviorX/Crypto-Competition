# AgentGuard MCP + OAuth 架构说明

## 1. 项目定位

AgentGuard 现在同时提供两类入口：

```text
传统结构化 API：/gateway/*、/tool-proxy/*
标准 MCP 入口：/mcp
```

MCP 入口不是一套平行安全实现，而是一个协议适配层。它将 `tools/call` 转换成现有 `ToolProxyAuthorizeRequest`，复用项目已经实现的完整安全链。

## 2. 主执行链

```text
MCP Client
   ↓ Authorization Code + PKCE
OAuth Demo Authorization Server
   ↓ Bearer Access Token
POST /mcp
   ↓ token signature / issuer / audience / expiry
OAuth Resource Server Gate
   ↓ required scopes / dynamic scopes
MCP Adapter
   ↓ ToolProxyAuthorizeRequest(execute=False)
Tool Proxy Prepare
   ↓ OAuth-style scope / Task Boundary / Runtime / Sandbox Policy
Capability Token issued
   ↓ ToolProxyAuthorizeRequest(execute=True, capability_token=...)
Tool Proxy Execute
   ↓ token binding and replay protection
Hybrid Sandbox
   ↓
Tool Result + Sandbox Evidence + Audit Hash Chain
   ↓
MCP Tool Result
```

## 3. 新增目录

```text
backend/
├── mcp/
│   ├── __init__.py
│   ├── service.py              # JSON-RPC 生命周期、tools/list、tools/call 适配
│   └── tool_registry.py        # MCP Tool Schema、注解和 scope 可见性
│
├── oauth/
│   ├── __init__.py
│   ├── token_service.py        # Demo JWT access token 签发与资源服务器校验
│   └── demo_authorization_server.py
│                                # 独立 localhost OAuth Authorization Server
│
└── routes/
    └── mcp_routes.py           # /mcp 与 Protected Resource Metadata

examples/
└── mcp_oauth_demo_client.py    # 独立 OAuth Client + MCP Client

tests/unit/
├── test_oauth_access_token.py
├── test_mcp_tool_registry.py
└── test_mcp_service.py
```

现有模块保持职责不变：

```text
backend/proxy/        外部 Agent 统一授权入口
backend/guardrails/   Task Boundary 与 Capability Token
backend/capability/   Capability Contract 编译和执行
backend/runtime/      多步状态、标签传播、安全图
backend/attack_chain/ 攻击链检测
backend/sandbox/      Sandbox Policy 与 Docker/Native 执行
backend/audit/        审计日志和哈希链
backend/tools/        受控工具实现
```

## 4. OAuth 与 Capability Token 的边界

| 令牌 | 签发方 | 粒度 | 主要作用 |
|---|---|---|---|
| OAuth Access Token | Authorization Server | 用户/客户端与 scope | 证明调用方能访问某类 MCP 工具 |
| AgentGuard Capability Token | AgentGuard | 单任务、单工具、单参数、单沙箱 | 防止授权后改参数、换任务、换 Agent 或重放 |

两者不能合并：OAuth 是外层粗粒度授权，Capability Token 是网关内部的任务级执行凭证。

## 5. MCP 方法映射

| MCP 方法 | AgentGuard 行为 |
|---|---|
| `initialize` | 协商协议版本并声明 tools capability |
| `notifications/initialized` | 接收初始化完成通知，不产生 JSON-RPC 响应 |
| `ping` | 返回空结果 |
| `tools/list` | 根据 OAuth scopes 返回确定性排序后的可见工具 |
| `tools/call` | 动态 scope 检查 → Tool Proxy 两阶段授权 → Hybrid Sandbox |

## 6. 错误分层

```text
401 Unauthorized
  未提供 token、token 无效、过期、issuer/audience 不匹配

403 Forbidden + insufficient_scope
  token 有效，但缺少当前 MCP 方法或具体工具参数所需 scope

MCP Tool Result isError=true
  OAuth 权限足够，但 AgentGuard 判断任务越界、需要确认或工具执行失败

JSON-RPC Error
  请求结构、方法或参数不符合 MCP/JSON-RPC 要求
```

这一区分是答辩重点：OAuth 与 AgentGuard 的决策不是重复判断。

## 7. 安全设计

当前实现包含：

- MCP HTTP 请求必须携带 Bearer Token；
- 校验 token HMAC 签名、`iss`、`aud`、`exp` 和 token use；
- Protected Resource Metadata 暴露 Authorization Server 和 scopes；
- Authorization Server 使用 Authorization Code + PKCE S256；
- `tools/list` 根据 token scopes 过滤；
- `tools/call` 根据收件人、路径等参数推导动态 scopes；
- 本地 MCP 请求执行 Origin 基础校验；
- 可选校验 `Mcp-Method`、`Mcp-Name` 与 JSON-RPC body 一致；
- 允许调用仍必须经过 Capability Token、Runtime Monitor、Sandbox 和 Audit。

## 8. 工程边界

当前 OAuth Server 为比赛演示组件，使用内存 authorization code 和共享 HMAC Secret。它用于证明 OAuth 角色、发现、PKCE、资源绑定和 scope challenge 的完整通信链路，不代表生产级身份系统。

生产化需要替换为：

```text
成熟 OAuth/OIDC Provider
HTTPS
非对称签名与 JWKS
客户端注册或 Client ID Metadata
用户登录、同意和撤销
refresh token 策略
密钥轮换
持久化授权记录
```

MCP 层当前是“受保护 MCP Tool Server + AgentGuard Gateway”，并非能够任意聚合多个第三方 MCP Server 的通用反向代理。后续若扩展，应新增 downstream registry、命名空间冲突处理和下游凭据隔离，而不是修改现有安全核心。
