# ARCHITECTURE

状态：CONFIRMED（当前基线）

## 当前可核验基线

现有系统仍以旧 AgentGuard 为主体，MCP 入口复用现有授权链，而不是一套完全独立实现。当前基线可概括为：

```text
MCP Client
  → OAuth Authorization Server
  → Bearer Access Token
  → /mcp Resource Server Gate
  → MCP Adapter
  → Tool Proxy Prepare
  → Task Boundary / Capability Contract / Runtime / Sandbox Policy
  → allow / confirm / deny
  → Task-scoped Capability Token
  → Execute
  → Sandbox
  → Audit / Evidence
```

## 当前主要模块

- `backend/mcp/`：MCP JSON-RPC 生命周期、工具注册与调用适配。
- `backend/oauth/`：演示 OAuth Authorization Server 与 token 服务。
- `backend/proxy/`：旧 AgentGuard 工具调用授权主链。
- `backend/guardrails/` / `backend/capability/` / `backend/runtime/`：旧任务边界、能力约束和运行时控制。
- `backend/sandbox/`：受限工具执行。
- `backend/audit/`：审计与可验证证据基线。

## 目标方向

目标架构尚未最终冻结。后续预计把授权逻辑收敛为更清晰的 OAuth/RAR + VC/VP + MCP 执行边界，并弱化或淘汰与新研究问题无关的旧风险评分、攻击链和展示层模块。

具体重构前必须再次读取实际 import / route / runtime 依赖，不能按本文件直接删除代码。
