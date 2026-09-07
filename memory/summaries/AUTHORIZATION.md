# AUTHORIZATION

状态：PROPOSED + BASELINE

## 当前工程基线

旧 AgentGuard 当前把 OAuth Access Token 与内部 Task-scoped Capability Token 分层使用：OAuth 负责 MCP 入口身份/权限校验，内部 Capability Token 绑定具体任务、工具、参数、沙箱和有效期，并提供消费/重放限制。

该设计是现有工程基线，不等于新密码赛最终方案。

## 新研究问题

当前拟研究的核心不是简单“增加 OAuth”或“增加 VC”，而是建立可机器验证的授权一致性链：

```text
REQUESTED → GRANTED → EXECUTED
```

需要验证至少以下维度没有发生权限扩张或主体/参数替换：

- principal / user
- agent / holder
- tool / operation
- resource / audience
- arguments / parameter bounds
- validFrom / validUntil
- usage / quota
- credential status
- proof / signature / binding

## 目标协议关系

当前候选方向：

- OAuth / RAR 表达请求与授权细节；
- W3C VC / VP 提供可验证的授权或委托证据；
- MCP `tools/call` 表达真实执行请求；
- 执行边界验证 `Executed ⊆ Granted`，并检查主体、资源和参数绑定。

上述内容在协议与 prior-art 对比完成前保持 `PROPOSED`。
