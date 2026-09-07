# AgentGuard 后端授权主线阶段性改进清单

围绕外部 Agent 工具调用授权主线进行后端增强。

## 1. OAuth-only vs AgentGuard 对比

新增 OAuth-only baseline 与 AgentGuard 完整授权链路的横向对比，用于证明仅依赖 OAuth-style scope 不足以覆盖任务边界、沙箱策略、数据来源和运行时风险。

## 2. Task Boundary Guard

新增任务边界守卫，从原始用户任务中提取限制条件，拦截 scope 足够但偏离任务意图的工具调用，例如“只总结文件”任务中尝试发送邮件或外传数据。

## 3. Capability Contract

将任务边界抽象为结构化 Capability Contract，描述本次任务允许和禁止的能力，包括是否允许副作用工具、是否允许外部传输、是否允许联网、是否允许读取敏感路径。

## 4. Data Provenance Guard

新增数据来源守卫，针对 untrusted、external、web、email、prompt_injection 等输入标签，禁止不可信内容直接驱动 email.send、http.post、shell.run、file.write 等副作用工具。

## 5. Authorization Trace

新增授权决策 Trace，记录 OAuth scope、Capability Token、Task Boundary、Sandbox Policy、Final Decision 等阶段，便于解释为什么 allow / deny / confirm。

## 6. Task-scoped Capability Token

新增任务级 Capability Token。与 OAuth token 不同，OAuth 表示外部 Agent 的长期权限声明，Capability Token 表示 AgentGuard 基于本次任务临时签发的最小能力凭证。

## 7. 两阶段授权流程

新增 prepare -> execute 两阶段流程：
- prepare 阶段只做授权判断，allow 后签发 Capability Token，不执行工具；
- execute 阶段必须携带合法 Capability Token，校验通过后才允许执行工具。

## 8. Token 绑定与防滥用

Capability Token 已绑定：
- user
- agent_platform
- original_task
- tool
- params
- sandbox_profile
- capability_contract
- 过期时间

并支持：
- 防篡改签名校验
- 过期拒绝
- 跨任务复用拒绝
- 换工具复用拒绝
- 换参数复用拒绝
- 换沙箱复用拒绝
- 执行阶段必须带 token
- 执行成功后 token 被消费，禁止重放

## 9. Token Ledger 与生命周期审计

新增 Capability Token Ledger，记录 token 的 issued、consumed、revoked 状态，并提供事件审计：
- issued
- consumed
- revoked

后端也提供 token status / revoke / events 查询接口，方便后续演示授权生命周期。

## 10. 后端自动化测试

新增多组 pytest 测试，覆盖 OAuth 对比、任务边界、数据来源、Capability Contract、Capability Token、两阶段授权、token 防重放、撤销、生命周期审计和 Trace 状态。
