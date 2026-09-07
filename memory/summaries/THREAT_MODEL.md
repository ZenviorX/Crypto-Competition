# THREAT_MODEL

状态：PROPOSED

## 当前关注的受保护对象

- 用户授权意图与授权结果；
- Agent / Holder 身份与密钥绑定；
- MCP 工具、资源和参数约束；
- OAuth token、VC/VP 与其他授权证据；
- 执行阶段的真实 `tools/call`；
- 撤销、过期、使用次数和防重放状态；
- 审计与验证证据。

## 主要候选攻击

- 权限扩张：实际执行超出已授予范围；
- 参数替换：授权后修改工具参数或边界；
- 资源替换：使用授权访问不同 resource / audience；
- 主体替换：更换 user、agent 或 credential holder；
- 凭证篡改：修改 VC/VP/token 内容或证明；
- 重放：重复使用一次性或受限授权；
- 过期后继续使用；
- 撤销后继续使用；
- Requested / Granted / Executed 三者语义不一致。

## 当前边界

旧 AgentGuard 还包含提示注入、危险 Shell、SQL、数据外发、沙箱等更广泛 Agent Security 威胁。哪些继续进入新密码赛核心威胁模型，必须在后续收敛时明确；不能因为旧代码存在就自动认定为新项目研究重点。
