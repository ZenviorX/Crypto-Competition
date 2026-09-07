# DEMO

状态：BASELINE + PROPOSED

## 已验证基线

原 `docs/archive/Task34.md` 记录了真实第三方 Agent 接入阶段：Cherry Studio + DeepSeek 通过公网 MCP 与 OAuth 调用 AgentGuard，并完成一组真实 ALLOW / DENY 联调。该历史阶段已保留为 `memory/stages/task1.md`。

## 新比赛展示目标

后续演示应从“管理后台式功能堆叠”收敛为可验证授权实验。建议核心界面围绕：

```text
REQUESTED | GRANTED | EXECUTED
```

展示 principal、agent/holder、tool、resource、arguments、有效期、使用限制、credential status 和 proof，并给出明确验证结果。

优先候选场景：

1. 完全匹配授权 → ALLOW；
2. 参数超出授权边界 → DENY；
3. 凭证/证明篡改 → DENY；
4. 过期或撤销 → DENY；
5. Holder mismatch / replay → 在对应机制完成后演示。

未实现的场景不得在答辩或文档中写成已完成。
