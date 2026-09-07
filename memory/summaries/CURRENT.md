# CURRENT

状态：CONFIRMED

## 当前项目定位

`Crypto-Competition` 正在从旧 AgentGuard 工程向密码科学技术竞赛方向收敛。当前研究主线围绕 OAuth / RAR / W3C Verifiable Credentials / MCP / Agent Authorization 展开，同时逐步清理旧 AgentGuard 的工程噪声和历史产物。

## 当前阶段

- 旧 AgentGuard 的 MCP、OAuth、Capability Token、Task Boundary、Runtime、Sandbox、Audit 等模块仍大量保留。
- 新密码赛协议与密码学创新点尚未定稿；在完成 prior-art 对比前保持 `PROPOSED`。
- 仓库存在多人并行开发，`main` 可能持续前进；任何当前状态结论都必须先核验实际 Git 与代码。
- 大规模瘦身使用 `cleanup/crypto-slim-20260907` 分支；小范围明确热修补可直接进入 `main`。
- 原 `docs/` 已重构为 `memory/` 项目记忆库。

## 当前优先级

1. 先完成旧代码依赖收敛，避免边删边破坏当前可运行链路。
2. 明确 Requested → Granted → Executed 的可验证授权模型及其与 OAuth/RAR、VC/VP、MCP `tools/call` 的映射。
3. 完成 prior-art 对比后再确定创新点。
4. 重构比赛展示与评测，使其围绕密码学授权证据而不是旧风险分体系展开。

## 关键风险

- 不得把“OAuth 只能粗粒度授权”当作事实。
- 不得把“OAuth + VC”本身直接声称为创新。
- 不得根据旧 AgentGuard 文档推断当前代码状态。
