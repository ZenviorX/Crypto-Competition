# Task 2：Crypto-Competition 继承、查新与仓库瘦身启动

状态：CONFIRMED

## 1. 阶段目标

将旧 AgentGuard 工程收敛为面向密码科学技术竞赛的新项目基础，先查清现状、控制仓库噪声，再逐步把研究主线转向 OAuth / RAR / W3C VC / MCP / Agent Authorization。

## 2. 开始前状态

项目由旧 AgentGuard 整体复制而来，仍保留大量风险评分、Task Boundary、Capability Token、Runtime Monitor、Sandbox、Audit、Benchmark 与历史文档。与此同时，仓库存在多人并行修改 `main` 的情况。

## 3. 本阶段实际完成

- 核验旧 AgentGuard 的 MCP、OAuth、Tool Proxy、Capability Token、Audit、Revocation、Task Session 等主要依赖关系。
- 确认新竞赛阶段不能把“OAuth + VC”本身直接作为创新点，也不能把“OAuth 只能粗粒度授权”作为既定事实。
- 建立独立瘦身分支 `cleanup/crypto-slim-20260907`，用于后续大规模删改与 `main` 隔离。
- 从 `main` 删除旧 `Results/` 静态研究结果；历史仍可由 Git 恢复。
- 在瘦身分支删除旧运行时 SQLite 数据并建立 `.gitignore`，该部分尚未作为本阶段热修补同步到 `main`。
- 将原 `docs/` 重构为项目内置 `memory/` 记忆库；原 `docs/archive/Task34.md` 作为新的 `memory/stages/task1.md` 保留。

## 4. 关键设计与决定

- 稳定优先：旧 backend 依赖未拆清前，不先删其运行依赖配置。
- 研究主线当前仍处于查新和收敛阶段；密码学创新点在 prior-art 对比完成前保持 `PROPOSED`。
- 项目记忆采用“stage 记录历史事实 + summary 记录当前结论”的双层结构。
- 多人并行时，大规模瘦身走独立分支；仅小范围明确热修补直接进入 `main`。

## 5. 验证结果

- 已确认 `main` 仍有其他并行提交活动。
- 已确认原 Task34 记录了真实第三方 MCP Client + OAuth + AgentGuard 的 ALLOW / DENY 联调阶段。
- 本次记忆库重构通过单独热修补提交进入 `main`，不改业务代码。

## 6. 当前限制

- 旧 AgentGuard backend 仍然大量存在，尚未完成依赖解耦。
- 新 OAuth/RAR/VC 授权协议结构尚未定稿和实现。
- 旧评测体系与新密码赛评测体系尚未完成切换。

## 7. 下一步

继续按目录审查仓库；处理 backend 时先建立依赖图，再决定保留、迁移或删除旧模块，并逐步形成新的授权协议、威胁模型和实验设计。
