# ENGINEERING

状态：CONFIRMED（当前基线）

## 当前工程事实

- 项目仍保留旧 AgentGuard 的 Gateway、Capability、Runtime、Sandbox、Audit、Revocation、Task Session 等大量模块。
- `config/policy.yaml` 与 `config/semantic_guard.yaml` 仍被旧 backend 使用，暂时属于过渡依赖，不能只因不是新核心就直接删除。
- 旧运行时 SQLite 数据属于可再生成状态，不应作为项目知识或实验事实来源；后续应避免把运行数据库长期提交进 Git。
- `Results/` 旧静态研究结果已从 `main` 清理，历史由 Git 保留。
- 仓库存在多人并行开发，因此大规模清理默认走独立分支并在合并前重新核验 `main`。

## 工程优先级

稳定 > 可恢复 > 可维护 > 可追踪 > 简洁 > 新奇。

删除模块前必须先检查 import、route、启动路径、测试和运行时依赖；不为“顺手优化”扩大修改范围。

## 待处理

- 旧 backend 依赖图和最小保留集；
- `.gitignore` 与运行时产物卫生规则同步到最终主线；
- 新授权协议模块的目录边界；
- 旧 Sandbox/Audit/Revocation 中哪些能力作为 baseline 复用。
