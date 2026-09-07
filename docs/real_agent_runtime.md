# 真实 Stepwise LLM Agent 运行时防护说明

## 1. 模块定位

本模块用于展示 AgentGuard 对真实大模型 Agent 工具调用过程的运行时安全防护能力。

与早期固定样例不同，真实 Stepwise LLM Agent 模式不是直接手写危险工具调用，而是让大模型根据用户自然语言任务和上一步工具输出继续规划下一步工具调用。系统不信任 Agent 的规划结果，每一步候选工具调用都必须经过 Capability Contract、Runtime Monitor、Attack Chain Detector 和 Sandbox Executor 的联合检查。

核心目标是证明：

```text
真实 LLM Agent 可以接入系统，
但真实工具执行权不交给 Agent，
每一步工具调用都必须经过任务级授权边界和运行时安全检查。

<!-- TASK26_RUNTIME_BENCHMARK_DOCS_START -->
## 8.6 Task26：真实 Agent Runtime 样例库增强

Task26 对真实 Agent Runtime 样例库进行了系统扩充，使其从早期功能演示样例升级为更适合比赛展示和自动化检查的评测规格。

当前 `security_cases/llm_runtime_cases.json` 已覆盖 18 条真实 Agent Runtime 样例：

| 类别 | 数量 | 代表场景 |
|---|---:|---|
| normal | 5 | 公开文件读取、公开文档读取、内部邮箱发送、只读数据库查询、安全 Shell 命令 |
| suspicious | 2 | 外部合作邮箱发送、private 内部资料读取 |
| attack | 11 | 间接提示注入、secret 读取、.env/token 访问、路径穿越、凭证外发、curl 外联、DROP TABLE、低置信度敏感计划、文件删除 |

本阶段的重点不是直接修改 Gateway 决策逻辑，而是增强真实 Agent Runtime 的评测覆盖面。通过样例库可以证明系统不仅能阻断攻击，也能区分正常任务、灰区任务和高危任务。

### 自动化测试约束

配套测试文件为：

```text
tests/test_llm_runtime_cases.py

当前测试会检查：

样例数量不少于 15 条；
normal / suspicious / attack 三类样例均有覆盖；
攻击样例不能只期望 allow；
正常样例不能只期望 deny；
正常样例必须显式禁止攻击者邮箱和 secret 访问；
prompt injection 样例必须体现 tainted 标签或阻断预期；
样例库必须覆盖 file.read、email.send、shell.run、db.query、file.delete 等工具；
secret、token、.env、password 等敏感场景必须要求阻断或确认；
删除、DROP、curl 等破坏性或外发行为必须进入确认或拒绝。
评测价值

这一增强使真实 Agent Runtime 模块不再只是一个展示页面，而是具备了可复查、可扩展、可持续增强的评测规格。

答辩时可以表述为：

我们不仅实现了真实 LLM Agent 的逐步规划和运行时防护，还构建了覆盖正常、可疑、攻击三类场景的真实 Agent Runtime 样例库，并通过自动化测试约束样例质量，保证系统评测不是单一脚本演示，而是可复查、可扩展的安全评测体系。

<!-- TASK26_RUNTIME_BENCHMARK_DOCS_END -->

