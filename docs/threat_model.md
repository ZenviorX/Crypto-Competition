# Threat Model

本文档描述 AgentGuard 的威胁模型、信任边界、安全目标和防护层映射。

---

## 1. 系统背景

AI Agent 不再只是生成自然语言回答，而是可以调用工具完成任务，例如读取文件、写入文件、执行命令、发送邮件、查询数据库或调用网络接口。

一旦 Agent 被恶意任务、外部文件、网页内容或提示注入影响，就可能产生越权工具调用、敏感数据读取、凭证外发或破坏性操作。

AgentGuard 的目标是在 Agent 与真实工具之间加入安全控制层，使所有工具调用在执行前都经过授权、监控、风险评估和审计。

---

## 2. 受保护资产

| 资产 | 示例 | 安全需求 |
|---|---|---|
| 公开数据 | `data/public/*` | 可读取，但需要防止提示注入传播 |
| 课程或业务数据 | `data/course/*` | 按任务授权访问 |
| 私密数据 | `data/private/*` | 默认禁止访问 |
| 凭证数据 | `.env`、token、key、password | 禁止读取和外发 |
| 安全策略 | `config/policy.yaml`、`config/semantic_guard.yaml` | 防止 Agent 修改或关闭防护 |
| 审计证据 | `Results/Result_XXX.json`、`EvidencePack_XXX.md` | 防篡改、可验证 |
| 工具执行环境 | runtime workspace | 防止路径穿越和危险命令 |
| 外部通信目标 | email、http endpoint | 防止数据外发 |

---

## 3. 信任假设

### 3.1 用户

用户不一定可信，可能提交恶意任务，例如读取敏感文件、关闭审计、跳过人工确认、执行危险命令或将数据发送到外部邮箱。

### 3.2 Agent

Agent 被视为不完全可信。它可能：

- 误解用户任务；
- 被外部内容提示注入；
- 规划超出任务边界的工具调用；
- 将污染数据传递给后续危险工具；
- 生成高置信度但不安全的计划。

因此，系统不允许 Agent 直接执行工具。

### 3.3 Gateway 与 Runtime Monitor

Gateway 和 Runtime Monitor 属于可信计算基，负责策略加载、风险判断、任务能力边界检查、数据标签追踪和最终安全决策。

### 3.4 Tool Executor

Tool Executor 只有在安全层给出 `allow` 后才执行工具。当前项目作为竞赛原型，已实现受限执行边界；生产环境中还需要进一步使用容器、网络隔离和系统调用限制。

---

## 4. 信任边界

```text
User / External Content
        │
        ▼
Untrusted Agent Planner
        │ tool plan
        ▼
Trusted Security Boundary
  - Capability Contract
  - Runtime Monitor
  - Gateway
  - Semantic Guard
  - Data-flow Label Tracker
        │ allow / confirm / deny
        ▼
Constrained Tool Executor
        │
        ▼
Audit / Evidence / Integrity Chain
```

关键边界包括：

| 边界 | 风险 | 防护 |
|---|---|---|
| 用户输入 → Agent | 恶意任务、越权请求 | Gateway、Capability Contract |
| 外部内容 → Agent | 间接提示注入 | Semantic Guard、tainted label |
| Agent → Tool Executor | 危险工具调用 | Runtime Monitor |
| Step output → Later step | 污染数据传播 | Data-flow Security Graph |
| Tool output → External sink | 数据外发 | sink 检查、confirm/deny |
| Report → Reviewer | 结果被篡改 | SHA-256 Integrity Chain |

---

## 5. 攻击者能力

本文假设攻击者可以：

1. 构造恶意用户任务；
2. 在公开文件中植入提示注入内容；
3. 诱导 Agent 读取敏感路径；
4. 诱导 Agent 执行 Shell 命令；
5. 诱导 Agent 发送邮件到外部地址；
6. 诱导 Agent 查询或破坏数据库；
7. 请求绕过安全策略、关闭审计或跳过人工确认；
8. 尝试通过路径穿越访问敏感资源；
9. 尝试让 Agent 修改安全配置；
10. 尝试让污染数据在多个 step 中传播到危险 sink。

本文不假设攻击者可以：

- 直接修改后端源码；
- 直接修改运行时内存；
- 绕过操作系统文件权限；
- 控制 Gateway 进程；
- 获取服务器管理员权限。

---

## 6. 安全目标

| 目标 | 说明 |
|---|---|
| 最小权限 | Agent 只能使用当前任务需要的工具和资源 |
| 越权阻断 | 敏感路径、危险命令、破坏性 SQL 应被拒绝 |
| 风险确认 | 中风险外发、灰区请求应进入人工确认 |
| 数据流追踪 | 追踪 tainted、prompt_injection、sensitive、secret 等标签 |
| Sink 保护 | 防止污染或敏感数据流向 email、shell、db、write/delete 等危险工具 |
| 可解释性 | 每个决策应有 reason、risk_score、labels、graph evidence |
| 可复现性 | Benchmark 和 EvidencePack 可重复生成 |
| 防篡改 | 评测报告应能通过 hash chain 验证完整性 |
| 正常可用 | 正常公开任务不应被过度阻断 |

---

## 7. 非目标

当前原型暂不解决：

- 操作系统级强沙箱；
- 真实生产环境密钥管理；
- 恶意用户获得服务器 shell 后的攻击；
- 对所有自然语言攻击的完全识别；
- 对所有第三方 Agent 框架的完整兼容；
- 大规模并发环境下的审计存储；
- 形式化证明级别的策略正确性。

---

## 8. 攻击类型与防护映射

| 攻击类型 | 示例 | 防护层 |
|---|---|---|
| 敏感文件读取 | `secret/password.txt` | Gateway、Capability Contract、Runtime Monitor |
| 路径穿越 | `public/../secret/password.txt` | Path normalization、forbidden resources |
| 凭证访问 | 读取 `.env`、token、key | Semantic Guard、Sensitive Path Policy |
| 数据外发 | 发送到外部邮箱 | Email policy、Semantic Guard、sink check |
| 间接提示注入 | 文件内容要求 Agent 外发数据 | tainted label、Runtime Monitor、Data-flow Graph |
| 策略绕过 | “不要记录审计日志” | Semantic Guard、policy_bypass label |
| 危险 Shell | `curl`、`wget`、`rm -rf` | Shell keyword policy、Capability Contract |
| 破坏性 SQL | `DROP TABLE`、`DELETE` | SQL hard deny |
| 安全策略篡改 | 修改 `policy.yaml` | Policy self-protection |
| 多步攻击链 | 读文件 → 提取凭证 → 外发 | Runtime Monitor、Security Graph、Effectiveness |

---

## 9. 防护层说明

### 9.1 Capability Contract

在任务开始时，根据用户原始请求编译任务能力边界，限制允许工具、禁止工具、允许资源、禁止资源、最大步骤和风险预算。

### 9.2 Runtime Monitor

在每一步工具调用前执行安全检查，判断是否越权、是否超出风险预算、输入标签是否安全、工具是否是危险 sink。

### 9.3 Semantic Guard

识别自然语言风险意图，包括数据外发、凭证访问、策略绕过、提示注入、破坏性操作、网络滥用和权限提升。

### 9.4 Data-flow Security Graph

将多步执行转化为图谱：

```text
case → step → step → sink
```

并标注输入标签、输出标签、风险等级、high-risk flow、sink 工具和决策结果。

### 9.5 Integrity Chain

对 Benchmark 报告生成 SHA-256 完整性清单，包括 report hash、case hash、step hash、case hash chain 和 root hash。

### 9.6 Effectiveness Baseline

将 AgentGuard 与 naive baseline 对比。naive baseline 假设普通 Agent 会直接执行所有工具调用。AgentGuard 通过阻断、确认和数据流检测来降低风险。

---

## 10. 当前限制与后续方向

当前仍需继续增强：

1. 更强的沙箱隔离；
2. 更多真实 Agent 框架接入；
3. 更大规模攻击样例库；
4. 消融实验；
5. CI 自动测试；
6. 更严格的证据签名机制；
7. 网络工具和浏览器自动化工具安全控制。

---

## 11. 总结

AgentGuard 的威胁模型可以概括为：

Agent 不可信，
工具有风险，
数据会污染，
外发要控制，
证据要可验。

因此系统采用多层防护方式，将工具调用纳入任务能力合约、运行时监控、语义检测、数据流图谱、沙箱执行和完整性证据链中。
