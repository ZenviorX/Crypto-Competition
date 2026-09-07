# Competition Evidence Pack

本模块用于将最新的离线 Runtime Benchmark 报告升级。

证据包的目标是把分散在 Benchmark JSON、HTML 报告、Dashboard、完整性校验、数据流图谱和有效性评估中的信息，整理成一个可提交、可展示、可复查的材料文件。

---

## 1. 运行方式

### 1.1 分步运行

```powershell
python experiments\run_llm_runtime_benchmark.py
python experiments\generate_competition_evidence_pack.py
```

### 1.2 一键运行

```powershell
.\scripts\run_competition_evidence.ps1
```

如果只想快速生成结果、不运行测试：

```powershell
.\scripts\run_competition_evidence.ps1 -SkipTests
```

---

## 2. 输入与输出

默认读取最新的 Benchmark 报告：

```text
Results/Result_XXX.json
```

生成：

```text
Results/EvidencePack_XXX.json
Results/EvidencePack_XXX.md
```

其中：

| 文件 | 作用 |
|---|---|
| `EvidencePack_XXX.json` | 结构化证据包，便于程序读取和后续自动分析 |
| `EvidencePack_XXX.md` | Markdown 证据包，适合放入作品材料或答辩准备文档 |

---

## 3. 证据包内容

证据包包含以下部分：

1. 核心指标；
2. Benchmark 通过率；
3. SHA-256 完整性校验结果；
4. 防护覆盖矩阵；
5. AgentGuard 与 naive baseline 对比；
6. 代表性攻击样例；
7. 高风险数据流证据；
8. 可复现命令；
9. Dashboard 入口；
10. 答辩展示建议。

---

## 4. 核心指标

EvidencePack 会从最新 Benchmark 报告中提取：

| 指标 | 含义 |
|---|---|
| `total_cases` | Benchmark 样例总数 |
| `passed` | 通过样例数 |
| `failed` | 失败样例数 |
| `pass_rate` | Benchmark 通过率 |
| `integrity_valid` | 报告完整性是否校验通过 |
| `coverage_score` | 防护覆盖评分 |
| `overall_effectiveness_score` | 综合防护有效性评分 |
| `attack_neutralization_rate` | 攻击/可疑样例缓解率 |
| `normal_availability_rate` | 正常任务可用率 |
| `prevented_risky_execution_count` | 相比 naive baseline 阻止的危险执行次数 |

---

## 5. 完整性校验

Benchmark 报告会在生成时附加 `integrity` 字段。

完整性机制包括：

- report hash；
- case hash；
- step hash；
- case-level hash chain；
- root hash。

EvidencePack 会调用完整性校验逻辑，检查最新报告是否被篡改。

如果有人修改了 Benchmark 总体指标、某个 case 的结果、step 决策、security_graph 或 effectiveness 等证据字段，则重新校验时会发现 hash 不一致。

---

## 6. 防护覆盖矩阵

EvidencePack 会生成防护覆盖矩阵，用于说明当前 Benchmark 覆盖了哪些安全层。

当前防护层包括：

| 防护层 | 含义 |
|---|---|
| `capability_contract` | 任务级最小权限能力合约 |
| `runtime_monitor` | 多步运行时授权与风险预算控制 |
| `semantic_guard` | 语义风险检测 |
| `data_flow_graph` | 数据流安全图谱与高风险流证据 |
| `integrity_chain` | SHA-256 完整性哈希链 |
| `effectiveness_baseline` | AgentGuard vs naive baseline 对比 |
| `sandbox_executor` | 沙箱工具执行 |

同时统计以下攻击面：

| 攻击面 | 工具 |
|---|---|
| file | `file.read` / `file.write` / `file.delete` |
| email | `email.send` |
| shell | `shell.run` / `code.exec` / `run_code` |
| database | `db.query` |
| network | `http.post` / `http.get` |

---

## 7. AgentGuard vs Naive Baseline

EvidencePack 会保留 effectiveness 评估结果。

naive baseline 表示：

```text
普通 Agent 直接执行所有计划工具调用，
不进行 Capability Contract、Runtime Monitor、Semantic Guard、
Data-flow Graph、人工确认和沙箱前置授权。
```

AgentGuard 则会在每一步进行：

```text
任务合约检查
运行时授权
语义风险识别
数据流标签追踪
高风险 sink 检查
人工确认或拒绝
```

对比指标包括：

- 攻击缓解率；
- 正常任务可用率；
- 高风险流缓解率；
- 阻止危险执行次数；
- 综合有效性评分。

---

## 8. 代表性案例

EvidencePack 会自动挑选具有代表性的 case，优先选择：

1. 攻击样例；
2. suspicious 样例；
3. 包含 high-risk flow 的样例；
4. final decision 为 `deny` 或 `confirm` 的样例。

每个代表性案例会展示：

- case id；
- 类别；
- 描述；
- final decision；
- security_graph 摘要；
- high-risk flow；
- 关键 step。

---

## 9. 可复现命令

EvidencePack 会写入以下复现命令：

```powershell
python experiments\run_llm_runtime_benchmark.py
python experiments\generate_competition_evidence_pack.py
python -m pytest tests -q
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Dashboard 地址：

```text
http://127.0.0.1:8000/benchmark-dashboard
```

---

## 10. 答辩价值

证据包用于回答常见问题：

| 问题 | EvidencePack 如何回答 |
|---|---|
| 系统覆盖了哪些攻击面？ | 防护覆盖矩阵 |
| 防护链路是否完整？ | layer coverage 与 case coverage |
| 没有 AgentGuard 会怎样？ | naive baseline 对比 |
| 报告是否可信？ | SHA-256 integrity root hash |
| 能否复现实验？ | 可复现命令 |
| 为什么阻断某个工具调用？ | representative cases + high-risk flow |
| 是否只是关键词过滤？ | Semantic Guard + Runtime Monitor + Data-flow Graph |
| 正常任务会不会被过度拦截？ | normal availability rate |

---

## 11. 当前边界

EvidencePack 是竞赛展示和实验复现材料，不等同于生产环境审计系统。后续仍可增强：

- 更严格的审计存储；
- 报告签名；
- 时间戳服务；
- 多次 Benchmark 趋势分析；
- PDF 导出；
- 与 CI/CD 自动产物绑定；
- 与真实 Agent 框架的实验对照。
