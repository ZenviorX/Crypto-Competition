# Task31：AgentGuard 与 Naive Baseline 防护有效性对比评测

## 一、任务背景

前序阶段已经完成：

- 离线 Runtime Benchmark；
- Benchmark Dashboard；
- SHA-256 证据完整性；
- Runtime 数据流安全图谱；
- SVG 可视化图谱展示。

这些能力已经能回答“系统做出了什么安全决策”以及“风险数据如何流动”。

但是，从比赛评审角度看，还需要回答一个更关键的问题：

如果没有 AgentGuard，普通 Agent 会怎样？

因此，本阶段新增 AgentGuard 与 naive baseline 的对比评测，用于量化系统防护收益。

## 二、主要修改文件

本阶段主要新增或修改：

- backend/evidence/effectiveness.py
- experiments/run_llm_runtime_benchmark.py
- backend/routes/benchmark_dashboard_routes.py
- frontend/benchmark_dashboard.html
- tests/evidence/test_effectiveness.py
- tests/benchmark/test_llm_runtime_offline_benchmark.py
- tests/routes/test_benchmark_dashboard_routes.py
- Task/Task31.md

## 三、主要工作内容

### 1. 新增 naive baseline 对照模型

新增 `backend/evidence/effectiveness.py`。

naive baseline 假设：

- Agent 生成的所有 step 都会被直接执行；
- 不进行 Capability Contract 检查；
- 不进行 Runtime Monitor 检查；
- 不进行语义检测；
- 不进行数据流标签追踪；
- 不识别 high-risk flow；
- 不进行人工确认或阻断。

通过该 baseline，可以估计没有 AgentGuard 时会发生多少危险执行。

### 2. 新增防护有效性指标

当前生成以下核心指标：

- attack_neutralization_rate：攻击/可疑样例缓解率；
- normal_availability_rate：正常任务可用率；
- high_risk_flow_mitigation_rate：高风险数据流缓解率；
- graph_coverage_rate：安全图谱覆盖率；
- prevented_execution_rate：阻止危险执行比例；
- overall_effectiveness_score：综合有效性评分；
- baseline_risky_execution_count：基线下潜在危险执行次数；
- prevented_risky_execution_count：AgentGuard 阻止的危险执行次数。

### 3. Benchmark 报告自动附加 effectiveness

修改 `experiments/run_llm_runtime_benchmark.py`，在报告生成时自动附加：

```json
"effectiveness": {
  "baseline": "naive_execute_all_planned_steps",
  "protected_system": "AgentGuard Capability Contract + Runtime Monitor + Security Graph",
  "summary": {},
  "cases": []
}
该字段会在 integrity manifest 生成前写入报告，因此也受到 SHA-256 完整性校验保护。

4. Dashboard 展示有效性指标

Dashboard 新增一组指标卡片：

有效性评分；
攻击缓解率；
高风险流缓解率；
阻止的危险执行次数。

这样评审可以直观看到 AgentGuard 相比 naive baseline 的安全收益。

5. 新增后端接口

新增接口：

GET /benchmark/latest/effectiveness

用于单独查看最新 Benchmark 报告中的防护有效性对比结果。

6. 自动化测试

新增测试覆盖：

effectiveness 指标计算；
Benchmark 报告中包含 effectiveness；
Dashboard latest 接口返回 effectiveness summary；
effectiveness 独立接口可访问。
四、任务价值

本阶段的核心价值是将项目从“功能演示”提升到“量化评测”。

答辩时可以这样表述：

我们不仅展示 AgentGuard 对每个案例的安全决策，还进一步构造了 naive baseline 对照。基线模型表示没有安全网关时，Agent 会直接执行所有计划工具调用；AgentGuard 则通过 Capability Contract、Runtime Monitor、语义检测、数据流图谱和人工确认机制进行防护。系统自动计算攻击缓解率、正常可用率、高风险流缓解率、阻止危险执行次数和综合有效性评分，使防护效果具备量化对比依据。
