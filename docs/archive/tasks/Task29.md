# Task29：Runtime 数据流安全图谱与高风险流证据增强

## 一、任务背景

前序阶段已经完成离线 Runtime Benchmark、Dashboard 可视化展示以及 SHA-256 证据完整性机制。系统已经能够回答“这个样例最终是 allow、confirm 还是 deny”，也能证明报告没有被篡改。

但是，从比赛评审角度看，仅展示最终决策仍不够直观。安全系统需要进一步解释：

- 数据从哪里来；
- 哪一步产生了 tainted / prompt_injection / sensitive / secret 标签；
- 这些标签是否流向了 email.send、shell.run、db.query 等危险工具；
- 系统为什么在某一步确认或阻断。

因此，本阶段新增 Runtime 数据流安全图谱，将每个 Benchmark case 转换为节点、边和高风险流证据。

## 二、主要修改文件

本阶段主要新增或修改：

- backend/evidence/security_graph.py
- experiments/run_llm_runtime_benchmark.py
- backend/routes/benchmark_dashboard_routes.py
- frontend/benchmark_dashboard.html
- tests/evidence/test_security_graph.py
- tests/benchmark/test_llm_runtime_offline_benchmark.py
- tests/routes/test_benchmark_dashboard_routes.py
- Task/Task29.md

## 三、主要工作内容

### 1. 新增 Security Graph 模块

新增 `backend/evidence/security_graph.py`，用于将单个 Benchmark case 转换为数据流安全图谱。

图谱包含：

- case 节点；
- step 节点；
- case input 到 step 的边；
- step output 到后续 step input 的边；
- 标签传播信息；
- sink 工具识别；
- 高风险流 high_risk_flows；
- 图谱 summary 统计。

### 2. 识别危险 sink 工具

当前识别的 sink 工具包括：

- email.send
- shell.run
- file.write
- file.delete
- db.query
- http.post
- code.exec
- run_code

当 tainted、prompt_injection、sensitive、secret、credential 等标签流入这些工具时，系统会在 `high_risk_flows` 中生成证据记录。

### 3. Benchmark 报告自动附加 security_graph

修改 `experiments/run_llm_runtime_benchmark.py`，每个 case 结果都会自动附加：

```json
"security_graph": {
  "nodes": [],
  "edges": [],
  "high_risk_flows": [],
  "summary": {}
}
随后再进入 integrity manifest 计算，因此 security_graph 也会被纳入 SHA-256 防篡改证据范围。

4. Dashboard 展示图谱摘要

修改 frontend/benchmark_dashboard.html，在样例结果表格中新增“安全图谱”列，展示：

node_count；
edge_count；
sink_count；
high_risk_flow_count；
tainted_step_count；
sensitive_step_count。

同时支持点击按钮查看单个 case 的完整图谱 JSON。

5. 新增图谱接口

新增：

GET /benchmark/latest/graph/{case_id}

用于获取最新 Benchmark 报告中某个 case 的完整 security_graph。

6. 新增自动化测试

新增测试覆盖：

tainted 数据流向 email.send sink 时生成 high_risk_flow；
secret 标签步骤被识别为 critical；
Benchmark 报告中自动包含 security_graph；
Dashboard 接口能返回 graph_summary；
单 case 图谱接口能正常返回。
四、任务价值

本阶段的核心价值是提升系统的可解释性和答辩展示能力。

答辩中可以这样表述：

本项目不仅判断 Agent 工具调用是否允许，还进一步构建了 Runtime 数据流安全图谱。系统会把每个任务链拆解成 case 节点、step 节点和数据流边，追踪 tainted、prompt_injection、sensitive、secret 等标签如何在工具调用之间传播。当污染或敏感数据流向 email.send、shell.run、db.query 等危险 sink 工具时，系统会生成 high_risk_flow 证据，并在 Dashboard 和 Benchmark 报告中展示。这使防护结果不再只是一个黑盒 allow/deny，而是具备可解释、可审计、可复现的数据流证据链。
