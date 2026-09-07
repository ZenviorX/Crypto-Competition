# Task30：Runtime 安全图谱可视化展示

## 一、任务背景

前一阶段已经为每个 Benchmark case 生成了 security_graph，能够记录 case 节点、step 节点、数据流边、高风险流和 sink 工具。但前端最初只能打开 JSON 查看图谱，展示效果不够直观。

因此，本阶段将 security_graph 从 JSON 证据进一步升级为 SVG 可视化图谱，使评审可以直接看到工具调用链和高风险数据流路径。

## 二、主要修改文件

本阶段主要新增或修改：

- backend/evidence/graph_renderer.py
- backend/routes/benchmark_dashboard_routes.py
- frontend/benchmark_dashboard.html
- tests/evidence/test_graph_renderer.py
- tests/routes/test_benchmark_dashboard_routes.py
- Task/Task30.md

## 三、主要工作内容

### 1. 新增图谱渲染器

新增 `backend/evidence/graph_renderer.py`，用于将 security_graph 渲染为独立 HTML 页面。

页面包含：

- SVG 节点图；
- case 节点；
- step 节点；
- sink 节点；
- 数据流边；
- 风险颜色标记；
- high-risk flow 证据表格。

风险颜色包括：

- low：绿色；
- medium：黄色；
- high：橙色；
- critical：红色。

### 2. 新增可视化图谱接口

新增接口：

```text
GET /benchmark/latest/graph/{case_id}/view
该接口会读取最新 Benchmark 报告中的指定 case，并将其 security_graph 渲染为 SVG HTML 页面。

3. Dashboard 按钮升级

原 Dashboard 中“查看图谱 JSON”按钮升级为“查看图谱”，点击后直接打开可视化图谱页面。

这样评审不需要阅读原始 JSON，也能理解：

数据从哪个 step 传到哪个 step；
哪些节点风险更高；
哪些标签流向了 sink 工具；
系统在哪一步确认或阻断。
4. 新增自动化测试

新增测试覆盖：

graph_renderer 能生成包含 SVG 的 HTML；
HTML 中包含 high-risk flow evidence；
Dashboard 后端图谱 view 接口可访问；
图谱页面中能显示关键工具和风险信息。
四、任务价值

本阶段提升的是项目的答辩展示能力和安全解释能力。

答辩时可以这样表达：

系统不仅能够给出 allow、confirm、deny 的最终结果，还可以把每个 Agent Runtime 样例转化为可视化数据流图谱。图谱中展示 case、step、sink 以及标签传播路径，并用颜色标记风险等级。当污染数据或敏感数据流向危险工具时，系统会在图谱和证据表格中突出显示 high-risk flow，从而让安全决策具备直观、可解释、可审计的依据。
