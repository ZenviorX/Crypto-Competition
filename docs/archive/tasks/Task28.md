# Task28：Benchmark Dashboard 前端展示整合

## 一、任务背景

上一阶段已经完成离线真实 Agent Runtime Benchmark，能够将 `security_cases/llm_runtime_cases.json` 中的样例自动执行，并生成 `Results/Result_XXX.json` 与 `Results/Result_XXX.html` 报告。

但是，仅生成报告文件仍然不够直观。比赛答辩时，评委更希望通过一个统一页面快速看到：

- 总样例数；
- Benchmark 通过率；
- 攻击样例确认/阻断情况；
- 正常任务可用性；
- 每个样例的工具链、最终决策和执行证据。

因此，本阶段将离线 Benchmark 结果接入后端接口和前端 Dashboard。

## 二、主要修改文件

本阶段主要新增或修改以下文件：

- backend/routes/benchmark_dashboard_routes.py
- frontend/benchmark_dashboard.html
- backend/main.py
- tests/routes/test_benchmark_dashboard_routes.py
- Task/Task28.md

## 三、主要工作内容

### 1. 新增 Benchmark 后端接口

新增 `/benchmark/latest` 接口，自动扫描 `Results/Result_*.json`，从最大编号开始查找最新的 LLM Runtime Benchmark 报告。

接口会返回：

- summary 统计信息；
- 当前报告文件名；
- normal / suspicious / attack 分类数量；
- 攻击样例中被 confirm / deny 的数量；
- 正常样例中 allow / confirm 的数量；
- 每个 case 的工具链、最终决策、步骤数、执行状态等摘要。

新增 `/benchmark/reports` 接口，用于列出所有可识别的编号 Benchmark 报告。

### 2. 新增 Benchmark Dashboard 页面

新增 `frontend/benchmark_dashboard.html` 页面。

访问地址：

```text
http://127.0.0.1:8000/benchmark-dashboard
页面展示内容包括：

总样例数；
通过率；
攻击确认/阻断数量；
正常任务可用数量；
normal / suspicious / attack 分类统计；
所有 case 的执行摘要表格；
一键打开最新 HTML 报告。
3. 挂载 Results 静态目录

在 backend/main.py 中挂载：

/Results

这样前端可以直接打开：

/Results/Result_XXX.html

便于答辩时从 Dashboard 跳转到完整 HTML 证据报告。

4. 新增自动化测试

新增 tests/routes/test_benchmark_dashboard_routes.py，验证：

/benchmark/latest 能正确选择最大编号的 Benchmark JSON 报告；
接口能正确计算攻击阻断数和正常可用数；
/benchmark-dashboard 页面可以正常访问。
四、测试命令

本阶段建议运行：

python -m pytest tests\routes\test_benchmark_dashboard_routes.py -q
python -m pytest tests -q
五、任务价值

本阶段的核心价值是提升比赛展示效果。

在答辩中可以这样表达：

本项目不仅有可执行的离线 Runtime Benchmark，还将 Benchmark 结果接入了统一的前端 Dashboard。评审可以直接在页面中看到测试样例数量、通过率、攻击阻断情况和正常任务可用性，并能跳转到完整 JSON/HTML 证据报告。这使项目从“后端可运行”进一步提升为“可展示、可解释、可审计”的完整安全系统。
