# 多策略对比评测说明

## 一、实验目的

本实验用于评估不同工具调用控制策略在同一批样例集上的效果差异。项目将所有 `security_cases/gateway_cases*.json` 样例作为统一输入，分别运行三种策略：

1. `allow_all`：所有工具调用直接允许；
2. `keyword_only`：仅依赖显式危险关键词和副作用工具判断；
3. `gateway`：使用项目完整 Gateway 进行综合授权判断。

通过该实验，可以观察不同策略在攻击阻断、风险升级、正常任务保留和决策匹配方面的表现差异。

## 二、三种策略含义

### 1. allow_all

该策略代表缺少前置安全边界的 Agent 工具调用模式。它的正常任务通过率较高，但攻击请求也会被直接放行。

### 2. keyword_only

该策略代表基础关键词方案。它可以发现一部分明显攻击，例如路径穿越、敏感文件、危险命令、SQL 注入和提示注入关键词。

该策略的问题是缺少上下文理解，无法充分结合用户角色、资源风险、Agent 置信度和任务边界。

### 3. gateway

该策略代表项目完整方案。Gateway 会综合以下因素进行判断：

- 工具类型；
- 资源路径；
- 用户角色；
- 风险分；
- Agent 计划置信度；
- 任务授权合约；
- 语义风险；
- 人工确认与审计链路。

Gateway 的输出不是简单二分类，而是 `allow / confirm / deny` 三态决策。

## 三、运行方式

```powershell
.\scripts\run_strategy_comparison.ps1
如果需要自动打开 HTML 结果页面：

.\scripts\run_strategy_comparison.ps1 -Open
四、输出文件

运行后生成：

Results/strategy_comparison.csv
Results/strategy_comparison_summary.json
Results/strategy_comparison_report.md
Results/strategy_comparison_dashboard.html



