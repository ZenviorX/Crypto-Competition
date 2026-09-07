# Frontend Test Result API Contract

## 推荐读取文件

前端后续优先读取：

```text
test/results/latest_summary.json
test/results/latest_cases.json
```

## 预留后端接口

如果后续接入 FastAPI，可显式挂载 `test.api.router`，接口如下：

| Method | Path | 用途 |
|---|---|---|
| GET | `/test-results/latest/summary` | 读取最新测试摘要 |
| GET | `/test-results/latest/cases` | 读取最新 case 明细 |
| GET | `/test-results/latest/report` | 读取 Markdown 报告 |
| GET | `/test-results/latest/dashboard` | 读取 HTML 仪表盘 |

## 前端核心字段

`latest_summary.json`：

```json
{
  "schema": "agent_authorization_test_result.v1",
  "generated_at": "...",
  "total_cases": 118,
  "passed_cases": 118,
  "failed_cases": 0,
  "accuracy": 1.0,
  "risk_block_or_confirm_rate": 1.0,
  "risk_unsafe_allow_rate": 0.0,
  "normal_false_deny_rate": 0.0,
  "decision_distribution": {},
  "category_distribution": {},
  "tool_distribution": {},
  "outputs": {}
}
```

`latest_cases.json` 是 case 明细数组，每项包含：

```json
{
  "case_id": "...",
  "source_file": "...",
  "category": "...",
  "tool": "...",
  "expected": "confirm/deny",
  "actual": "deny",
  "matched": true,
  "risk_score": 90,
  "reason": "..."
}
```
