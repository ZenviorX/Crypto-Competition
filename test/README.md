# Agent-Authorization 独立测试模块

## 目标

`test/` 是一个独立评测模块：

> 读取 `test/cases/gateway_cases*.json`，将样例输入 Gateway，自动生成结构化测试结果。

主项目不应 import `test`。  
`test` 可以依赖主项目的 Gateway，因为测试模块需要验证主项目行为。

## 目录结构

```text
test/
├─ cases/                 # Gateway 测试样例，只放 gateway_cases*.json
├─ results/               # 测试输出，前端后续读取这里
├─ legacy/                # 迁移来的旧测试/实验脚本，仅保留归档
├─ run.py                 # 统一测试入口
├─ api.py                 # 预留 FastAPI Router，不默认接入主项目
├─ result_schema.json     # 前端读取结果的结构约定
└─ scripts/run.ps1        # PowerShell 运行入口
```

## 运行

项目根目录执行：

```powershell
python -m test.run
```

或：

```powershell
.\test\scripts\run.ps1
```

## 输出

运行后生成：

```text
test/results/latest_summary.json
test/results/latest_cases.json
test/results/latest_detail.csv
test/results/latest_report.md
test/results/latest_dashboard.html
test/results/run_YYYYMMDD_HHMMSS/
```

前端后续只需要读取 `test/results/latest_summary.json` 和 `test/results/latest_cases.json` 即可完成展示。

## 预留 API

`test/api.py` 提供了独立 Router：

```text
GET /test-results/latest/summary
GET /test-results/latest/cases
GET /test-results/latest/report
GET /test-results/latest/dashboard
```

它不会自动接入主后端。后续需要展示时，再由前端/后端显式接入。
