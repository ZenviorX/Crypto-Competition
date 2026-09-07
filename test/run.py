from __future__ import annotations

import argparse
import csv
import html
import importlib
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASE_DIR = PROJECT_ROOT / "test" / "cases"
DEFAULT_RESULT_DIR = PROJECT_ROOT / "test" / "results"

VALID_DECISIONS = {"allow", "confirm", "deny", "review"}


def _ensure_project_root_on_path() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _load_gateway_callable(import_path: str):
    _ensure_project_root_on_path()
    module_name, attr_name = import_path.split(":", 1)
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)


def _load_tool_request_class(import_path: str):
    _ensure_project_root_on_path()
    module_name, attr_name = import_path.split(":", 1)
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)


def load_case_files(case_dir: Path) -> List[Path]:
    return sorted(case_dir.glob("gateway_cases*.json"))


def load_cases(case_dir: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    cases: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    if not case_dir.exists():
        return cases, [{"level": "error", "message": f"case_dir not found: {case_dir}"}]

    files = load_case_files(case_dir)
    if not files:
        return cases, [{"level": "error", "message": f"no gateway_cases*.json found under {case_dir}"}]

    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            errors.append({"level": "error", "file": path.name, "message": f"json load failed: {exc}"})
            continue

        if isinstance(data, dict) and "cases" in data:
            data = data["cases"]

        if not isinstance(data, list):
            errors.append({"level": "error", "file": path.name, "message": "top-level JSON must be a list or {'cases': [...]}"})
            continue

        for index, item in enumerate(data):
            if not isinstance(item, dict):
                errors.append({"level": "error", "file": path.name, "index": index, "message": "case must be an object"})
                continue
            case = dict(item)
            case["_source_file"] = path.name
            case["_source_index"] = index
            cases.append(case)

    return cases, errors


def expected_decisions(case: Dict[str, Any]) -> List[str]:
    if "expected_decision" in case:
        return [case["expected_decision"]]
    if "expected_decision_in" in case:
        return list(case["expected_decision_in"])
    return []


def validate_cases(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    errors: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}

    for case in cases:
        source = case.get("_source_file", "unknown")
        case_id = case.get("id")

        if not isinstance(case_id, str) or not case_id.strip():
            errors.append({"level": "error", "file": source, "message": "case id is required", "case": case})
            continue

        if case_id in seen:
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": f"duplicated case id; first seen in {seen[case_id]}"})
        else:
            seen[case_id] = source

        if not isinstance(case.get("category"), str) or not case["category"].strip():
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "category is required"})

        request = case.get("request")
        if not isinstance(request, dict):
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "request object is required"})
            continue

        if not isinstance(request.get("user"), str) or not request["user"].strip():
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "request.user is required"})

        if not isinstance(request.get("tool"), str) or not request["tool"].strip():
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "request.tool is required"})

        if "params" in request and not isinstance(request.get("params"), dict):
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "request.params must be an object"})

        expected = expected_decisions(case)
        if not expected:
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "expected_decision or expected_decision_in is required"})
        elif not set(expected).issubset(VALID_DECISIONS):
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": f"invalid expected decision: {expected}"})

        confidence = request.get("agent_confidence")
        if confidence is not None and not (isinstance(confidence, (int, float)) and 0 <= confidence <= 1):
            errors.append({"level": "error", "file": source, "case_id": case_id, "message": "agent_confidence must be a number between 0 and 1"})

    return errors


def is_normal_case(case: Dict[str, Any]) -> bool:
    category = str(case.get("category", "")).lower()
    case_id = str(case.get("id", "")).lower()

    if category.startswith("normal") or "normal" in case_id:
        return True

    expected = set(expected_decisions(case))
    return bool(expected) and expected.issubset({"allow", "confirm"})


def get_decision(result: Any) -> str:
    if isinstance(result, dict):
        return str(result.get("decision", "unknown"))
    return str(getattr(result, "decision", "unknown"))


def get_risk_score(result: Any) -> Any:
    if isinstance(result, dict):
        return result.get("risk_score", "")
    return getattr(result, "risk_score", "")


def get_reason(result: Any) -> str:
    if isinstance(result, dict):
        reason = result.get("reason", [])
    else:
        reason = getattr(result, "reason", [])
    if isinstance(reason, list):
        return " | ".join(str(x) for x in reason)
    return str(reason)


def run_gateway_cases(
    cases: List[Dict[str, Any]],
    gateway_import: str,
    request_import: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    check_tool_call = _load_gateway_callable(gateway_import)
    ToolCallRequest = _load_tool_request_class(request_import)

    rows: List[Dict[str, Any]] = []
    started_all = time.perf_counter()

    decision_counter: Counter[str] = Counter()
    category_counter: Counter[str] = Counter()
    source_counter: Counter[str] = Counter()
    tool_counter: Counter[str] = Counter()
    category_total: defaultdict[str, int] = defaultdict(int)
    category_passed: defaultdict[str, int] = defaultdict(int)

    passed = 0
    risk_total = 0
    risk_block_or_confirm = 0
    risk_allow = 0
    normal_total = 0
    normal_denied = 0
    total_latency = 0.0

    for case in cases:
        case_id = str(case.get("id", ""))
        source_file = str(case.get("_source_file", ""))
        category = str(case.get("category", "unknown"))
        request_data = case.get("request", {})
        tool = str(request_data.get("tool", "unknown"))
        expected = expected_decisions(case)
        normal = is_normal_case(case)
        latency_ms = 0.0

        try:
            request = ToolCallRequest(**request_data)
            started = time.perf_counter()
            result = check_tool_call(request)
            latency_ms = (time.perf_counter() - started) * 1000
            actual = get_decision(result)
            risk_score = get_risk_score(result)
            reason = get_reason(result)
            error = ""
        except Exception as exc:
            actual = "error"
            risk_score = ""
            reason = ""
            error = str(exc)

        matched = actual in expected
        passed += int(matched)
        total_latency += latency_ms

        if normal:
            normal_total += 1
            if actual == "deny":
                normal_denied += 1
        else:
            risk_total += 1
            if actual in {"confirm", "deny"}:
                risk_block_or_confirm += 1
            if actual == "allow":
                risk_allow += 1

        decision_counter[actual] += 1
        category_counter[category] += 1
        source_counter[source_file] += 1
        tool_counter[tool] += 1
        category_total[category] += 1
        category_passed[category] += int(matched)

        rows.append(
            {
                "case_id": case_id,
                "source_file": source_file,
                "category": category,
                "tool": tool,
                "is_normal": normal,
                "expected": "/".join(expected),
                "actual": actual,
                "matched": matched,
                "risk_score": risk_score,
                "latency_ms": round(latency_ms, 3),
                "reason": reason,
                "error": error,
            }
        )

    total = len(cases)
    elapsed_ms = (time.perf_counter() - started_all) * 1000

    summary = {
        "schema": "agent_authorization_test_result.v1",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "case_glob": "test/cases/gateway_cases*.json",
        "gateway_import": gateway_import,
        "request_import": request_import,
        "total_cases": total,
        "passed_cases": passed,
        "failed_cases": total - passed,
        "accuracy": round(passed / total, 6) if total else 0,
        "elapsed_ms": round(elapsed_ms, 3),
        "avg_latency_ms": round(total_latency / total, 3) if total else 0,
        "normal_cases": normal_total,
        "risk_cases": risk_total,
        "risk_block_or_confirm": risk_block_or_confirm,
        "risk_allow": risk_allow,
        "risk_block_or_confirm_rate": round(risk_block_or_confirm / risk_total, 6) if risk_total else 0,
        "risk_unsafe_allow_rate": round(risk_allow / risk_total, 6) if risk_total else 0,
        "normal_denied": normal_denied,
        "normal_false_deny_rate": round(normal_denied / normal_total, 6) if normal_total else 0,
        "decision_distribution": dict(sorted(decision_counter.items())),
        "source_distribution": dict(sorted(source_counter.items())),
        "category_distribution": dict(sorted(category_counter.items())),
        "tool_distribution": dict(sorted(tool_counter.items())),
        "category_accuracy": {
            key: {
                "total": category_total[key],
                "passed": category_passed[key],
                "accuracy": round(category_passed[key] / category_total[key], 6) if category_total[key] else 0,
            }
            for key in sorted(category_total)
        },
    }
    return rows, summary


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "source_file",
        "category",
        "tool",
        "is_normal",
        "expected",
        "actual",
        "matched",
        "risk_score",
        "latency_ms",
        "reason",
        "error",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def write_markdown(path: Path, summary: Dict[str, Any], rows: List[Dict[str, Any]], validation_errors: List[Dict[str, Any]]) -> None:
    failed_rows = [row for row in rows if not row["matched"]]
    lines: List[str] = [
        "# Agent-Authorization 独立测试报告",
        "",
        "## 1. 测试目标",
        "",
        "本模块只负责读取 `test/cases/gateway_cases*.json`，将样例输入 Gateway，自动生成结构化结果。主项目不依赖本模块。",
        "",
        "## 2. 核心指标",
        "",
        f"- 总样例数：{summary.get('total_cases', 0)}",
        f"- 通过样例数：{summary.get('passed_cases', 0)}",
        f"- 失败样例数：{summary.get('failed_cases', 0)}",
        f"- 准确率：{pct(float(summary.get('accuracy', 0)))}",
        f"- 风险样例阻断/确认率：{pct(float(summary.get('risk_block_or_confirm_rate', 0)))}",
        f"- 风险样例误放行率：{pct(float(summary.get('risk_unsafe_allow_rate', 0)))}",
        f"- 正常样例误拒率：{pct(float(summary.get('normal_false_deny_rate', 0)))}",
        f"- 平均 Gateway 延迟：{summary.get('avg_latency_ms', 0)} ms",
        "",
        "## 3. 决策分布",
        "",
        "| Decision | Count |",
        "|---|---:|",
    ]

    for decision, count in summary.get("decision_distribution", {}).items():
        lines.append(f"| {decision} | {count} |")

    lines.extend(["", "## 4. 类别分布", "", "| Category | Cases | Passed | Accuracy |", "|---|---:|---:|---:|"])

    for category, item in summary.get("category_accuracy", {}).items():
        lines.append(f"| {category} | {item['total']} | {item['passed']} | {pct(float(item['accuracy']))} |")

    lines.extend(["", "## 5. 未通过样例", ""])

    if failed_rows:
        lines.extend(["| Case ID | Source | Expected | Actual | Reason/Error |", "|---|---|---|---|---|"])
        for row in failed_rows[:80]:
            msg = row.get("error") or row.get("reason") or ""
            lines.append(
                f"| `{row['case_id']}` | {row['source_file']} | {row['expected']} | {row['actual']} | {str(msg)[:160]} |"
            )
    else:
        lines.append("全部样例通过。")

    if validation_errors:
        lines.extend(["", "## 6. 样例格式问题", "", "| Level | File | Case | Message |", "|---|---|---|---|"])
        for err in validation_errors[:80]:
            lines.append(
                f"| {err.get('level', '')} | {err.get('file', '')} | {err.get('case_id', '')} | {err.get('message', '')} |"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_html(path: Path, summary: Dict[str, Any], rows: List[Dict[str, Any]], validation_errors: List[Dict[str, Any]]) -> None:
    failed_rows = [row for row in rows if not row["matched"]]

    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    table_rows = []
    for row in rows[:500]:
        cls = "failed" if not row["matched"] else ""
        table_rows.append(
            "<tr class='{cls}'>"
            "<td>{case_id}</td><td>{source}</td><td>{category}</td><td>{tool}</td>"
            "<td>{expected}</td><td>{actual}</td><td>{matched}</td><td>{risk}</td><td>{reason}</td>"
            "</tr>".format(
                cls=cls,
                case_id=esc(row["case_id"]),
                source=esc(row["source_file"]),
                category=esc(row["category"]),
                tool=esc(row["tool"]),
                expected=esc(row["expected"]),
                actual=esc(row["actual"]),
                matched=esc(row["matched"]),
                risk=esc(row["risk_score"]),
                reason=esc((row.get("error") or row.get("reason") or "")[:220]),
            )
        )

    validation_block = ""
    if validation_errors:
        validation_block = "<section><h2>样例格式问题</h2><pre>{}</pre></section>".format(
            esc(json.dumps(validation_errors[:50], ensure_ascii=False, indent=2))
        )

    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Agent-Authorization Test Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 32px; background: #f7f8fa; color: #111827; }}
h1 {{ margin-bottom: 8px; }}
.grid {{ display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }}
.card {{ background: white; border-radius: 14px; padding: 18px; box-shadow: 0 4px 18px rgba(15, 23, 42, .08); }}
.label {{ color: #6b7280; font-size: 13px; }}
.value {{ font-size: 28px; font-weight: 800; margin-top: 8px; }}
table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 18px rgba(15, 23, 42, .06); }}
th, td {{ padding: 10px; border-bottom: 1px solid #e5e7eb; text-align: left; vertical-align: top; font-size: 13px; }}
th {{ background: #111827; color: white; position: sticky; top: 0; }}
tr.failed td {{ background: #fff1f2; }}
pre {{ background: #111827; color: #e5e7eb; padding: 16px; border-radius: 12px; overflow: auto; }}
</style>
</head>
<body>
<h1>Agent-Authorization 独立测试报告</h1>
<p>读取 <code>test/cases/gateway_cases*.json</code>，输入 Gateway，输出统一测试结果。</p>
<div class="grid">
  <div class="card"><div class="label">总样例</div><div class="value">{summary.get('total_cases', 0)}</div></div>
  <div class="card"><div class="label">准确率</div><div class="value">{pct(float(summary.get('accuracy', 0)))}</div></div>
  <div class="card"><div class="label">风险阻断/确认率</div><div class="value">{pct(float(summary.get('risk_block_or_confirm_rate', 0)))}</div></div>
  <div class="card"><div class="label">风险误放行率</div><div class="value">{pct(float(summary.get('risk_unsafe_allow_rate', 0)))}</div></div>
</div>
<h2>样例明细</h2>
<table>
<thead>
<tr>
<th>Case ID</th><th>Source</th><th>Category</th><th>Tool</th>
<th>Expected</th><th>Actual</th><th>Matched</th><th>Risk</th><th>Reason / Error</th>
</tr>
</thead>
<tbody>
{''.join(table_rows)}
</tbody>
</table>
{validation_block}
</body>
</html>
"""
    path.write_text(html_doc, encoding="utf-8")


def write_outputs(result_dir: Path, summary: Dict[str, Any], rows: List[Dict[str, Any]], validation_errors: List[Dict[str, Any]]) -> Dict[str, str]:
    result_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    run_dir = result_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    outputs = {
        "latest_summary": result_dir / "latest_summary.json",
        "latest_cases": result_dir / "latest_cases.json",
        "latest_detail_csv": result_dir / "latest_detail.csv",
        "latest_report_md": result_dir / "latest_report.md",
        "latest_dashboard_html": result_dir / "latest_dashboard.html",
        "run_summary": run_dir / "summary.json",
        "run_cases": run_dir / "cases.json",
        "run_detail_csv": run_dir / "detail.csv",
        "run_report_md": run_dir / "report.md",
        "run_dashboard_html": run_dir / "dashboard.html",
    }

    final_summary = dict(summary)
    final_summary["validation_errors"] = validation_errors
    final_summary["outputs"] = {key: str(path.relative_to(PROJECT_ROOT)) for key, path in outputs.items()}

    write_json(outputs["latest_summary"], final_summary)
    write_json(outputs["latest_cases"], rows)
    write_csv(outputs["latest_detail_csv"], rows)
    write_markdown(outputs["latest_report_md"], final_summary, rows, validation_errors)
    write_html(outputs["latest_dashboard_html"], final_summary, rows, validation_errors)

    write_json(outputs["run_summary"], final_summary)
    write_json(outputs["run_cases"], rows)
    write_csv(outputs["run_detail_csv"], rows)
    write_markdown(outputs["run_report_md"], final_summary, rows, validation_errors)
    write_html(outputs["run_dashboard_html"], final_summary, rows, validation_errors)

    return {key: str(path.relative_to(PROJECT_ROOT)) for key, path in outputs.items()}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run independent Agent-Authorization gateway tests.")
    parser.add_argument("--case-dir", default=str(DEFAULT_CASE_DIR), help="Directory containing gateway_cases*.json")
    parser.add_argument("--output-dir", default=str(DEFAULT_RESULT_DIR), help="Directory for generated test results")
    parser.add_argument("--gateway-import", default="backend.gateway:check_tool_call", help="Gateway callable import path")
    parser.add_argument("--request-import", default="backend.schemas:ToolCallRequest", help="ToolCallRequest class import path")
    parser.add_argument("--allow-schema-errors", action="store_true", help="Continue even if case schema validation has errors")
    args = parser.parse_args(argv)

    case_dir = Path(args.case_dir)
    if not case_dir.is_absolute():
        case_dir = PROJECT_ROOT / case_dir

    result_dir = Path(args.output_dir)
    if not result_dir.is_absolute():
        result_dir = PROJECT_ROOT / result_dir

    cases, load_errors = load_cases(case_dir)
    validation_errors = load_errors + validate_cases(cases)

    if validation_errors and not args.allow_schema_errors:
        result_dir.mkdir(parents=True, exist_ok=True)
        error_summary = {
            "schema": "agent_authorization_test_result.v1",
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "total_cases": len(cases),
            "passed_cases": 0,
            "failed_cases": len(cases),
            "accuracy": 0,
            "status": "schema_error",
            "validation_errors": validation_errors,
        }
        write_json(result_dir / "latest_summary.json", error_summary)
        write_json(result_dir / "latest_cases.json", [])
        print("Schema validation failed. See test/results/latest_summary.json")
        return 2

    rows, summary = run_gateway_cases(cases, args.gateway_import, args.request_import)
    outputs = write_outputs(result_dir, summary, rows, validation_errors)

    print("=== Agent-Authorization Test Finished ===")
    print(f"cases: {summary['total_cases']}")
    print(f"passed: {summary['passed_cases']}")
    print(f"failed: {summary['failed_cases']}")
    print(f"accuracy: {pct(float(summary['accuracy']))}")
    print(f"risk_block_or_confirm: {pct(float(summary['risk_block_or_confirm_rate']))}")
    print(f"risk_unsafe_allow: {pct(float(summary['risk_unsafe_allow_rate']))}")
    print(f"normal_false_deny: {pct(float(summary['normal_false_deny_rate']))}")
    print("outputs:")
    for key, value in outputs.items():
        if key.startswith("latest_"):
            print(f"- {value}")

    return 0 if summary["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
