from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASE_DIR = PROJECT_ROOT / "test" / "cases"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "test" / "results"

VALID_DECISIONS = {"allow", "confirm", "deny"}


def load_case_files(case_dir: Path) -> list[Path]:
    """读取所有 Gateway 测试用例文件。"""
    return sorted(case_dir.glob("gateway_cases*.json"))


def load_cases(
    case_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
    cases: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []

    if not case_dir.exists():
        findings.append(
            {
                "level": "error",
                "file": str(case_dir),
                "case_id": "",
                "message": "测试用例目录不存在。",
            }
        )
        return cases, findings, 0

    files = load_case_files(case_dir)

    if not files:
        findings.append(
            {
                "level": "error",
                "file": str(case_dir),
                "case_id": "",
                "message": "没有找到 gateway_cases*.json 文件。",
            }
        )
        return cases, findings, 0

    for path in files:
        try:
            content = path.read_text(encoding="utf-8-sig")
            data = json.loads(content)
        except Exception as exc:
            findings.append(
                {
                    "level": "error",
                    "file": path.name,
                    "case_id": "",
                    "message": f"JSON 文件读取失败：{exc}",
                }
            )
            continue

        if isinstance(data, dict):
            data = data.get("cases")

        if not isinstance(data, list):
            findings.append(
                {
                    "level": "error",
                    "file": path.name,
                    "case_id": "",
                    "message": (
                        "JSON 顶层必须是数组，"
                        "或者是包含 cases 数组的对象。"
                    ),
                }
            )
            continue

        for index, item in enumerate(data):
            if not isinstance(item, dict):
                findings.append(
                    {
                        "level": "error",
                        "file": path.name,
                        "case_id": f"index:{index}",
                        "message": "测试用例必须是 JSON 对象。",
                    }
                )
                continue

            case = dict(item)
            case["_source_file"] = path.name
            case["_source_index"] = index
            cases.append(case)

    return cases, findings, len(files)


def normalize_decision(value: Any) -> str:
    return str(value).strip().lower()


def audit_cases(
    cases: list[dict[str, Any]],
    findings: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    rows: list[dict[str, Any]] = []
    seen_ids: dict[str, str] = {}

    by_file: defaultdict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "strict": 0,
            "flexible": 0,
            "invalid": 0,
        }
    )

    for case in cases:
        source_file = str(case.get("_source_file", "unknown"))
        source_index = case.get("_source_index", -1)

        raw_case_id = case.get("id")
        case_id = (
            str(raw_case_id).strip()
            if raw_case_id is not None
            else ""
        )

        if not case_id:
            case_id = f"index:{source_index}"
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": "测试用例缺少 id。",
                }
            )

        by_file[source_file]["total"] += 1

        if case_id in seen_ids:
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": (
                        "测试用例 id 重复，首次出现在 "
                        f"{seen_ids[case_id]}。"
                    ),
                }
            )
        else:
            seen_ids[case_id] = source_file

        category = case.get("category")

        if not isinstance(category, str) or not category.strip():
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": "测试用例缺少有效的 category。",
                }
            )

        request = case.get("request")

        if not isinstance(request, dict):
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": "测试用例缺少有效的 request 对象。",
                }
            )
            request = {}

        tool = request.get("tool")

        if not isinstance(tool, str) or not tool.strip():
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": "request 中缺少有效的 tool。",
                }
            )

        params = request.get("params")

        if params is not None and not isinstance(params, dict):
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": "request.params 必须是 JSON 对象。",
                }
            )

        has_strict = "expected_decision" in case
        has_flexible = "expected_decision_in" in case

        expected: list[str] = []
        expectation_mode = "invalid"

        if has_strict and has_flexible:
            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": (
                        "不能同时使用 expected_decision "
                        "和 expected_decision_in。"
                    ),
                }
            )

        if has_strict:
            strict_value = case.get("expected_decision")

            if not isinstance(strict_value, str):
                by_file[source_file]["invalid"] += 1

                findings.append(
                    {
                        "level": "error",
                        "file": source_file,
                        "case_id": case_id,
                        "message": (
                            "expected_decision 必须是字符串。"
                        ),
                    }
                )
            else:
                decision = normalize_decision(strict_value)
                expected = [decision]
                expectation_mode = "strict"
                by_file[source_file]["strict"] += 1

                if decision not in VALID_DECISIONS:
                    findings.append(
                        {
                            "level": "error",
                            "file": source_file,
                            "case_id": case_id,
                            "message": (
                                "expected_decision 的值无效："
                                f"{decision}"
                            ),
                        }
                    )

        elif has_flexible:
            flexible_value = case.get("expected_decision_in")

            if not isinstance(flexible_value, list):
                by_file[source_file]["invalid"] += 1

                findings.append(
                    {
                        "level": "error",
                        "file": source_file,
                        "case_id": case_id,
                        "message": (
                            "expected_decision_in 必须是数组。"
                        ),
                    }
                )
            else:
                expected = sorted(
                    {
                        normalize_decision(item)
                        for item in flexible_value
                        if str(item).strip()
                    }
                )

                expectation_mode = "flexible"
                by_file[source_file]["flexible"] += 1

                findings.append(
                    {
                        "level": "warning",
                        "file": source_file,
                        "case_id": case_id,
                        "message": (
                            "当前使用宽松判定 "
                            f"{expected}，后续需要改成唯一的 "
                            "expected_decision。"
                        ),
                    }
                )

                invalid_values = sorted(
                    set(expected) - VALID_DECISIONS
                )

                if invalid_values:
                    findings.append(
                        {
                            "level": "error",
                            "file": source_file,
                            "case_id": case_id,
                            "message": (
                                "存在不支持的决策值："
                                f"{invalid_values}"
                            ),
                        }
                    )

                if set(expected) == VALID_DECISIONS:
                    findings.append(
                        {
                            "level": "error",
                            "file": source_file,
                            "case_id": case_id,
                            "message": (
                                "该用例同时允许 allow、confirm、deny，"
                                "无论系统输出什么都可能通过，"
                                "无法作为有效评测证据。"
                            ),
                        }
                    )

                if len(expected) == 1:
                    findings.append(
                        {
                            "level": "warning",
                            "file": source_file,
                            "case_id": case_id,
                            "message": (
                                "该数组只有一个值，应直接改为 "
                                "expected_decision。"
                            ),
                        }
                    )

                if not expected:
                    findings.append(
                        {
                            "level": "error",
                            "file": source_file,
                            "case_id": case_id,
                            "message": (
                                "expected_decision_in 不能为空。"
                            ),
                        }
                    )

        else:
            by_file[source_file]["invalid"] += 1

            findings.append(
                {
                    "level": "error",
                    "file": source_file,
                    "case_id": case_id,
                    "message": (
                        "缺少 expected_decision。"
                    ),
                }
            )

        rows.append(
            {
                "case_id": case_id,
                "source_file": source_file,
                "source_index": source_index,
                "category": str(category or ""),
                "tool": str(tool or ""),
                "expectation_mode": expectation_mode,
                "expected": expected,
            }
        )

    return rows, dict(sorted(by_file.items()))


def build_summary(
    rows: list[dict[str, Any]],
    findings: list[dict[str, str]],
    file_count: int,
    by_file: dict[str, dict[str, int]],
) -> dict[str, Any]:
    level_counter = Counter(
        finding["level"]
        for finding in findings
    )

    strict_cases = sum(
        row["expectation_mode"] == "strict"
        for row in rows
    )

    flexible_cases = sum(
        row["expectation_mode"] == "flexible"
        for row in rows
    )

    invalid_cases = sum(
        row["expectation_mode"] == "invalid"
        for row in rows
    )

    is_ready = (
        len(rows) > 0
        and flexible_cases == 0
        and invalid_cases == 0
        and level_counter.get("error", 0) == 0
    )

    return {
        "schema": "agentguard_evaluation_case_audit.v1",
        "generated_at": (
            datetime.now()
            .astimezone()
            .isoformat(timespec="seconds")
        ),
        "files_scanned": file_count,
        "cases_total": len(rows),
        "strict_cases": strict_cases,
        "flexible_cases": flexible_cases,
        "invalid_cases": invalid_cases,
        "errors": level_counter.get("error", 0),
        "warnings": level_counter.get("warning", 0),
        "status": (
            "strict_ready"
            if is_ready
            else "needs_rewrite"
        ),
        "by_file": by_file,
    }


def write_json_report(
    output_dir: Path,
    summary: dict[str, Any],
    rows: list[dict[str, Any]],
    findings: list[dict[str, str]],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = (
        output_dir / "evaluation_case_audit.json"
    )

    payload = {
        "summary": summary,
        "cases": rows,
        "findings": findings,
    }

    output_path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return output_path


def write_markdown_report(
    output_dir: Path,
    summary: dict[str, Any],
    findings: list[dict[str, str]],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = (
        output_dir / "evaluation_case_audit.md"
    )

    lines: list[str] = [
        "# AgentGuard 评测用例严格性审计",
        "",
        "## 一、总体结果",
        "",
        f"- 扫描文件数：{summary['files_scanned']}",
        f"- 测试用例总数：{summary['cases_total']}",
        f"- 严格唯一判定用例：{summary['strict_cases']}",
        f"- 宽松多结果用例：{summary['flexible_cases']}",
        f"- 无效用例：{summary['invalid_cases']}",
        f"- 错误数量：{summary['errors']}",
        f"- 警告数量：{summary['warnings']}",
        f"- 当前状态：`{summary['status']}`",
        "",
        "## 二、各文件统计",
        "",
        "| 文件 | 总数 | 严格判定 | 宽松判定 | 无效 |",
        "|---|---:|---:|---:|---:|",
    ]

    for file_name, stats in summary["by_file"].items():
        lines.append(
            f"| `{file_name}` "
            f"| {stats['total']} "
            f"| {stats['strict']} "
            f"| {stats['flexible']} "
            f"| {stats['invalid']} |"
        )

    lines.extend(
        [
            "",
            "## 三、待处理问题",
            "",
        ]
    )

    if not findings:
        lines.append("未发现问题。")
    else:
        for finding in findings:
            level = finding.get("level", "")
            file_name = finding.get("file", "")
            case_id = finding.get("case_id", "")
            message = finding.get("message", "")

            lines.append(
                f"- **{level.upper()}** "
                f"`{file_name}` / `{case_id}`："
                f"{message}"
            )

    output_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "检查 AgentGuard 评测用例是否使用唯一、"
            "严格的期望决策。"
        )
    )

    parser.add_argument(
        "--case-dir",
        default=str(DEFAULT_CASE_DIR),
        help="测试用例目录。",
    )

    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="审计报告输出目录。",
    )

    args = parser.parse_args()

    case_dir = Path(args.case_dir)

    if not case_dir.is_absolute():
        case_dir = PROJECT_ROOT / case_dir

    output_dir = Path(args.output_dir)

    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    cases, findings, file_count = load_cases(
        case_dir
    )

    rows, by_file = audit_cases(
        cases,
        findings,
    )

    summary = build_summary(
        rows,
        findings,
        file_count,
        by_file,
    )

    json_path = write_json_report(
        output_dir,
        summary,
        rows,
        findings,
    )

    markdown_path = write_markdown_report(
        output_dir,
        summary,
        findings,
    )

    print()
    print("========================================")
    print(" AgentGuard Evaluation Case Audit")
    print("========================================")
    print(f"files_scanned : {summary['files_scanned']}")
    print(f"cases_total   : {summary['cases_total']}")
    print(f"strict_cases  : {summary['strict_cases']}")
    print(f"flexible_cases: {summary['flexible_cases']}")
    print(f"invalid_cases : {summary['invalid_cases']}")
    print(f"errors        : {summary['errors']}")
    print(f"warnings      : {summary['warnings']}")
    print(f"status        : {summary['status']}")
    print("----------------------------------------")
    print(f"JSON report   : {json_path}")
    print(f"Markdown      : {markdown_path}")
    print("========================================")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
