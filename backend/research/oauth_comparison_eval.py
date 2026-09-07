from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from backend.research.oauth_comparison import (
    OAuthComparisonRequest,
    run_oauth_comparison,
)

ROOT = Path(__file__).resolve().parents[2]
CASE_FILE = ROOT / "research_cases" / "oauth_comparison_cases.json"
RESULT_DIR = ROOT / "Results"


def load_cases() -> List[Dict[str, Any]]:
    return json.loads(CASE_FILE.read_text(encoding="utf-8-sig"))


def main() -> None:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    cases = load_cases()
    rows = []

    for case in cases:
        result = run_oauth_comparison(
            OAuthComparisonRequest(scenario=case["scenario"])
        )

        oauth_decision = result.oauth_only["decision"]
        agentguard_decision = result.agentguard["decision"]

        rows.append({
            "id": case["id"],
            "scenario": case["scenario"],
            "oauth_only": oauth_decision,
            "agentguard": agentguard_decision,
            "expected_oauth_only": case["expected_oauth_only"],
            "expected_agentguard": case["expected_agentguard"],
            "matched": (
                oauth_decision == case["expected_oauth_only"]
                and agentguard_decision == case["expected_agentguard"]
            ),
            "research_value": result.conclusion["research_value"],
            "summary": result.conclusion["summary"],
        })

    passed = sum(1 for row in rows if row["matched"])

    report = {
        "name": "OAuth-only vs AgentGuard Research Comparison",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total": len(rows),
        "passed": passed,
        "failed": len(rows) - passed,
        "accuracy": passed / len(rows) if rows else 0,
        "cases": rows,
    }

    json_path = RESULT_DIR / "Research_OAuth_Comparison_latest.json"
    md_path = RESULT_DIR / "Research_OAuth_Comparison_latest.md"

    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    lines = [
        "# OAuth-only vs AgentGuard 对比实验报告",
        "",
        f"- 总样例数：{report['total']}",
        f"- 通过数：{report['passed']}",
        f"- 失败数：{report['failed']}",
        f"- 准确率：{report['accuracy']:.2%}",
        "",
        "| Case | Scenario | OAuth-only | AgentGuard | Research Value | Result |",
        "|---|---|---|---|---|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['id']} | {row['scenario']} | {row['oauth_only']} | "
            f"{row['agentguard']} | {row['research_value']} | "
            f"{'PASS' if row['matched'] else 'FAIL'} |"
        )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("=== Research comparison finished ===")
    print(f"total: {report['total']}")
    print(f"passed: {report['passed']}")
    print(f"failed: {report['failed']}")
    print(f"json: {json_path}")
    print(f"markdown: {md_path}")


if __name__ == "__main__":
    main()
