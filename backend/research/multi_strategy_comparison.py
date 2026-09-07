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



def _first_block_stage(agentguard: Dict[str, Any]) -> str:
    trace = agentguard.get("authorization_trace", []) or []

    for item in trace:
        stage = str(item.get("stage") or "")
        decision = str(item.get("decision") or "")

        if stage != "final_decision" and decision in {"deny", "confirm"}:
            return stage

    if str(agentguard.get("decision") or "") in {"deny", "confirm"}:
        return "final_decision"

    return "none"


def _load_cases() -> List[Dict[str, Any]]:
    return json.loads(CASE_FILE.read_text(encoding="utf-8-sig"))


def _is_risky_case(scenario: str) -> bool:
    return scenario != "normal_public_read"


def run_multi_strategy_comparison() -> Dict[str, Any]:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    rows = []

    for case in _load_cases():
        result = run_oauth_comparison(
            OAuthComparisonRequest(scenario=case["scenario"])
        )

        rows.append({
            "id": case["id"],
            "scenario": case["scenario"],
            "is_risky": _is_risky_case(case["scenario"]),
            "noguard": "allow",
            "oauth_only": result.oauth_only["decision"],
            "agentguard": result.agentguard["decision"],
            "agentguard_block_stage": _first_block_stage(result.agentguard),
            "research_value": result.conclusion["research_value"],
            "summary": result.conclusion["summary"],
        })

    risky_rows = [row for row in rows if row["is_risky"]]

    def unsafe_allow_rate(strategy: str) -> float:
        if not risky_rows:
            return 0.0
        unsafe = sum(1 for row in risky_rows if row[strategy] == "allow")
        return unsafe / len(risky_rows)

    report = {
        "name": "NoGuard vs OAuth-only vs AgentGuard Strategy Comparison",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_cases": len(rows),
        "risky_cases": len(risky_rows),
        "metrics": {
            "noguard_unsafe_allow_rate": unsafe_allow_rate("noguard"),
            "oauth_only_unsafe_allow_rate": unsafe_allow_rate("oauth_only"),
            "agentguard_unsafe_allow_rate": unsafe_allow_rate("agentguard"),
        },
        "cases": rows,
    }

    json_path = RESULT_DIR / "Research_Strategy_Comparison_latest.json"
    md_path = RESULT_DIR / "Research_Strategy_Comparison_latest.md"

    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    lines = [
        "# NoGuard vs OAuth-only vs AgentGuard 横向对比实验",
        "",
        f"- 总样例数：{report['total_cases']}",
        f"- 风险样例数：{report['risky_cases']}",
        f"- NoGuard 风险误放行率：{report['metrics']['noguard_unsafe_allow_rate']:.2%}",
        f"- OAuth-only 风险误放行率：{report['metrics']['oauth_only_unsafe_allow_rate']:.2%}",
        f"- AgentGuard 风险误放行率：{report['metrics']['agentguard_unsafe_allow_rate']:.2%}",
        "",
        "| Case | Scenario | NoGuard | OAuth-only | AgentGuard | Block Stage | Research Value |",
        "|---|---|---|---|---|---|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['id']} | {row['scenario']} | {row['noguard']} | "
            f"{row['oauth_only']} | {row['agentguard']} | "
            f"{row['agentguard_block_stage']} | {row['research_value']} |"
        )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return report


if __name__ == "__main__":
    report = run_multi_strategy_comparison()
    print("=== Multi-strategy comparison finished ===")
    print("total:", report["total_cases"])
    print("risky:", report["risky_cases"])
    print("noguard unsafe allow:", report["metrics"]["noguard_unsafe_allow_rate"])
    print("oauth-only unsafe allow:", report["metrics"]["oauth_only_unsafe_allow_rate"])
    print("agentguard unsafe allow:", report["metrics"]["agentguard_unsafe_allow_rate"])
