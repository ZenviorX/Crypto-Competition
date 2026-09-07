from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter

from backend.research.oauth_comparison import (
    OAuthComparisonRequest,
    run_oauth_comparison,
)

router = APIRouter(
    prefix="/research/oauth-comparison",
    tags=["Research Comparison"],
)

ROOT = Path(__file__).resolve().parents[2]
CASE_FILE = ROOT / "research_cases" / "oauth_comparison_cases.json"
RESULT_DIR = ROOT / "Results"


def _load_cases() -> List[Dict[str, Any]]:
    return json.loads(CASE_FILE.read_text(encoding="utf-8-sig"))


def _run_eval() -> Dict[str, Any]:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    for case in _load_cases():
        result = run_oauth_comparison(
            OAuthComparisonRequest(scenario=case["scenario"])
        )

        oauth_decision = result.oauth_only["decision"]
        agentguard_decision = result.agentguard["decision"]

        matched = (
            oauth_decision == case["expected_oauth_only"]
            and agentguard_decision == case["expected_agentguard"]
        )

        rows.append({
            "id": case["id"],
            "scenario": case["scenario"],
            "oauth_only": oauth_decision,
            "agentguard": agentguard_decision,
            "expected_oauth_only": case["expected_oauth_only"],
            "expected_agentguard": case["expected_agentguard"],
            "matched": matched,
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

    path = RESULT_DIR / "Research_OAuth_Comparison_latest.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return report


@router.post("/eval/run")
def run_research_eval():
    return _run_eval()


@router.get("/eval/latest")
def get_latest_research_eval():
    path = RESULT_DIR / "Research_OAuth_Comparison_latest.json"

    if not path.exists():
        return {
            "available": False,
            "message": "No research comparison result yet. Run POST /research/oauth-comparison/eval/run first.",
        }

    return {
        "available": True,
        "report": json.loads(path.read_text(encoding="utf-8")),
    }
