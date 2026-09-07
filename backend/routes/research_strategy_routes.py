from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter

from backend.research.multi_strategy_comparison import run_multi_strategy_comparison

router = APIRouter(
    prefix="/research/strategy-comparison",
    tags=["Research Strategy Comparison"],
)

ROOT = Path(__file__).resolve().parents[2]
RESULT_PATH = ROOT / "Results" / "Research_Strategy_Comparison_latest.json"


@router.post("/run")
def run_strategy_comparison():
    return run_multi_strategy_comparison()


@router.get("/latest")
def get_latest_strategy_comparison():
    if not RESULT_PATH.exists():
        return {
            "available": False,
            "message": "No strategy comparison result yet. Run POST /research/strategy-comparison/run first.",
        }

    return {
        "available": True,
        "report": json.loads(RESULT_PATH.read_text(encoding="utf-8")),
    }
