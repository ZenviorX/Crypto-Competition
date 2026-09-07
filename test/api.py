from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    from fastapi import APIRouter
    from fastapi.responses import FileResponse
except Exception:  # keeps this module import-safe when FastAPI is not installed
    APIRouter = None  # type: ignore
    FileResponse = None  # type: ignore


TEST_DIR = Path(__file__).resolve().parent
RESULT_DIR = TEST_DIR / "results"

if APIRouter is not None:
    router = APIRouter(prefix="/test-results", tags=["test-results"])

    @router.get("/latest/summary")
    def latest_summary() -> Dict[str, Any]:
        path = RESULT_DIR / "latest_summary.json"
        if not path.exists():
            return {
                "available": False,
                "message": "No test result generated yet.",
                "hint": "Run: python -m test.run",
            }
        data = json.loads(path.read_text(encoding="utf-8"))
        data["available"] = True
        return data

    @router.get("/latest/cases")
    def latest_cases() -> Dict[str, Any]:
        path = RESULT_DIR / "latest_cases.json"
        if not path.exists():
            return {
                "available": False,
                "message": "No detailed test cases generated yet.",
                "hint": "Run: python -m test.run",
                "cases": [],
            }
        return {
            "available": True,
            "cases": json.loads(path.read_text(encoding="utf-8")),
        }

    @router.get("/latest/report")
    def latest_report():
        path = RESULT_DIR / "latest_report.md"
        if not path.exists():
            return {
                "available": False,
                "message": "No markdown report generated yet.",
                "hint": "Run: python -m test.run",
            }
        return FileResponse(path, media_type="text/markdown")

    @router.get("/latest/dashboard")
    def latest_dashboard():
        path = RESULT_DIR / "latest_dashboard.html"
        if not path.exists():
            return {
                "available": False,
                "message": "No dashboard generated yet.",
                "hint": "Run: python -m test.run",
            }
        return FileResponse(path, media_type="text/html")
