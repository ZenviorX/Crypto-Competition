from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from backend.sandbox.native_sandbox_executor import (
    NATIVE_RUNS_DIR,
    RUNTIME_WORKSPACE,
    execute_tool_in_native_sandbox,
)
from backend.sandbox.real_sandbox_executor import execute_tool_in_real_sandbox


router = APIRouter(prefix="/sandbox-native", tags=["Native Sandbox"])


@router.get("/health")
def native_sandbox_health() -> Dict[str, Any]:
    return {
        "success": True,
        "sandbox_type": "native_subprocess",
        "requires_external_software": False,
        "runtime_workspace": str(RUNTIME_WORKSPACE),
        "runs_dir": str(NATIVE_RUNS_DIR),
        "note": (
            "This no-install sandbox uses a restricted Python subprocess runner. "
            "It is weaker than Docker/gVisor/Firecracker, but works without Docker Desktop."
        ),
    }


@router.post("/execute")
def native_sandbox_execute(payload: Dict[str, Any]) -> Dict[str, Any]:
    tool = str(payload.get("tool") or "")
    params = dict(payload.get("params") or {})
    sandbox_profile = str(payload.get("sandbox_profile") or "local_readonly")

    if not tool:
        raise HTTPException(status_code=400, detail="tool is required.")

    return execute_tool_in_native_sandbox(
        tool=tool,
        params=params,
        profile_name=sandbox_profile,
    )


@router.post("/hybrid-execute")
def hybrid_sandbox_execute(payload: Dict[str, Any]) -> Dict[str, Any]:
    tool = str(payload.get("tool") or "")
    params = dict(payload.get("params") or {})
    sandbox_profile = str(payload.get("sandbox_profile") or "local_readonly")
    prefer = str(payload.get("prefer") or "auto")

    if not tool:
        raise HTTPException(status_code=400, detail="tool is required.")

    return execute_tool_in_real_sandbox(
        tool=tool,
        params=params,
        profile_name=sandbox_profile,
        prefer=prefer,
    )


@router.get("/runs")
def list_native_sandbox_runs() -> Dict[str, Any]:
    NATIVE_RUNS_DIR.mkdir(parents=True, exist_ok=True)

    runs = []
    for run_dir in sorted(NATIVE_RUNS_DIR.glob("native_*"), reverse=True):
        evidence_path = run_dir / "evidence.json"
        evidence = _read_json(evidence_path) if evidence_path.exists() else {}
        runs.append({
            "run_id": run_dir.name,
            "relative_path": str(run_dir.relative_to(RUNTIME_WORKSPACE)),
            "tool": evidence.get("tool"),
            "sandbox_profile": evidence.get("sandbox_profile"),
            "success": (evidence.get("tool_result") or {}).get("success"),
            "exit_code": evidence.get("exit_code"),
            "evidence_hash": evidence.get("evidence_hash"),
            "created_at": evidence.get("started_at"),
        })

    return {
        "success": True,
        "count": len(runs),
        "runs": runs,
    }


@router.get("/runs/{run_id}")
def read_native_sandbox_run(run_id: str) -> Dict[str, Any]:
    if "/" in run_id or "\\" in run_id or not run_id.startswith("native_"):
        raise HTTPException(status_code=400, detail="Invalid native sandbox run id.")

    run_dir = (NATIVE_RUNS_DIR / run_id).resolve()
    try:
        run_dir.relative_to(NATIVE_RUNS_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid native sandbox run path.") from exc

    evidence_path = run_dir / "evidence.json"
    if not evidence_path.exists():
        raise HTTPException(status_code=404, detail="Native sandbox evidence not found.")

    return {
        "success": True,
        "run_id": run_id,
        "evidence": _read_json(evidence_path),
    }


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": str(exc)}
