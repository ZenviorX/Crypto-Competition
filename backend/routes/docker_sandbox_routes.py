from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from backend.sandbox.docker_sandbox_executor import (
    DOCKER_RUNS_DIR,
    IMAGE_NAME,
    RUNTIME_WORKSPACE,
    build_image_if_needed,
    docker_available,
    execute_tool_in_docker_sandbox,
)


router = APIRouter(prefix="/sandbox-docker", tags=["Docker Sandbox"])


@router.get("/health")
def docker_sandbox_health() -> Dict[str, Any]:
    image_status = build_image_if_needed() if docker_available() else {
        "available": False,
        "built": False,
        "image": IMAGE_NAME,
        "reason": "Docker CLI was not found in PATH.",
    }

    return {
        "success": bool(image_status.get("available")),
        "sandbox_type": "docker",
        "image": IMAGE_NAME,
        "docker_cli_available": docker_available(),
        "image_status": image_status,
        "runtime_workspace": str(RUNTIME_WORKSPACE),
        "runs_dir": str(DOCKER_RUNS_DIR),
        "note": "This endpoint verifies the real Docker execution sandbox used after Gateway allow.",
    }


@router.post("/execute")
def docker_sandbox_execute(payload: Dict[str, Any]) -> Dict[str, Any]:
    tool = str(payload.get("tool") or "")
    params = dict(payload.get("params") or {})
    sandbox_profile = str(payload.get("sandbox_profile") or "local_readonly")

    if not tool:
        raise HTTPException(status_code=400, detail="tool is required.")

    return execute_tool_in_docker_sandbox(
        tool=tool,
        params=params,
        profile_name=sandbox_profile,
    )


@router.get("/runs")
def list_docker_sandbox_runs() -> Dict[str, Any]:
    DOCKER_RUNS_DIR.mkdir(parents=True, exist_ok=True)

    runs = []
    for run_dir in sorted(DOCKER_RUNS_DIR.glob("docker_*"), reverse=True):
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
def read_docker_sandbox_run(run_id: str) -> Dict[str, Any]:
    if "/" in run_id or "\\" in run_id or not run_id.startswith("docker_"):
        raise HTTPException(status_code=400, detail="Invalid Docker sandbox run id.")

    run_dir = (DOCKER_RUNS_DIR / run_id).resolve()
    try:
        run_dir.relative_to(DOCKER_RUNS_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Docker sandbox run path.") from exc

    evidence_path = run_dir / "evidence.json"
    if not evidence_path.exists():
        raise HTTPException(status_code=404, detail="Docker sandbox evidence not found.")

    return {
        "success": True,
        "run_id": run_id,
        "evidence": _read_json(evidence_path),
    }


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "error": str(exc),
        }
