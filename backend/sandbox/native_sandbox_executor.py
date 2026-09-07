from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from backend.tools.tool_executor import ensure_sandbox_ready


BASE_DIR = Path(__file__).resolve().parents[2]
RUNTIME_WORKSPACE = BASE_DIR / "runtime_workspace"
PUBLIC_DIR = RUNTIME_WORKSPACE / "public"
COURSE_DIR = RUNTIME_WORKSPACE / "course"
OUTBOX_DIR = RUNTIME_WORKSPACE / "outbox"
NATIVE_RUNS_DIR = RUNTIME_WORKSPACE / "native_sandbox_runs"
RUNNER_PATH = Path(__file__).resolve().parent / "runner" / "native_sandbox_tool.py"
DEFAULT_TIMEOUT_SECONDS = 15


NATIVE_PROFILE_CONFIG: Dict[str, Dict[str, Any]] = {
    "default": {
        "allowed_prefixes": ["public/", "course/", "outbox/"],
        "writable_prefixes": ["outbox/"],
        "network": "blocked_by_tool_surface",
        "shell": "interpreter_only",
        "memory": "not_enforced_without_os_container",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "local_readonly": {
        "allowed_prefixes": ["public/", "course/"],
        "writable_prefixes": [],
        "network": "blocked_by_tool_surface",
        "shell": "interpreter_only",
        "memory": "not_enforced_without_os_container",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "local_safe_write": {
        "allowed_prefixes": ["public/", "course/", "outbox/"],
        "writable_prefixes": ["outbox/"],
        "network": "blocked_by_tool_surface",
        "shell": "interpreter_only",
        "memory": "not_enforced_without_os_container",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "no_shell": {
        "allowed_prefixes": ["public/", "course/", "outbox/"],
        "writable_prefixes": ["outbox/"],
        "network": "blocked_by_tool_surface",
        "shell": "disabled",
        "memory": "not_enforced_without_os_container",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "strict": {
        "allowed_prefixes": ["public/"],
        "writable_prefixes": [],
        "network": "blocked_by_tool_surface",
        "shell": "disabled",
        "memory": "not_enforced_without_os_container",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_json(data: Dict[str, Any]) -> str:
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def normalize_profile(profile_name: Optional[str]) -> str:
    normalized = str(profile_name or "default").strip().lower()
    return normalized if normalized in NATIVE_PROFILE_CONFIG else "default"


def ensure_workspace_ready() -> None:
    ensure_sandbox_ready()
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    COURSE_DIR.mkdir(parents=True, exist_ok=True)
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    NATIVE_RUNS_DIR.mkdir(parents=True, exist_ok=True)


def execute_tool_in_native_sandbox(
    tool: str,
    params: Optional[Dict[str, Any]],
    profile_name: Optional[str] = "default",
    timeout_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    No-install execution sandbox.

    This is not a VM/container. It is a restricted subprocess runner with:
    - strict tool allowlist implemented by native_sandbox_tool.py
    - path allowlist rooted at runtime_workspace
    - no arbitrary shell=True execution
    - timeout and evidence files

    It is intended as the default local demo backend when Docker Desktop is not installed.
    """

    ensure_workspace_ready()
    params = params or {}
    profile = normalize_profile(profile_name)
    runtime_policy = dict(NATIVE_PROFILE_CONFIG[profile])
    timeout = int(timeout_seconds or runtime_policy.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)

    run_id = f"native_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}"
    run_dir = NATIVE_RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    input_path = run_dir / "input.json"
    result_path = run_dir / "result.json"
    evidence_path = run_dir / "evidence.json"
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"

    input_payload = {
        "run_id": run_id,
        "tool": tool,
        "params": params,
        "sandbox_profile": profile,
        "runtime_workspace": str(RUNTIME_WORKSPACE),
        "runtime_policy": runtime_policy,
        "created_at": _now(),
    }
    input_path.write_text(json.dumps(input_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    evidence: Dict[str, Any] = {
        "run_id": run_id,
        "sandbox_type": "native_subprocess",
        "sandbox_profile": profile,
        "tool": tool,
        "params": params,
        "engine": "python_subprocess_restricted_runner",
        "runtime_policy": runtime_policy,
        "paths": {
            "run_dir": str(run_dir.relative_to(RUNTIME_WORKSPACE)),
            "input": str(input_path.relative_to(RUNTIME_WORKSPACE)),
            "result": str(result_path.relative_to(RUNTIME_WORKSPACE)),
            "stdout": str(stdout_path.relative_to(RUNTIME_WORKSPACE)),
            "stderr": str(stderr_path.relative_to(RUNTIME_WORKSPACE)),
            "evidence": str(evidence_path.relative_to(RUNTIME_WORKSPACE)),
        },
        "security_notes": [
            "No external sandbox software is required.",
            "The runner exposes only a small tool allowlist and denies path traversal.",
            "secret/ and private/ are not in allowed prefixes for public demo profiles.",
            "This is weaker than Docker/gVisor/Firecracker because it is not an OS container or VM.",
        ],
        "started_at": _now(),
    }

    try:
        completed = subprocess.run(
            [sys.executable, str(RUNNER_PATH), str(input_path), str(result_path)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        timeout_hit = False
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        completed = None
        timeout_hit = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        exit_code = None

    stdout_path.write_text(str(stdout), encoding="utf-8", errors="replace")
    stderr_path.write_text(str(stderr), encoding="utf-8", errors="replace")

    if result_path.exists():
        try:
            runner_payload = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception as exc:
            runner_payload = {
                "success": False,
                "tool_result": {
                    "success": False,
                    "result": f"Failed to parse native sandbox result: {exc}",
                },
                "error": str(exc),
            }
    else:
        runner_payload = {
            "success": False,
            "tool_result": {
                "success": False,
                "result": "Native sandbox did not produce result.json.",
            },
            "error": "Missing result.json",
        }

    tool_result = runner_payload.get("tool_result") or {
        "success": False,
        "result": runner_payload.get("error") or "Unknown native sandbox result.",
    }

    evidence.update({
        "finished_at": _now(),
        "executed": completed is not None,
        "exit_code": exit_code,
        "timeout": timeout_hit,
        "stdout_tail": str(stdout)[-2000:],
        "stderr_tail": str(stderr)[-2000:],
        "runner_payload": _jsonable(runner_payload),
        "tool_result": _jsonable(tool_result),
    })
    evidence["evidence_hash"] = _hash_json(evidence)
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "success": bool(tool_result.get("success")),
        "result": tool_result.get("result"),
        "tool_result": _jsonable(tool_result),
        "sandbox_evidence": evidence,
    }
