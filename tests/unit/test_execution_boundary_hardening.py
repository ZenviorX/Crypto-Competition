from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import backend.guardrails.capability_token_ledger as ledger
import backend.proxy.tool_proxy_service as proxy_service
from backend.guardrails.capability_token import (
    claim_capability_token_for_execution,
    finalize_capability_token_execution,
    issue_capability_token,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _read_routes_for_mode(
    mode: str,
) -> dict:
    script = r"""
import json

from backend.main import (
    AGENTGUARD_MODE,
    COMPETITION_MODE,
    app,
)

paths = sorted(
    {
        str(getattr(route, "path", ""))
        for route in app.routes
    }
)

print(
    json.dumps(
        {
            "mode": AGENTGUARD_MODE,
            "competition": COMPETITION_MODE,
            "paths": paths,
        }
    )
)
"""

    environment = dict(os.environ)
    environment["AGENTGUARD_MODE"] = mode
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert completed.returncode == 0, (
        completed.stdout
        + "\n"
        + completed.stderr
    )

    output_lines = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip()
    ]

    assert output_lines, (
        "Route inspection returned no output."
    )

    return json.loads(
        output_lines[-1]
    )


def _use_temporary_ledger(
    tmp_path: Path,
) -> None:
    ledger.LEDGER_DIR = tmp_path
    ledger.LEDGER_DB = (
        tmp_path
        / "capability_token_test.db"
    )

    ledger.reset_token_ledger()


def test_competition_mode_removes_direct_execution_routes():
    state = _read_routes_for_mode(
        "competition"
    )

    paths = set(state["paths"])

    required_routes = {
        "/mcp",
        "/api/status",
        (
            "/.well-known/"
            "oauth-protected-resource"
        ),
    }

    forbidden_routes = {
        "/gateway/call",
        "/agent/call",
        "/tool-proxy/authorize",
        "/sandbox-native/execute",
        "/sandbox-native/hybrid-execute",
        "/sandbox-docker/execute",
        "/approval/confirm/{pending_id}",
    }

    assert state["mode"] == "competition"
    assert state["competition"] is True
    assert required_routes.issubset(paths)
    assert not (
        forbidden_routes
        & paths
    )


def test_demo_mode_retains_development_routes():
    state = _read_routes_for_mode(
        "demo"
    )

    paths = set(state["paths"])

    required_routes = {
        "/mcp",
        "/gateway/call",
        "/tool-proxy/authorize",
        "/sandbox-native/execute",
    }

    assert state["mode"] == "demo"
    assert state["competition"] is False
    assert required_routes.issubset(paths)


def test_sandbox_entry_requires_explicit_evidence():
    assert (
        proxy_service._sandbox_entered(
            {
                "sandbox_evidence": {
                    "run_id": "run-only",
                }
            }
        )
        is False
    )

    assert (
        proxy_service._sandbox_entered(
            {
                "sandbox_evidence": {
                    "started_at": (
                        "2026-08-01T00:00:00Z"
                    ),
                }
            }
        )
        is False
    )

    assert (
        proxy_service._sandbox_entered(
            {
                "success": True,
                "sandbox_evidence": {
                    "executed": False,
                    "run_id": "not-started",
                },
            }
        )
        is False
    )

    assert (
        proxy_service._sandbox_entered(
            {
                "success": False,
                "sandbox_evidence": {
                    "executed": True,
                    "exit_code": 2,
                },
            }
        )
        is True
    )

    assert (
        proxy_service._sandbox_entered(
            {
                "sandbox_evidence": {
                    "lifecycle_state": (
                        "completed"
                    ),
                }
            }
        )
        is True
    )


def test_only_one_concurrent_token_claim_succeeds(
    tmp_path,
):
    _use_temporary_ledger(
        tmp_path
    )

    issued = issue_capability_token(
        user="alice",
        agent_platform="mcp-client",
        original_task="Read public notice.",
        capability_contract={
            "contract_version": "test-v1",
        },
        tool="file.read",
        params={
            "path": "public/notice.txt",
        },
        sandbox_profile="local_readonly",
    )

    token = issued["token"]

    barrier = threading.Barrier(2)
    results = []
    result_lock = threading.Lock()

    def claim(
        execution_id: str,
    ) -> None:
        barrier.wait()

        result = (
            claim_capability_token_for_execution(
                token=token,
                execution_id=execution_id,
            )
        )

        with result_lock:
            results.append(
                result
            )

    workers = [
        threading.Thread(
            target=claim,
            args=("exec_A",),
        ),
        threading.Thread(
            target=claim,
            args=("exec_B",),
        ),
    ]

    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join()

    acquired = [
        result
        for result in results
        if result.get("acquired")
        is True
    ]

    rejected = [
        result
        for result in results
        if result.get("acquired")
        is False
    ]

    assert len(acquired) == 1
    assert len(rejected) == 1

    winner = acquired[0][
        "execution_id"
    ]

    finalized = (
        finalize_capability_token_execution(
            token=token,
            execution_id=winner,
            outcome="consumed",
            result_hash=(
                "sha256:concurrency-test"
            ),
        )
    )

    assert finalized[
        "finalized"
    ] is True

    replay = (
        claim_capability_token_for_execution(
            token=token,
            execution_id="exec_replay",
        )
    )

    assert replay[
        "acquired"
    ] is False

    assert replay[
        "status"
    ] == "consumed"


def test_replay_never_enters_sandbox(
    tmp_path,
    monkeypatch,
):
    _use_temporary_ledger(
        tmp_path
    )

    issued = issue_capability_token(
        user="alice",
        agent_platform="mcp-client",
        original_task="Read public notice.",
        capability_contract={
            "contract_version": "test-v1",
        },
        tool="file.read",
        params={
            "path": "public/notice.txt",
        },
        sandbox_profile="local_readonly",
    )

    request = SimpleNamespace(
        capability_token=(
            issued["token"]
        ),
        tool="file.read",
        params={
            "path": "public/notice.txt",
        },
        sandbox_profile=(
            "local_readonly"
        ),
    )

    sandbox_calls = []

    def sandbox_executor(
        **kwargs,
    ):
        sandbox_calls.append(
            kwargs
        )

        return {
            "success": True,
            "tool_result": {
                "success": True,
                "result": "notice",
            },
            "sandbox_evidence": {
                "executed": True,
                "exit_code": 0,
                "lifecycle_state": (
                    "completed"
                ),
            },
        }

    monkeypatch.setattr(
        proxy_service,
        "execute_tool_in_real_sandbox",
        sandbox_executor,
    )

    first = (
        proxy_service
        ._execute_with_atomic_capability_claim(
            request
        )
    )

    replay = (
        proxy_service
        ._execute_with_atomic_capability_claim(
            request
        )
    )

    assert first[
        "claim"
    ]["acquired"] is True

    assert first[
        "executed"
    ] is True

    assert first[
        "finalization"
    ]["status"] == "consumed"

    assert replay[
        "claim"
    ]["acquired"] is False

    assert replay[
        "executed"
    ] is False

    assert len(
        sandbox_calls
    ) == 1


def test_failed_sandbox_entry_marks_token_failed(
    tmp_path,
    monkeypatch,
):
    _use_temporary_ledger(
        tmp_path
    )

    issued = issue_capability_token(
        user="bob",
        agent_platform="mcp-client",
        original_task="Read public file.",
        capability_contract={
            "contract_version": "test-v1",
        },
        tool="file.read",
        params={
            "path": "public/test.txt",
        },
        sandbox_profile="local_readonly",
    )

    request = SimpleNamespace(
        capability_token=(
            issued["token"]
        ),
        tool="file.read",
        params={
            "path": "public/test.txt",
        },
        sandbox_profile=(
            "local_readonly"
        ),
    )

    def failed_executor(
        **kwargs,
    ):
        return {
            "success": False,
            "tool_result": {
                "success": False,
                "result": (
                    "runner failed to start"
                ),
            },
            "sandbox_evidence": {
                "executed": False,
                "lifecycle_state": (
                    "failed_to_start"
                ),
            },
        }

    monkeypatch.setattr(
        proxy_service,
        "execute_tool_in_real_sandbox",
        failed_executor,
    )

    attempt = (
        proxy_service
        ._execute_with_atomic_capability_claim(
            request
        )
    )

    assert attempt[
        "claim"
    ]["acquired"] is True

    assert attempt[
        "executed"
    ] is False

    assert attempt[
        "finalization"
    ]["finalized"] is True

    assert attempt[
        "finalization"
    ]["status"] == "failed"

    replay = (
        proxy_service
        ._execute_with_atomic_capability_claim(
            request
        )
    )

    assert replay[
        "claim"
    ]["acquired"] is False

    assert replay[
        "claim"
    ]["status"] == "failed"
