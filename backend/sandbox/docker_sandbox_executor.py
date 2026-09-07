from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.tool_executor import ensure_sandbox_ready


BASE_DIR = Path(__file__).resolve().parents[2]
RUNTIME_WORKSPACE = BASE_DIR / "runtime_workspace"
PUBLIC_DIR = RUNTIME_WORKSPACE / "public"
COURSE_DIR = RUNTIME_WORKSPACE / "course"
OUTBOX_DIR = RUNTIME_WORKSPACE / "outbox"
DATABASE_PATH = (
    RUNTIME_WORKSPACE
    / "agent_runtime.db"
)
DOCKER_RUNS_DIR = (
    RUNTIME_WORKSPACE
    / "sandbox_runs"
)
RUNNER_DIR = (
    Path(__file__).resolve().parent
    / "runner"
)

# Runner 功能发生变化后使用新镜像标签，
# 防止继续运行旧缓存镜像。
IMAGE_NAME = "agentguard-tool-sandbox:v2"
DEFAULT_TIMEOUT_SECONDS = 30


PROFILE_RUNTIME_CONFIG: Dict[str, Dict[str, Any]] = {
    "default": {
        "network": "none",
        "read_only_rootfs": True,
        "memory": "128m",
        "cpus": "0.5",
        "pids_limit": 64,
        "mounts": [
            {"source": "public", "target": "/workspace/public", "readonly": True},
            {"source": "course", "target": "/workspace/course", "readonly": True},
            {"source": "outbox", "target": "/workspace/outbox", "readonly": False},
        ],
    },
    "local_readonly": {
        "network": "none",
        "read_only_rootfs": True,
        "memory": "128m",
        "cpus": "0.5",
        "pids_limit": 64,
        "mounts": [
            {"source": "public", "target": "/workspace/public", "readonly": True},
            {"source": "course", "target": "/workspace/course", "readonly": True},
        ],
    },
    "local_safe_write": {
        "network": "none",
        "read_only_rootfs": True,
        "memory": "128m",
        "cpus": "0.5",
        "pids_limit": 64,
        "mounts": [
            {"source": "public", "target": "/workspace/public", "readonly": True},
            {"source": "course", "target": "/workspace/course", "readonly": True},
            {"source": "outbox", "target": "/workspace/outbox", "readonly": False},
        ],
    },
    "no_shell": {
        "network": "none",
        "read_only_rootfs": True,
        "memory": "128m",
        "cpus": "0.5",
        "pids_limit": 64,
        "mounts": [
            {"source": "public", "target": "/workspace/public", "readonly": True},
            {"source": "course", "target": "/workspace/course", "readonly": True},
            {"source": "outbox", "target": "/workspace/outbox", "readonly": False},
        ],
    },
    "strict": {
        "network": "none",
        "read_only_rootfs": True,
        "memory": "128m",
        "cpus": "0.5",
        "pids_limit": 64,
        "mounts": [
            {"source": "public", "target": "/workspace/public", "readonly": True},
        ],
    },
}


SOURCE_DIR_MAP = {
    "public": PUBLIC_DIR,
    "course": COURSE_DIR,
    "outbox": OUTBOX_DIR,
}




def docker_available(
    timeout_seconds: int = 3,
) -> bool:
    """
    自动沙箱模式只接受可响应的 Linux Docker daemon。

    Windows GitHub Runner 可能安装 Docker CLI，
    甚至临时启动 Windows 容器 daemon，但本项目的
    沙箱镜像是 Linux 镜像，不能将其视为可用环境。
    """
    docker_path = shutil.which(
        "docker"
    )

    if not docker_path:
        return False

    try:
        completed = subprocess.run(
            [
                docker_path,
                "info",
                "--format",
                "{{.OSType}}|{{.ServerVersion}}",
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(
                1,
                int(timeout_seconds),
            ),
            check=False,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        return False

    if completed.returncode != 0:
        return False

    output = str(
        completed.stdout
        or ""
    ).strip()

    if "|" not in output:
        return False

    os_type, server_version = (
        output.split(
            "|",
            1,
        )
    )

    return bool(
        os_type.strip().lower()
        == "linux"
        and server_version.strip()
    )




def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_json(data: Dict[str, Any]) -> str:
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def normalize_profile(profile_name: Optional[str]) -> str:
    normalized = str(profile_name or "default").strip().lower()
    return normalized if normalized in PROFILE_RUNTIME_CONFIG else "default"


def ensure_workspace_ready() -> None:
    ensure_sandbox_ready()
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    COURSE_DIR.mkdir(parents=True, exist_ok=True)
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    DOCKER_RUNS_DIR.mkdir(parents=True, exist_ok=True)


def build_image_if_needed() -> Dict[str, Any]:
    if not docker_available():
        return {
            "available": False,
            "built": False,
            "image": IMAGE_NAME,
            "reason": "Docker CLI was not found in PATH.",
        }

    inspect = subprocess.run(
        ["docker", "image", "inspect", IMAGE_NAME],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    if inspect.returncode == 0:
        return {
            "available": True,
            "built": False,
            "image": IMAGE_NAME,
            "reason": "Docker image already exists.",
        }

    build = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, str(RUNNER_DIR)],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    return {
        "available": build.returncode == 0,
        "built": build.returncode == 0,
        "image": IMAGE_NAME,
        "returncode": build.returncode,
        "stdout_tail": build.stdout[-2000:],
        "stderr_tail": build.stderr[-2000:],
        "reason": "Docker image built." if build.returncode == 0 else "Docker image build failed.",
    }


def _mount_arg(source: Path, target: str, readonly: bool) -> str:
    value = f"type=bind,src={source.resolve()},dst={target}"
    if readonly:
        value += ",readonly"
    return value


def build_docker_command(run_dir: Path, profile_name: str) -> List[str]:
    profile = PROFILE_RUNTIME_CONFIG[normalize_profile(profile_name)]

    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        str(profile["network"]),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(profile["pids_limit"]),
        "--memory",
        str(profile["memory"]),
        "--cpus",
        str(profile["cpus"]),
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
    ]

    if profile.get("read_only_rootfs"):
        command.append("--read-only")

    command.extend([
        "--mount",
        _mount_arg(run_dir, "/sandbox", readonly=False),
    ])

    for mount in profile.get("mounts", []):
        source_name = str(mount["source"])
        source_path = SOURCE_DIR_MAP[
            source_name
        ]

        source_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        command.extend(
            [
                "--mount",
                _mount_arg(
                    source_path,
                    str(mount["target"]),
                    bool(
                        mount.get(
                            "readonly",
                            True,
                        )
                    ),
                ),
            ]
        )

    # 数据库文件始终以只读方式挂载，
    # 物理层面禁止容器修改数据库。
    if (
        not DATABASE_PATH.exists()
        or not DATABASE_PATH.is_file()
    ):
        raise RuntimeError(
            "Sandbox database was not initialized."
        )

    command.extend(
        [
            "--mount",
            _mount_arg(
                DATABASE_PATH,
                "/workspace/agent_runtime.db",
                readonly=True,
            ),
        ]
    )

    command.extend([
        IMAGE_NAME,
        "/sandbox/input.json",
        "/sandbox/result.json",
    ])

    return command


def _public_mounts(profile_name: str) -> List[Dict[str, Any]]:
    profile = PROFILE_RUNTIME_CONFIG[normalize_profile(profile_name)]
    mounts = [
        {
            "source": "sandbox_run_dir",
            "target": "/sandbox",
            "readonly": False,
        }
    ]
    mounts.extend(
        profile.get(
            "mounts",
            [],
        )
    )

    mounts.append(
        {
            "source": "agent_runtime.db",
            "target": (
                "/workspace/"
                "agent_runtime.db"
            ),
            "readonly": True,
        }
    )

    return _jsonable(mounts)


def execute_tool_in_docker_sandbox(
    tool: str,
    params: Optional[Dict[str, Any]],
    profile_name: Optional[str] = "default",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    ensure_workspace_ready()

    params = params or {}
    profile = normalize_profile(profile_name)
    run_id = f"docker_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}"
    run_dir = DOCKER_RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    input_payload = {
        "run_id": run_id,
        "tool": tool,
        "params": params,
        "sandbox_profile": profile,
        "created_at": _now(),
    }
    input_path = run_dir / "input.json"
    result_path = run_dir / "result.json"
    evidence_path = run_dir / "evidence.json"
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"

    input_path.write_text(json.dumps(input_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    image_status = build_image_if_needed()

    evidence: Dict[str, Any] = {
        "run_id": run_id,
        "sandbox_type": "docker",
        "sandbox_profile": profile,
        "tool": tool,
        "params": params,
        "image": IMAGE_NAME,
        "docker_available": image_status.get("available") is True,
        "image_status": image_status,
        "runtime_policy": {
            "network": PROFILE_RUNTIME_CONFIG[profile]["network"],
            "read_only_rootfs": PROFILE_RUNTIME_CONFIG[profile]["read_only_rootfs"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
            "memory": PROFILE_RUNTIME_CONFIG[profile]["memory"],
            "cpus": PROFILE_RUNTIME_CONFIG[profile]["cpus"],
            "pids_limit": PROFILE_RUNTIME_CONFIG[profile]["pids_limit"],
            "mounts": _public_mounts(profile),
        },
        "paths": {
            "run_dir": str(run_dir.relative_to(RUNTIME_WORKSPACE)),
            "input": str(input_path.relative_to(RUNTIME_WORKSPACE)),
            "result": str(result_path.relative_to(RUNTIME_WORKSPACE)),
            "stdout": str(stdout_path.relative_to(RUNTIME_WORKSPACE)),
            "stderr": str(stderr_path.relative_to(RUNTIME_WORKSPACE)),
            "evidence": str(evidence_path.relative_to(RUNTIME_WORKSPACE)),
        },
        "started_at": _now(),
    }

    if not image_status.get("available"):
        tool_result = {
            "success": False,
            "result": image_status.get("reason", "Docker sandbox is not available."),
        }
        evidence.update({
            "finished_at": _now(),
            "executed": False,
            "exit_code": None,
            "timeout": False,
            "tool_result": tool_result,
        })
        evidence["evidence_hash"] = _hash_json(evidence)
        evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "success": False,
            "result": tool_result.get("result"),
            "sandbox_evidence": evidence,
        }

    command = build_docker_command(run_dir=run_dir, profile_name=profile)

    try:
        completed = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        timeout = False
    except subprocess.TimeoutExpired as exc:
        completed = None
        timeout = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
    else:
        stdout = completed.stdout
        stderr = completed.stderr

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
                    "result": f"Failed to parse Docker sandbox result: {exc}",
                },
                "error": str(exc),
            }
    else:
        runner_payload = {
            "success": False,
            "tool_result": {
                "success": False,
                "result": "Docker sandbox did not produce result.json.",
            },
            "error": "Missing result.json",
        }

    exit_code = None if completed is None else completed.returncode
    tool_result = runner_payload.get("tool_result") or {
        "success": False,
        "result": runner_payload.get("error") or "Unknown Docker sandbox result.",
    }

    evidence.update({
        "finished_at": _now(),
        "executed": completed is not None,
        "exit_code": exit_code,
        "timeout": timeout,
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
