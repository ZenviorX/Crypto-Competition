from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
RUNTIME = ROOT / ".agentguard"
STATE_FILE = RUNTIME / "launcher-state.json"
LOCK_FILE = RUNTIME / "launcher.lock"

GRACEFUL_STOP_SECONDS = 5.0
FORCE_STOP_SECONDS = 3.0

SERVICES: dict[str, dict[str, Any]] = {
    "backend": {
        "label": "Backend",
        "port": 8000,
        "ready": "http://127.0.0.1:8000/api/status",
        "marker": "AgentGuard",
        "process_markers": ("backend.main:app", "backend.main"),
    },
    "frontend": {
        "label": "Frontend",
        "port": 5173,
        "ready": "http://127.0.0.1:5173",
        "marker": "AgentGuard",
        "process_markers": ("vite", "run dev"),
    },
    "oauth": {
        "label": "OAuth",
        "port": 9000,
        "ready": "http://127.0.0.1:9000/health",
        "marker": "local_demo_only",
        "process_markers": ("backend.oauth.demo_authorization_server",),
    },
}

PYTHON_MODULES = (
    "fastapi",
    "uvicorn",
    "pydantic",
    "yaml",
    "jwt",
    "cryptography",
    "openai",
    "dotenv",
    "sentence_transformers",
    "numpy",
)


class LaunchError(RuntimeError):
    pass


def is_windows() -> bool:
    return os.name == "nt"


def run_powershell(script: str, *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def load_state() -> dict[str, Any]:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict[str, Any]) -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(STATE_FILE)


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if is_windows():
        return run_powershell(
            f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
        ).returncode == 0
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def reap_child(pid: int) -> bool:
    if is_windows() or pid <= 0:
        return False
    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        return waited == pid
    except (ChildProcessError, ProcessLookupError, PermissionError):
        return False


def wait_pid_exit(pid: int, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if reap_child(pid) or not pid_alive(pid):
            return True
        time.sleep(0.1)
    return reap_child(pid) or not pid_alive(pid)


def process_group_alive(pgid: int) -> bool:
    if pgid <= 0 or is_windows():
        return False
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_process_group_exit(pgid: int, seconds: float, leader_pid: int = 0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if leader_pid:
            reap_child(leader_pid)
        if not process_group_alive(pgid):
            return True
        time.sleep(0.1)
    if leader_pid:
        reap_child(leader_pid)
    return not process_group_alive(pgid)


def command_line(pid: int) -> str:
    if is_windows():
        result = run_powershell(
            f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}" '
            '-ErrorAction SilentlyContinue; if ($p) { $p.CommandLine }'
        )
        return result.stdout.strip()
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()


def listening_pids(port: int) -> set[int]:
    if is_windows():
        result = run_powershell(
            f"Get-NetTCPConnection -State Listen -LocalPort {port} "
            "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique"
        )
        return {int(line) for line in result.stdout.splitlines() if line.strip().isdigit()}

    lsof = shutil.which("lsof")
    if not lsof:
        return set()
    result = subprocess.run(
        [lsof, "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
        capture_output=True,
        text=True,
        check=False,
    )
    return {int(line) for line in result.stdout.splitlines() if line.strip().isdigit()}


def related(pid: int, service: str) -> bool:
    line = command_line(pid).lower()
    if not line:
        return False
    markers = SERVICES[service]["process_markers"]
    if not any(marker.lower() in line for marker in markers):
        return False
    if service in {"backend", "oauth"}:
        return True
    return str(ROOT).lower() in line


def project_pids(service: str) -> set[int]:
    markers = SERVICES[service]["process_markers"]
    if is_windows():
        env = os.environ.copy()
        env["AG_ROOT"] = str(ROOT)
        env["AG_MARKERS"] = "|".join(markers)
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                '$r=$env:AG_ROOT.ToLower(); $m=$env:AG_MARKERS; '
                'Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | '
                'Where-Object { $_.CommandLine -and $_.CommandLine.ToLower().Contains($r) '
                '-and $_.CommandLine -match $m } | '
                'Select-Object -ExpandProperty ProcessId -Unique',
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        return {int(line) for line in result.stdout.splitlines() if line.strip().isdigit()}

    result = subprocess.run(
        ["ps", "-eo", "pid=,args="], capture_output=True, text=True, check=False
    )
    found: set[int] = set()
    root = str(ROOT).lower()
    for raw in result.stdout.splitlines():
        pid_text, _, line = raw.strip().partition(" ")
        lowered = line.lower()
        if pid_text.isdigit() and root in lowered and any(m.lower() in lowered for m in markers):
            found.add(int(pid_text))
    return found


def child_pids(pid: int) -> list[int]:
    result = subprocess.run(
        ["pgrep", "-P", str(pid)], capture_output=True, text=True, check=False
    )
    return [int(item) for item in result.stdout.splitlines() if item.strip().isdigit()]


def kill_tree(pid: int) -> None:
    """Terminate one managed process and every descendant/process-group member.

    Services are started in their own process groups. Ctrl+C reaches the launcher,
    then this function shuts down the complete service group on both Windows and
    POSIX systems. A forced termination is used only after a graceful timeout.
    """
    if pid <= 0 or pid in {os.getpid(), os.getppid()} or not pid_alive(pid):
        return

    if is_windows():
        ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
        if ctrl_break is not None:
            try:
                os.kill(pid, ctrl_break)
            except (OSError, ValueError):
                pass
            else:
                if wait_pid_exit(pid, GRACEFUL_STOP_SECONDS):
                    return

        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        wait_pid_exit(pid, FORCE_STOP_SECONDS)
        return

    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        pgid = 0

    if pgid > 0 and pgid != os.getpgrp():
        try:
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        if wait_process_group_exit(pgid, GRACEFUL_STOP_SECONDS, pid):
            return
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        wait_process_group_exit(pgid, FORCE_STOP_SECONDS, pid)
        return

    # Safety fallback for a process that was not started in a separate group.
    for child in child_pids(pid):
        kill_tree(child)
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    if wait_pid_exit(pid, GRACEFUL_STOP_SECONDS):
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    wait_pid_exit(pid, FORCE_STOP_SECONDS)


def port_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if is_windows() and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def wait_port_free(port: int, seconds: float = 8) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if port_free(port):
            return True
        time.sleep(0.2)
    return port_free(port)


def healthy(service: str) -> bool:
    spec = SERVICES[service]
    request = Request(spec["ready"], headers={"User-Agent": "AgentGuard-Launcher/3.0"})
    try:
        with urlopen(request, timeout=1.5) as response:
            body = response.read(256_000).decode("utf-8", errors="replace")
            return int(getattr(response, "status", 200)) < 500 and spec["marker"].lower() in body.lower()
    except HTTPError as exc:
        body = exc.read(256_000).decode("utf-8", errors="replace")
        return exc.code < 500 and spec["marker"].lower() in body.lower()
    except (URLError, TimeoutError, OSError):
        return False


def wait_ready(service: str, process: subprocess.Popen[Any], seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if process.poll() is not None:
            return False
        if healthy(service):
            return True
        time.sleep(0.4)
    return False


def venv_python() -> Path:
    relative = Path("Scripts/python.exe" if is_windows() else "bin/python")
    for directory in (ROOT / "venv", ROOT / ".venv"):
        candidate = directory / relative
        if candidate.exists():
            return candidate

    target = ROOT / "venv"
    print(f"[deps] creating virtual environment: {target}")
    if subprocess.run([sys.executable, "-m", "venv", str(target)], cwd=ROOT).returncode:
        raise LaunchError("Failed to create the Python virtual environment.")
    return target / relative


def missing_modules(python: Path) -> list[str]:
    code = (
        "import importlib.util,json;"
        f"m={list(PYTHON_MODULES)!r};"
        "print(json.dumps([x for x in m if importlib.util.find_spec(x) is None]))"
    )
    result = subprocess.run(
        [str(python), "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    try:
        return json.loads(result.stdout.strip() or "[]") if result.returncode == 0 else list(PYTHON_MODULES)
    except json.JSONDecodeError:
        return list(PYTHON_MODULES)


def npm_path() -> str:
    for name in (("npm.cmd", "npm") if is_windows() else ("npm",)):
        found = shutil.which(name)
        if found:
            return found
    raise LaunchError("npm was not found. Install Node.js and reopen the terminal.")


def npm_command(npm: str, *args: str) -> list[str]:
    base = [npm, *args]
    if not is_windows() or not npm.lower().endswith((".cmd", ".bat")):
        return base
    return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", subprocess.list2cmdline(base)]


def frontend_modules_ready(package: dict[str, Any]) -> bool:
    modules = FRONTEND / "node_modules"
    names: list[str] = []
    for group in ("dependencies", "devDependencies"):
        if isinstance(package.get(group), dict):
            names.extend(package[group])
    return modules.exists() and all(
        (modules.joinpath(*name.split("/")) / "package.json").exists() for name in names
    )


def ensure_dependencies(state: dict[str, Any]) -> tuple[Path, str, bool]:
    requirements = ROOT / "requirements.txt"
    package_file = FRONTEND / "package.json"
    if not requirements.exists() or not package_file.exists():
        raise LaunchError("requirements.txt or frontend/package.json is missing.")

    python = venv_python()
    npm = npm_path()
    deps = state.setdefault("dependencies", {})
    changed = False

    requirements_hash = file_hash(requirements)
    missing = missing_modules(python)
    if deps.get("requirements") != requirements_hash or missing:
        print("[deps] installing Python dependencies ...")
        command = [str(python), "-m", "pip", "install", "-r", str(requirements)]
        if subprocess.run(command, cwd=ROOT).returncode:
            raise LaunchError("Python dependency installation failed.")
        missing = missing_modules(python)
        if missing:
            raise LaunchError("Missing Python modules: " + ", ".join(missing))
        deps["requirements"] = requirements_hash
        changed = True
    else:
        print("[deps] Python dependencies are ready")

    try:
        package = json.loads(package_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LaunchError(f"frontend/package.json is invalid: {exc}") from exc
    package_hash = file_hash(package_file)
    if deps.get("package") != package_hash or not frontend_modules_ready(package):
        print("[deps] installing frontend dependencies ...")
        command = npm_command(npm, "--prefix", str(FRONTEND), "install")
        if subprocess.run(command, cwd=ROOT).returncode:
            raise LaunchError("Frontend dependency installation failed.")
        if not frontend_modules_ready(package):
            raise LaunchError("frontend/node_modules is incomplete after npm install.")
        deps["package"] = package_hash
        changed = True
    else:
        print("[deps] Frontend dependencies are ready")

    save_state(state)
    return python, npm, changed


def ensure_frontend_env() -> None:
    env_file = FRONTEND / ".env"
    desired = "VITE_API_BASE=http://127.0.0.1:8000"
    lines = env_file.read_text(encoding="utf-8", errors="replace").splitlines() if env_file.exists() else []
    output = [line for line in lines if not line.strip().startswith("VITE_API_BASE=")]
    output.append(desired)
    env_file.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")


def process_command(service: str, python: Path, npm: str) -> list[str]:
    if service == "backend":
        return [str(python), "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"]
    if service == "oauth":
        return [
            str(python), "-m", "uvicorn", "backend.oauth.demo_authorization_server:app",
            "--host", "127.0.0.1", "--port", "9000",
        ]
    return npm_command(npm, "--prefix", str(FRONTEND), "run", "dev", "--", "--strictPort")


def recorded_pid(state: dict[str, Any], service: str) -> int:
    try:
        return int(state.get("services", {}).get(service, {}).get("pid", 0))
    except (TypeError, ValueError, AttributeError):
        return 0


def stop_service(service: str, state: dict[str, Any]) -> None:
    spec = SERVICES[service]
    targets = project_pids(service)
    targets.update(pid for pid in listening_pids(spec["port"]) if related(pid, service))
    old = recorded_pid(state, service)
    if old and related(old, service):
        targets.add(old)

    targets.discard(os.getpid())
    targets.discard(os.getppid())
    for pid in sorted(targets):
        kill_tree(pid)

    if targets and not wait_port_free(spec["port"]):
        remaining = {
            pid for pid in listening_pids(spec["port"])
            if related(pid, service)
        }
        for pid in sorted(remaining):
            kill_tree(pid)
        if not wait_port_free(spec["port"], FORCE_STOP_SECONDS):
            raise LaunchError(f"Could not release {service} port {spec['port']}.")


def existing_service(service: str, state: dict[str, Any], restart: bool) -> int:
    spec = SERVICES[service]
    listeners = listening_pids(spec["port"])
    related_listeners = {pid for pid in listeners if related(pid, service)}
    old = recorded_pid(state, service)
    old = old if old and pid_alive(old) and related(old, service) else 0

    if healthy(service) and (related_listeners or old):
        pid = old or min(related_listeners)
        if restart:
            stop_service(service, state)
            return 0
        print(f"[reuse] {spec['label']} PID={pid}")
        return pid

    related_processes = project_pids(service) | related_listeners
    if related_processes or old:
        stop_service(service, state)
        return 0

    if listeners or not port_free(spec["port"]):
        details = "; ".join(f"PID={pid} {command_line(pid)}" for pid in sorted(listeners))
        raise LaunchError(
            f"Port {spec['port']} is occupied by an unrelated process. "
            f"Close it manually. {details}".rstrip()
        )
    return 0


def start_service(
    service: str,
    state: dict[str, Any],
    python: Path,
    npm: str,
    restart: bool,
) -> dict[str, Any]:
    spec = SERVICES[service]
    pid = existing_service(service, state, restart)
    process: subprocess.Popen[Any] | None = None
    reused = bool(pid)

    if not pid:
        command = process_command(service, python, npm)
        print(f"[start] {spec['label']}: {subprocess.list2cmdline(command)}")
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if is_windows() else {"start_new_session": True}
        process = subprocess.Popen(command, cwd=ROOT, **kwargs)
        pid = process.pid
        timeout = 45 if service == "frontend" else 30
        if not wait_ready(service, process, timeout):
            kill_tree(pid)
            raise LaunchError(f"{spec['label']} failed to start at {spec['ready']}.")

    state.setdefault("services", {})[service] = {"pid": pid, "port": spec["port"]}
    save_state(state)
    print(f"[OK] {spec['label']:<8} {'REUSED' if reused else 'STARTED':<7} {spec['ready']}")
    return {"name": service, "pid": pid, "process": process}


def stop_managed(items: list[dict[str, Any]], state: dict[str, Any]) -> None:
    if items:
        print("\n[stop] closing AgentGuard services ...")

    errors: list[str] = []
    for item in reversed(items):
        name = item["name"]
        try:
            stop_service(name, state)
        except LaunchError as exc:
            errors.append(str(exc))
            print(f"[warn] {SERVICES[name]['label']} cleanup: {exc}")
        else:
            print(f"[stop] {SERVICES[name]['label']} closed")
        finally:
            state.get("services", {}).pop(name, None)

    save_state(state)
    if errors:
        print("[warn] cleanup completed with errors; run 'python start_project.py --stop' if needed.")


def service_status() -> None:
    for name in ("frontend", "backend", "oauth"):
        status = "READY" if healthy(name) else "OFFLINE"
        print(f"  [{status:<7}] {SERVICES[name]['label']:<8} {SERVICES[name]['ready']}")


def read_lock_pid() -> int:
    try:
        return int(json.loads(LOCK_FILE.read_text(encoding="utf-8")).get("pid", 0))
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def acquire_lock(restart: bool) -> int | None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, json.dumps({"pid": os.getpid(), "root": str(ROOT)}).encode())
            return fd
        except FileExistsError:
            pid = read_lock_pid()
            if pid and pid_alive(pid):
                if not restart:
                    print(f"[running] AgentGuard launcher already exists (PID={pid}).")
                    service_status()
                    print("[hint] Use --restart for a fresh instance or --stop to close it.")
                    return None
                print(f"[restart] stopping launcher PID={pid} ...")
                kill_tree(pid)
                time.sleep(1)
            try:
                LOCK_FILE.unlink()
            except FileNotFoundError:
                pass


def release_lock(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
    if read_lock_pid() == os.getpid():
        try:
            LOCK_FILE.unlink()
        except FileNotFoundError:
            pass


def print_urls(with_oauth: bool) -> None:
    print("\n" + "=" * 68)
    print("AgentGuard is ready")
    print("=" * 68)
    print("Frontend:           http://127.0.0.1:5173")
    print("Backend API:        http://127.0.0.1:8000")
    print("API documentation: http://127.0.0.1:8000/docs")
    print("MCP endpoint:       http://127.0.0.1:8000/mcp")
    print("OAuth demo server:  " + ("http://127.0.0.1:9000" if with_oauth else "skipped"))
    print("\nPress Ctrl+C to stop all managed services.")
    print("=" * 68 + "\n")


def stop_everything(state: dict[str, Any]) -> None:
    errors: list[str] = []
    for name in ("oauth", "frontend", "backend"):
        try:
            stop_service(name, state)
        except LaunchError as exc:
            errors.append(str(exc))
            print(f"[warn] {SERVICES[name]['label']} cleanup: {exc}")
        finally:
            state.get("services", {}).pop(name, None)
    state["services"] = {}
    save_state(state)
    if errors:
        raise LaunchError("; ".join(errors))


def install_signal_handlers() -> None:
    stopping = False

    def stop_handler(signum: int, frame: Any) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        raise KeyboardInterrupt

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        value = getattr(signal, name, None)
        if value is not None:
            try:
                signal.signal(value, stop_handler)
            except (OSError, ValueError):
                pass


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Install dependencies and run one managed AgentGuard instance."
    )
    oauth = result.add_mutually_exclusive_group()
    oauth.add_argument(
        "--with-oauth",
        dest="with_oauth",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    oauth.add_argument(
        "--without-oauth",
        "--no-oauth",
        dest="with_oauth",
        action="store_false",
        help="Skip the OAuth demo server and start only Backend and Frontend.",
    )
    result.set_defaults(with_oauth=True)
    result.add_argument("--restart", action="store_true", help="Replace an existing AgentGuard instance.")
    result.add_argument("--stop", action="store_true", help="Stop AgentGuard and exit.")
    result.add_argument("--clean", action="store_true", help=argparse.SUPPRESS)
    return result


def main() -> int:
    args = parser().parse_args()
    restart = args.restart or args.clean
    state = load_state()

    if args.stop:
        launcher = read_lock_pid()
        if launcher and pid_alive(launcher):
            kill_tree(launcher)
            time.sleep(1)
        try:
            LOCK_FILE.unlink()
        except FileNotFoundError:
            pass
        try:
            stop_everything(state)
        except LaunchError as exc:
            print(f"[ERROR] {exc}")
            return 1
        print("[stop] AgentGuard is not running")
        return 0

    lock_fd = acquire_lock(restart)
    if lock_fd is None:
        return 0

    install_signal_handlers()
    managed: list[dict[str, Any]] = []
    try:
        print("=" * 68)
        print("AgentGuard managed launcher")
        print("=" * 68)

        state["launcher_pid"] = os.getpid()
        save_state(state)
        python, npm, dependencies_changed = ensure_dependencies(state)
        ensure_frontend_env()
        restart_services = restart or dependencies_changed

        if not args.with_oauth:
            stale_oauth = project_pids("oauth")
            for pid in stale_oauth:
                kill_tree(pid)

        managed.append(start_service("backend", state, python, npm, restart_services))
        managed.append(start_service("frontend", state, python, npm, restart_services))
        if args.with_oauth:
            managed.append(start_service("oauth", state, python, npm, restart_services))

        print_urls(args.with_oauth)
        while True:
            for item in managed:
                process = item["process"]
                if process is not None and process.poll() is not None:
                    raise LaunchError(
                        f"{SERVICES[item['name']]['label']} exited with code {process.returncode}."
                    )
                if not healthy(item["name"]):
                    raise LaunchError(f"{SERVICES[item['name']]['label']} is no longer healthy.")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[stop] Ctrl+C received.")
        return 0
    except LaunchError as exc:
        print(f"\n[ERROR] {exc}")
        return 1
    finally:
        try:
            stop_managed(managed, state)
            state.pop("launcher_pid", None)
            save_state(state)
        finally:
            release_lock(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
