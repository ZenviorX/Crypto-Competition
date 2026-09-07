import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_WORKSPACE = PROJECT_ROOT / "runtime_workspace"


@dataclass
class ToolExecutionResult:
    """
    工具执行结果。
    该对象用于记录真实工具执行后的状态、输出、错误信息和耗时。
    """
    tool: str
    status: str
    output: Any = None
    error: Optional[str] = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SafeToolExecutor:
    """
    受控工具执行器。

    该执行器只在 runtime_workspace 目录内执行文件读写，
    并对 shell.run 采用白名单命令策略，避免真实高危命令被直接执行。
    """

    def __init__(self, workspace: Optional[Path] = None) -> None:
        self.workspace = workspace or RUNTIME_WORKSPACE
        self.workspace.mkdir(parents=True, exist_ok=True)

        self.allowed_shell_prefixes = [
            "echo",
            "dir",
            "ls",
            "pwd",
            "whoami",
            "python --version",
            "python -V",
        ]

    def execute(self, tool: str, params: Dict[str, Any]) -> ToolExecutionResult:
        start = time.perf_counter()

        try:
            if tool == "file.read":
                result = self._file_read(params)
            elif tool == "file.write":
                result = self._file_write(params)
            elif tool == "shell.run":
                result = self._shell_run(params)
            elif tool == "email.send":
                result = self._email_send_mock(params)
            elif tool == "db.query":
                result = self._db_query_mock(params)
            else:
                result = ToolExecutionResult(
                    tool=tool,
                    status="error",
                    error=f"Unsupported tool: {tool}",
                )

        except Exception as exc:
            result = ToolExecutionResult(
                tool=tool,
                status="error",
                error=str(exc),
            )

        result.elapsed_ms = (time.perf_counter() - start) * 1000
        return result

    def _resolve_workspace_path(self, raw_path: str) -> Path:
        """
        将用户传入路径限制在 runtime_workspace 内。
        即使传入 ../ 也不能逃逸出工作区。
        """
        if not raw_path:
            raise ValueError("path is required")

        candidate = (self.workspace / raw_path).resolve()
        workspace_root = self.workspace.resolve()

        if workspace_root not in candidate.parents and candidate != workspace_root:
            raise PermissionError(f"path escapes runtime workspace: {raw_path}")

        return candidate


    def _file_read(self, params: Dict[str, Any]) -> ToolExecutionResult:
        path = self._resolve_workspace_path(str(params.get("path", "")))

        if not path.exists():
            return ToolExecutionResult(
                tool="file.read",
                status="error",
                error=f"file not found: {path.name}",
            )

        if not path.is_file():
            return ToolExecutionResult(
                tool="file.read",
                status="error",
                error=f"path is not a file: {path.name}",
            )

        content = path.read_text(encoding="utf-8", errors="replace")

        return ToolExecutionResult(
            tool="file.read",
            status="success",
            output={
                "path": str(path.relative_to(self.workspace)),
                "content": content,
            },
        )

    def _file_write(self, params: Dict[str, Any]) -> ToolExecutionResult:
        path = self._resolve_workspace_path(str(params.get("path", "")))
        content = str(params.get("content", ""))

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        return ToolExecutionResult(
            tool="file.write",
            status="success",
            output={
                "path": str(path.relative_to(self.workspace)),
                "bytes_written": len(content.encode("utf-8")),
            },
        )

    def _shell_run(self, params: Dict[str, Any]) -> ToolExecutionResult:
        command = str(params.get("command", "")).strip()

        if not command:
            return ToolExecutionResult(
                tool="shell.run",
                status="error",
                error="command is required",
            )

        if not self._is_allowed_shell_command(command):
            return ToolExecutionResult(
                tool="shell.run",
                status="blocked_by_executor",
                error=f"command is not allowed by SafeToolExecutor: {command}",
            )

        completed = subprocess.run(
            command,
            shell=True,
            cwd=str(self.workspace),
            capture_output=True,
            text=True,
            timeout=5,
        )

        return ToolExecutionResult(
            tool="shell.run",
            status="success" if completed.returncode == 0 else "error",
            output={
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            },
        )

    def _is_allowed_shell_command(self, command: str) -> bool:
        lowered = command.lower().strip()

        for prefix in self.allowed_shell_prefixes:
            if lowered == prefix.lower() or lowered.startswith(prefix.lower() + " "):
                return True

        return False

    def _email_send_mock(self, params: Dict[str, Any]) -> ToolExecutionResult:
        """
        邮件工具采用模拟执行，不真实发送邮件。
        """
        to = params.get("to")
        subject = params.get("subject", "")
        content = params.get("content", "")

        if not to:
            return ToolExecutionResult(
                tool="email.send",
                status="error",
                error="email recipient is required",
            )

        mock_record = {
            "to": to,
            "subject": subject,
            "content_preview": str(content)[:120],
            "mocked": True,
        }

        return ToolExecutionResult(
            tool="email.send",
            status="success",
            output=mock_record,
        )

    def _db_query_mock(self, params: Dict[str, Any]) -> ToolExecutionResult:
        """
        数据库工具采用模拟执行，不连接真实数据库。
        """
        sql = str(params.get("sql", "")).strip()

        if not sql:
            return ToolExecutionResult(
                tool="db.query",
                status="error",
                error="sql is required",
            )

        return ToolExecutionResult(
            tool="db.query",
            status="success",
            output={
                "sql": sql,
                "rows": [],
                "mocked": True,
            },
        )


def execute_tool(tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
    executor = SafeToolExecutor()
    return executor.execute(tool, params).to_dict()
