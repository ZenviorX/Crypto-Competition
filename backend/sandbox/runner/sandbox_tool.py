from __future__ import annotations

import json
import os
import re
import shlex
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple


WORKSPACE = Path("/workspace")
DATABASE_PATH = (
    WORKSPACE
    / "agent_runtime.db"
)

MAX_READ_BYTES = 512 * 1024
MAX_DB_ROWS = 200

SAFE_SHELL_COMMANDS = {
    "echo",
    "pwd",
    "ls",
    "cat",
}


class SandboxDenied(Exception):
    pass


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _normalize_rel_path(raw: Any) -> str:
    path = str(raw or "").strip().replace("\\", "/")

    while path.startswith("./"):
        path = path[2:]

    if not path:
        raise SandboxDenied("File path is empty.")

    first = path.split("/", 1)[0]
    if path.startswith("/") or ":" in first:
        raise SandboxDenied("Absolute path or drive-letter path is denied inside Docker sandbox.")

    if "../" in path or path == ".." or path.startswith("../"):
        raise SandboxDenied("Path traversal is denied inside Docker sandbox.")

    return path


def _resolve_workspace_path(raw: Any) -> Tuple[Path, str]:
    rel = _normalize_rel_path(raw)
    target = (WORKSPACE / rel).resolve()

    try:
        target.relative_to(WORKSPACE.resolve())
    except ValueError as exc:
        raise SandboxDenied("Path escapes /workspace.") from exc

    return target, rel


def _get_path(params: Dict[str, Any]) -> Any:
    return params.get("path") or params.get("file_path") or params.get("resource") or params.get("filename")


def _read_file(params: Dict[str, Any]) -> Dict[str, Any]:
    path, rel = _resolve_workspace_path(_get_path(params))

    if not path.exists():
        raise SandboxDenied(f"File does not exist in mounted workspace: {rel}")

    if not path.is_file():
        raise SandboxDenied(f"Target is not a regular file: {rel}")

    size = path.stat().st_size
    if size > MAX_READ_BYTES:
        raise SandboxDenied("File is too large for sandbox read.")

    content = path.read_text(encoding="utf-8", errors="replace")
    return {
        "success": True,
        "result": content,
        "meta": {
            "path": rel,
            "bytes": len(content.encode("utf-8")),
            "workspace": "/workspace",
        },
    }


def _write_file(params: Dict[str, Any]) -> Dict[str, Any]:
    path, rel = _resolve_workspace_path(_get_path(params))
    content = str(params.get("content") or params.get("body") or "")

    if not rel.startswith("outbox/"):
        raise SandboxDenied("Docker sandbox only allows file.write under outbox/.")

    if path.exists() and path.is_dir():
        raise SandboxDenied(f"Target is a directory: {rel}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

    return {
        "success": True,
        "result": {
            "message": "File written inside Docker sandbox outbox mount.",
            "path": rel,
            "bytes": len(content.encode("utf-8")),
        },
    }


def _delete_file(
    params: Dict[str, Any],
) -> Dict[str, Any]:
    path, rel = _resolve_workspace_path(
        _get_path(params)
    )

    # Docker 中只有 outbox 是可写挂载。
    if not rel.startswith("outbox/"):
        raise SandboxDenied(
            "Docker sandbox only allows "
            "file.delete under outbox/."
        )

    if not path.exists():
        raise SandboxDenied(
            f"File does not exist in mounted workspace: {rel}"
        )

    if not path.is_file():
        raise SandboxDenied(
            f"Target is not a regular file: {rel}"
        )

    path.unlink()

    return {
        "success": True,
        "result": {
            "message": (
                "File deleted inside Docker "
                "sandbox outbox mount."
            ),
            "path": rel,
        },
    }


def _validate_readonly_sql(
    raw_sql: Any,
) -> str:
    sql = str(raw_sql or "").strip()

    if not sql:
        raise SandboxDenied(
            "SQL query is empty."
        )

    normalized = sql.rstrip(";").strip()

    if ";" in normalized:
        raise SandboxDenied(
            "Multiple SQL statements are denied."
        )

    lowered = re.sub(
        r"\s+",
        " ",
        normalized.lower(),
    )

    if not (
        lowered.startswith("select ")
        or lowered == "select"
        or lowered.startswith("with ")
    ):
        raise SandboxDenied(
            "Docker sandbox database only permits "
            "SELECT or read-only WITH queries."
        )

    forbidden_pattern = (
        r"\b("
        r"insert|update|delete|drop|alter|"
        r"create|replace|attach|detach|"
        r"pragma|vacuum|reindex|analyze"
        r")\b"
    )

    if re.search(
        forbidden_pattern,
        lowered,
    ):
        raise SandboxDenied(
            "Database modification or administrative "
            "SQL is denied."
        )

    if re.search(
        r"load_extension\s*\(",
        lowered,
    ):
        raise SandboxDenied(
            "SQLite extension loading is denied."
        )

    return normalized




def _execute_public_database_query(
    database_path: Path,
    sql: str,
) -> Dict[str, Any]:
    """
    从原始只读数据库提取 public 数据，
    再在隔离的内存数据库中执行 Agent SQL。
    """
    from urllib.parse import quote

    source_connection = None
    public_connection = None

    try:
        resolved_path = (
            database_path.resolve()
        )

        if not resolved_path.exists():
            raise SandboxDenied(
                "Runtime database does not exist: "
                + str(resolved_path)
            )

        # Windows:
        # file:D:/project/.../agent_runtime.db?mode=ro
        #
        # Linux:
        # file:/home/.../agent_runtime.db?mode=ro
        encoded_path = quote(
            resolved_path.as_posix(),
            safe="/:",
        )

        source_uri = (
            "file:"
            + encoded_path
            + "?mode=ro"
        )

        source_connection = (
            sqlite3.connect(
                source_uri,
                uri=True,
                timeout=5,
            )
        )

        source_connection.execute(
            "PRAGMA query_only=ON"
        )

        table_exists = (
            source_connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE
                    type = 'table'
                    AND name = 'notices'
                """
            ).fetchone()
        )

        if table_exists is None:
            raise SandboxDenied(
                "Runtime database does not "
                "contain the notices table."
            )

        table_info = (
            source_connection.execute(
                "PRAGMA table_info(notices)"
            ).fetchall()
        )

        available_columns = {
            str(row[1]).lower()
            for row in table_info
        }

        required_columns = {
            "id",
            "title",
            "content",
            "visibility",
        }

        missing_columns = (
            required_columns
            - available_columns
        )

        if missing_columns:
            raise SandboxDenied(
                "The notices table is missing "
                "required columns: "
                + ", ".join(
                    sorted(missing_columns)
                )
            )

        public_source_rows = (
            source_connection.execute(
                """
                SELECT
                    id,
                    title,
                    content,
                    visibility
                FROM notices
                WHERE
                    lower(
                        trim(visibility)
                    ) = 'public'
                ORDER BY id
                """
            ).fetchall()
        )

        public_connection = (
            sqlite3.connect(":memory:")
        )

        public_connection.row_factory = (
            sqlite3.Row
        )

        public_connection.execute(
            """
            CREATE TABLE notices (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                visibility TEXT NOT NULL
                    CHECK (
                        visibility = 'public'
                    )
            )
            """
        )

        public_connection.executemany(
            """
            INSERT INTO notices (
                id,
                title,
                content,
                visibility
            )
            VALUES (?, ?, ?, ?)
            """,
            public_source_rows,
        )

        public_connection.commit()

        public_connection.execute(
            "PRAGMA query_only=ON"
        )

        executed_vm_steps = [0]

        def progress_handler():
            executed_vm_steps[0] += 1000

            if (
                executed_vm_steps[0]
                > 200000
            ):
                return 1

            return 0

        public_connection.set_progress_handler(
            progress_handler,
            1000,
        )

        cursor = public_connection.execute(
            sql
        )

        columns = [
            str(item[0])
            for item in (
                cursor.description
                or []
            )
        ]

        fetched_rows = cursor.fetchmany(
            MAX_DB_ROWS + 1
        )

        truncated = (
            len(fetched_rows)
            > MAX_DB_ROWS
        )

        visible_rows = fetched_rows[
            :MAX_DB_ROWS
        ]

        return {
            "sql": sql,
            "columns": columns,
            "rows": [
                dict(row)
                for row in visible_rows
            ],
            "row_count": len(
                visible_rows
            ),
            "truncated": truncated,
            "data_scope": "public",
            "source_public_rows": len(
                public_source_rows
            ),
            "policy": {
                "source_database": (
                    "read_only"
                ),
                "query_database": (
                    "sanitized_in_memory"
                ),
                "allowed_tables": [
                    "notices"
                ],
                "allowed_visibility": [
                    "public"
                ],
                "max_rows": (
                    MAX_DB_ROWS
                ),
                "max_vm_steps": 200000,
            },
        }

    except sqlite3.OperationalError as exc:
        if (
            "interrupted"
            in str(exc).lower()
        ):
            raise SandboxDenied(
                "Database query exceeded "
                "the execution budget."
            ) from exc

        raise SandboxDenied(
            "Public database query failed: "
            + str(exc)
        ) from exc

    except sqlite3.DatabaseError as exc:
        raise SandboxDenied(
            "Public database projection "
            "failed: "
            + str(exc)
        ) from exc

    finally:
        if public_connection is not None:
            public_connection.close()

        if source_connection is not None:
            source_connection.close()




def _query_database(
    params: Dict[str, Any],
) -> Dict[str, Any]:
    sql = _validate_readonly_sql(
        str(
            params.get("sql")
            or ""
        )
    )

    database_path = (
        DATABASE_PATH.resolve()
    )

    if not database_path.exists():
        raise SandboxDenied(
            "Runtime database does not exist."
        )

    projected_result = (
        _execute_public_database_query(
            database_path,
            sql,
        )
    )

    # Docker Runner 与 Native Runner
    # 使用完全相同的工具返回协议。
    return {
        "success": True,
        "result": projected_result,
    }



def _send_email(params: Dict[str, Any]) -> Dict[str, Any]:
    to = str(params.get("to") or "").strip()
    if not to:
        raise SandboxDenied("Email recipient is empty.")

    subject = str(params.get("subject") or "AgentGuard Docker Sandbox Mail")
    content = str(params.get("content") or params.get("body") or params.get("message") or "")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    outbox = WORKSPACE / "outbox"
    outbox.mkdir(parents=True, exist_ok=True)
    mail_path = outbox / f"docker_email_{timestamp}.json"

    record = {
        "to": to,
        "subject": subject,
        "content": content,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sandbox_type": "docker",
        "real_external_send": False,
    }
    _write_json(mail_path, record)

    return {
        "success": True,
        "result": {
            "message": "Email was written to Docker sandbox outbox. No real external email was sent.",
            "outbox_file": str(mail_path.relative_to(WORKSPACE)),
            "to": to,
            "subject": subject,
        },
    }


def _run_shell(params: Dict[str, Any]) -> Dict[str, Any]:
    command = str(params.get("command") or params.get("cmd") or "").strip()
    if not command:
        raise SandboxDenied("Shell command is empty.")

    parts = shlex.split(command)
    if not parts:
        raise SandboxDenied("Shell command is empty.")

    command_name = parts[0].lower()
    args = parts[1:]

    if command_name not in SAFE_SHELL_COMMANDS:
        raise SandboxDenied(f"Only safe demo shell commands are allowed: {sorted(SAFE_SHELL_COMMANDS)}")

    if command_name == "echo":
        stdout = " ".join(args)
    elif command_name == "pwd":
        stdout = "/workspace"
    elif command_name == "ls":
        target_raw = args[0] if args else "."
        target, _ = _resolve_workspace_path(target_raw)
        if not target.exists():
            raise SandboxDenied(f"Path does not exist: {target_raw}")
        if target.is_file():
            stdout = target.name
        else:
            stdout = "\n".join(sorted(item.name for item in target.iterdir()))
    elif command_name == "cat":
        if not args:
            raise SandboxDenied("cat requires a file path.")
        return _read_file({"path": args[0]})
    else:
        raise SandboxDenied(f"Command is not implemented: {command_name}")

    return {
        "success": True,
        "result": {
            "command": command,
            "stdout": stdout,
            "stderr": "",
            "cwd": "/workspace",
            "sandbox_interpreter": True,
        },
    }


def execute_tool(tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
    normalized = str(tool or "").strip().lower()

    if normalized == "file.read":
        return _read_file(params)
    if normalized == "file.write":
        return _write_file(params)
    if normalized == "file.delete":
        return _delete_file(params)
    if normalized == "email.send":
        return _send_email(params)
    if normalized == "shell.run":
        return _run_shell(params)
    if normalized == "db.query":
        return _query_database(params)

    raise SandboxDenied(f"Tool is not implemented in Docker sandbox runner: {tool}")


def main() -> int:
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/sandbox/input.json")
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/sandbox/result.json")

    started_at = datetime.now(timezone.utc).isoformat()

    try:
        request = _read_json(input_path)
        result = execute_tool(
            tool=str(request.get("tool") or ""),
            params=dict(request.get("params") or {}),
        )
        payload = {
            "success": bool(result.get("success")),
            "tool_result": _jsonable(result),
            "error": None,
        }
    except Exception as exc:
        payload = {
            "success": False,
            "tool_result": {
                "success": False,
                "result": str(exc),
            },
            "error": str(exc),
        }

    payload["runner"] = {
        "sandbox_type": "docker",
        "workspace": "/workspace",
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }

    _write_json(output_path, payload)
    return 0 if payload.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
