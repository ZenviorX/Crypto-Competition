from __future__ import annotations
import hashlib
import time

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.task_session.session_models import TaskSession
from backend.audit.trusted_audit_store import append_trusted_audit_event


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "data" / "trusted_task_sessions.db"


class TaskStoreError(RuntimeError):
    """可信任务会话存储基础异常。"""


class TaskNotFoundError(TaskStoreError):
    """任务句柄不存在。"""


class TaskVersionConflictError(TaskStoreError):
    """任务状态发生并发冲突。"""


class TaskBindingError(TaskStoreError):
    """任务句柄与用户或原始任务不匹配。"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_to_dict(session: TaskSession) -> dict:
    if hasattr(session, "model_dump"):
        return session.model_dump(mode="json")

    return session.dict()


def session_from_dict(data: dict) -> TaskSession:
    if hasattr(TaskSession, "model_validate"):
        return TaskSession.model_validate(data)

    return TaskSession.parse_obj(data)


def create_task_handle() -> str:
    """
    生成由服务端控制的高强度随机任务句柄。

    Agent 不能自行伪造或根据用户名推测该句柄。
    """
    return f"agt_{secrets.token_urlsafe(32)}"


def connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(DATABASE_PATH),
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA busy_timeout=10000")

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_task_sessions (
            task_handle TEXT PRIMARY KEY,
            session_id TEXT NOT NULL UNIQUE,
            user TEXT NOT NULL,
            original_input TEXT NOT NULL,
            session_json TEXT NOT NULL,
            status TEXT NOT NULL,
            final_decision TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    connection.execute(
        "PRAGMA foreign_keys=ON"
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_data_references (
            data_ref TEXT PRIMARY KEY,
            task_handle TEXT NOT NULL,
            user TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            labels_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(task_handle, step_index),
            FOREIGN KEY(task_handle)
                REFERENCES trusted_task_sessions(task_handle)
                ON DELETE CASCADE
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_data_refs_task
        ON trusted_data_references(task_handle)
        """
    )

    connection.commit()
    return connection


def _append_task_created_audit_or_rollback(
    *,
    task_handle: str,
    session,
    version: int,
) -> None:
    """
    A trusted task must not exist without a matching
    task.created audit record.

    If trusted audit writing fails, remove the newly
    created task session as a compensating rollback.
    """
    try:
        append_trusted_audit_event(
            task_handle=task_handle,
            user=str(session.user),
            event_type="task.created",
            payload={
                "version": int(version),
                "session_id": str(
                    session.session_id
                ),
                "original_task": str(
                    session.original_input
                ),
                "agent_type": str(
                    session.agent_type
                ),
            },
        )

    except Exception as exc:
        rollback_connection = connect()

        try:
            rollback_connection.execute(
                """
                DELETE FROM trusted_task_sessions
                WHERE task_handle = ?
                """,
                (task_handle,),
            )
            rollback_connection.commit()

        finally:
            rollback_connection.close()

        raise TaskStoreError(
            "Trusted task creation audit failed; "
            "the new task session was rolled back"
        ) from exc

def create_session(session: TaskSession) -> tuple[str, int]:
    """
    首次保存任务会话。

    task_handle 只能由服务端生成。
    """
    task_handle = create_task_handle()
    timestamp = now_iso()

    # ???????????????????
    session.task_handle = task_handle
    session.version = 1

    session_json = json.dumps(
        session_to_dict(session),
        ensure_ascii=False,
        sort_keys=True,
    )

    connection = connect()

    try:
        connection.execute(
            """
            INSERT INTO trusted_task_sessions (
                task_handle,
                session_id,
                user,
                original_input,
                session_json,
                status,
                final_decision,
                version,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                task_handle,
                session.session_id,
                session.user,
                session.original_input,
                session_json,
                session.status,
                session.final_decision,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    created_version = int(
        1
    )

    _append_task_created_audit_or_rollback(
        task_handle=task_handle,
        session=session,
        version=created_version,
    )

    return task_handle, 1


def load_session(
    task_handle: str,
    expected_user: Optional[str] = None,
) -> tuple[TaskSession, int]:
    """
    根据服务端任务句柄恢复任务状态。
    """
    connection = connect()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM trusted_task_sessions
            WHERE task_handle = ?
            """,
            (task_handle,),
        ).fetchone()

    finally:
        connection.close()

    if row is None:
        raise TaskNotFoundError(
            f"任务句柄不存在：{task_handle}"
        )

    if (
        expected_user is not None
        and row["user"] != expected_user
    ):
        raise TaskBindingError(
            "该任务句柄不属于当前用户"
        )

    session_data = json.loads(row["session_json"])
    session = session_from_dict(session_data)

    version = int(row["version"])

    # ????????????????????????
    session.task_handle = task_handle
    session.version = version

    return session, version


def save_session(
    task_handle: str,
    session: TaskSession,
    expected_version: int,
) -> int:
    """
    保存任务最新状态。

    使用 version 乐观锁，防止多个请求同时覆盖状态。
    同时禁止修改任务所属用户和原始任务。
    """
    connection = connect()

    try:
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            """
            SELECT
                session_id,
                user,
                original_input,
                version
            FROM trusted_task_sessions
            WHERE task_handle = ?
            """,
            (task_handle,),
        ).fetchone()

        if row is None:
            raise TaskNotFoundError(
                f"任务句柄不存在：{task_handle}"
            )

        if row["session_id"] != session.session_id:
            raise TaskBindingError(
                "不能将任务句柄绑定到其他 session_id"
            )

        if row["user"] != session.user:
            raise TaskBindingError(
                "不能修改任务所属用户"
            )

        if row["original_input"] != session.original_input:
            raise TaskBindingError(
                "任务创建后不能修改 original_input"
            )

        current_version = int(row["version"])

        if current_version != expected_version:
            raise TaskVersionConflictError(
                f"版本冲突：当前版本为 {current_version}，"
                f"提交版本为 {expected_version}"
            )

        new_version = current_version + 1

        # ??????????????????
        session.task_handle = task_handle
        session.version = new_version

        session_json = json.dumps(
            session_to_dict(session),
            ensure_ascii=False,
            sort_keys=True,
        )

        cursor = connection.execute(
            """
            UPDATE trusted_task_sessions
            SET
                session_json = ?,
                status = ?,
                final_decision = ?,
                version = ?,
                updated_at = ?
            WHERE task_handle = ?
              AND version = ?
            """,
            (
                session_json,
                session.status,
                session.final_decision,
                new_version,
                now_iso(),
                task_handle,
                expected_version,
            ),
        )

        if cursor.rowcount != 1:
            raise TaskVersionConflictError(
                "任务状态已被其他请求修改"
            )

        connection.commit()
        return new_version

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

class DataReferenceNotFoundError(TaskStoreError):
    """????????"""


class DataReferenceBindingError(TaskStoreError):
    """??????????????"""


def create_data_reference(
    task_handle: str,
    user: str,
    step_index: int,
    labels: list[str],
) -> str:
    """
    ??????????????????????

    ????????????????????
    ??????????????
    """
    if step_index <= 0:
        raise ValueError(
            "step_index must be greater than zero"
        )

    load_session(
        task_handle=task_handle,
        expected_user=user,
    )

    normalized_labels: list[str] = []

    for label in labels:
        value = str(label).strip()

        if (
            value
            and value not in normalized_labels
        ):
            normalized_labels.append(value)

    labels_json = json.dumps(
        normalized_labels,
        ensure_ascii=False,
        sort_keys=True,
    )

    connection = connect()

    try:
        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            """
            SELECT data_ref
            FROM trusted_data_references
            WHERE task_handle = ?
              AND step_index = ?
            """,
            (
                task_handle,
                step_index,
            ),
        ).fetchone()

        if existing is not None:
            data_ref = str(
                existing["data_ref"]
            )

            connection.execute(
                """
                UPDATE trusted_data_references
                SET
                    labels_json = ?,
                    user = ?
                WHERE data_ref = ?
                """,
                (
                    labels_json,
                    user,
                    data_ref,
                ),
            )

            connection.commit()
            return data_ref

        data_ref = (
            "agr_"
            + secrets.token_urlsafe(24)
        )

        connection.execute(
            """
            INSERT INTO trusted_data_references (
                data_ref,
                task_handle,
                user,
                step_index,
                labels_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                data_ref,
                task_handle,
                user,
                step_index,
                labels_json,
                now_iso(),
            ),
        )

        connection.commit()
        return data_ref

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def resolve_data_references(
    task_handle: str,
    user: str,
    data_refs: list[str],
) -> tuple[list[int], list[str]]:
    """
    ???????????????????
    """
    normalized_refs: list[str] = []

    for data_ref in data_refs:
        value = str(data_ref).strip()

        if (
            value
            and value not in normalized_refs
        ):
            normalized_refs.append(value)

    if not normalized_refs:
        return [], []

    connection = connect()

    step_indexes: list[int] = []
    labels: list[str] = []

    try:
        for data_ref in normalized_refs:
            row = connection.execute(
                """
                SELECT
                    task_handle,
                    user,
                    step_index,
                    labels_json
                FROM trusted_data_references
                WHERE data_ref = ?
                """,
                (data_ref,),
            ).fetchone()

            if row is None:
                raise DataReferenceNotFoundError(
                    f"Unknown data reference: {data_ref}"
                )

            if row["task_handle"] != task_handle:
                raise DataReferenceBindingError(
                    "Data reference belongs to another task"
                )

            if row["user"] != user:
                raise DataReferenceBindingError(
                    "Data reference belongs to another user"
                )

            step_index = int(
                row["step_index"]
            )

            if step_index not in step_indexes:
                step_indexes.append(step_index)

            try:
                stored_labels = json.loads(
                    row["labels_json"]
                )
            except json.JSONDecodeError as exc:
                raise TaskStoreError(
                    "Stored data reference labels are corrupted"
                ) from exc

            if not isinstance(stored_labels, list):
                raise TaskStoreError(
                    "Stored data reference labels are invalid"
                )

            for label in stored_labels:
                value = str(label).strip()

                if value and value not in labels:
                    labels.append(value)

    finally:
        connection.close()

    return step_indexes, labels

class ApprovalTicketNotFoundError(TaskStoreError):
    """Approval ticket does not exist."""


class ApprovalTicketBindingError(TaskStoreError):
    """Approval ticket belongs to another task or user."""


class ApprovalTicketStateError(TaskStoreError):
    """Approval ticket is in an invalid state."""


def _ensure_approval_schema(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_approval_tickets (
            approval_ticket TEXT PRIMARY KEY,
            task_handle TEXT NOT NULL,
            user TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            tool TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            params_json TEXT NOT NULL,
            data_refs_json TEXT NOT NULL,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            consumed_at TEXT,
            UNIQUE(task_handle, step_index),
            FOREIGN KEY(task_handle)
                REFERENCES trusted_task_sessions(task_handle)
                ON DELETE CASCADE
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_approval_task
        ON trusted_approval_tickets(task_handle)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_approval_status
        ON trusted_approval_tickets(status)
        """
    )


def _normalize_data_refs(
    data_refs: list[str],
) -> list[str]:
    normalized: list[str] = []

    for item in data_refs:
        value = str(item).strip()

        if value and value not in normalized:
            normalized.append(value)

    return normalized


def _approval_request_hash(
    *,
    tool: str,
    params: dict,
    data_refs: list[str],
) -> str:
    import hashlib

    payload = {
        "tool": str(tool),
        "params": dict(params or {}),
        "data_refs": _normalize_data_refs(
            data_refs
        ),
    }

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        encoded
    ).hexdigest()


def create_approval_ticket(
    *,
    task_handle: str,
    user: str,
    step_index: int,
    tool: str,
    params: dict,
    data_refs: list[str],
) -> tuple[str, str]:
    """
    Create an opaque approval ticket for one persisted
    confirmation-required runtime step.

    Repeating the exact request for the same step returns
    the existing ticket instead of creating another one.
    """
    if step_index <= 0:
        raise ValueError(
            "step_index must be greater than zero"
        )

    task_handle = str(
        task_handle
    ).strip()

    user = str(user).strip()
    tool = str(tool).strip()

    if not task_handle:
        raise ValueError(
            "task_handle is required"
        )

    if not user:
        raise ValueError(
            "user is required"
        )

    if not tool:
        raise ValueError(
            "tool is required"
        )

    load_session(
        task_handle=task_handle,
        expected_user=user,
    )

    normalized_refs = _normalize_data_refs(
        data_refs
    )

    params_json = json.dumps(
        dict(params or {}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    data_refs_json = json.dumps(
        normalized_refs,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    request_hash = _approval_request_hash(
        tool=tool,
        params=dict(params or {}),
        data_refs=normalized_refs,
    )

    connection = connect()

    try:
        _ensure_approval_schema(connection)
        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            """
            SELECT
                approval_ticket,
                request_hash,
                status
            FROM trusted_approval_tickets
            WHERE task_handle = ?
              AND step_index = ?
            """,
            (
                task_handle,
                step_index,
            ),
        ).fetchone()

        if existing is not None:
            if (
                str(existing["request_hash"])
                != request_hash
            ):
                raise ApprovalTicketStateError(
                    "The persisted step is already bound "
                    "to a different approval request"
                )

            connection.commit()

            return (
                str(
                    existing[
                        "approval_ticket"
                    ]
                ),
                str(existing["status"]),
            )

        approval_ticket = (
            "aga_"
            + secrets.token_urlsafe(32)
        )

        connection.execute(
            """
            INSERT INTO trusted_approval_tickets (
                approval_ticket,
                task_handle,
                user,
                step_index,
                tool,
                request_hash,
                params_json,
                data_refs_json,
                status,
                requested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval_ticket,
                task_handle,
                user,
                step_index,
                tool,
                request_hash,
                params_json,
                data_refs_json,
                "pending",
                now_iso(),
            ),
        )

        connection.commit()

        return approval_ticket, "pending"

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_approval_ticket(
    *,
    approval_ticket: str,
    expected_task_handle: str | None = None,
    expected_user: str | None = None,
) -> dict:
    approval_ticket = str(
        approval_ticket
    ).strip()

    connection = connect()

    try:
        _ensure_approval_schema(connection)

        row = connection.execute(
            """
            SELECT
                approval_ticket,
                task_handle,
                user,
                step_index,
                tool,
                request_hash,
                params_json,
                data_refs_json,
                status,
                requested_at,
                decided_at,
                decided_by,
                consumed_at
            FROM trusted_approval_tickets
            WHERE approval_ticket = ?
            """,
            (approval_ticket,),
        ).fetchone()

        if row is None:
            raise ApprovalTicketNotFoundError(
                "Approval ticket was not found"
            )

        if (
            expected_task_handle is not None
            and str(row["task_handle"])
            != str(expected_task_handle)
        ):
            raise ApprovalTicketBindingError(
                "Approval ticket belongs to another task"
            )

        if (
            expected_user is not None
            and str(row["user"])
            != str(expected_user)
        ):
            raise ApprovalTicketBindingError(
                "Approval ticket belongs to another user"
            )

        return {
            "approval_ticket": str(
                row["approval_ticket"]
            ),
            "task_handle": str(
                row["task_handle"]
            ),
            "user": str(row["user"]),
            "step_index": int(
                row["step_index"]
            ),
            "tool": str(row["tool"]),
            "request_hash": str(
                row["request_hash"]
            ),
            "params": json.loads(
                row["params_json"]
            ),
            "data_refs": json.loads(
                row["data_refs_json"]
            ),
            "status": str(row["status"]),
            "requested_at": row[
                "requested_at"
            ],
            "decided_at": row[
                "decided_at"
            ],
            "decided_by": row[
                "decided_by"
            ],
            "consumed_at": row[
                "consumed_at"
            ],
        }

    finally:
        connection.close()


def decide_approval_ticket(
    *,
    approval_ticket: str,
    task_handle: str,
    user: str,
    decided_by: str,
    decision: str,
) -> dict:
    normalized_decision = str(
        decision
    ).strip().lower()

    decision_map = {
        "approve": "approved",
        "approved": "approved",
        "deny": "denied",
        "denied": "denied",
    }

    if normalized_decision not in decision_map:
        raise ValueError(
            "decision must be approve or deny"
        )

    target_status = decision_map[
        normalized_decision
    ]

    connection = connect()

    try:
        _ensure_approval_schema(connection)
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            """
            SELECT
                task_handle,
                user,
                status,
                decided_by
            FROM trusted_approval_tickets
            WHERE approval_ticket = ?
            """,
            (
                str(
                    approval_ticket
                ).strip(),
            ),
        ).fetchone()

        if row is None:
            raise ApprovalTicketNotFoundError(
                "Approval ticket was not found"
            )

        if (
            str(row["task_handle"])
            != str(task_handle)
        ):
            raise ApprovalTicketBindingError(
                "Approval ticket belongs to another task"
            )

        if str(row["user"]) != str(user):
            raise ApprovalTicketBindingError(
                "Approval ticket belongs to another user"
            )

        current_status = str(
            row["status"]
        )

        if current_status == target_status:
            connection.commit()

            return get_approval_ticket(
                approval_ticket=approval_ticket,
                expected_task_handle=task_handle,
                expected_user=user,
            )

        if current_status != "pending":
            raise ApprovalTicketStateError(
                "Only a pending approval ticket "
                "can be decided"
            )

        connection.execute(
            """
            UPDATE trusted_approval_tickets
            SET
                status = ?,
                decided_at = ?,
                decided_by = ?
            WHERE approval_ticket = ?
            """,
            (
                target_status,
                now_iso(),
                str(decided_by).strip(),
                str(
                    approval_ticket
                ).strip(),
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return get_approval_ticket(
        approval_ticket=approval_ticket,
        expected_task_handle=task_handle,
        expected_user=user,
    )

def validate_approval_ticket_for_request(
    *,
    approval_ticket: str,
    task_handle: str,
    user: str,
    tool: str,
    params: dict,
    data_refs: list[str],
) -> dict:
    """
    Validate that an approved ticket is bound to the
    exact task, user, tool, parameters and data references.
    """
    ticket = get_approval_ticket(
        approval_ticket=approval_ticket,
        expected_task_handle=task_handle,
        expected_user=user,
    )

    expected_hash = _approval_request_hash(
        tool=str(tool),
        params=dict(params or {}),
        data_refs=_normalize_data_refs(
            data_refs
        ),
    )

    if (
        ticket["request_hash"]
        != expected_hash
    ):
        raise ApprovalTicketBindingError(
            "Approval ticket does not match "
            "the requested tool call"
        )

    if ticket["tool"] != str(tool):
        raise ApprovalTicketBindingError(
            "Approval ticket is bound to "
            "a different tool"
        )

    if ticket["status"] != "approved":
        raise ApprovalTicketStateError(
            "Approval ticket must be approved "
            "before execution"
        )

    return ticket


def consume_approval_ticket(
    *,
    approval_ticket: str,
    task_handle: str,
    user: str,
    tool: str,
    params: dict,
    data_refs: list[str],
) -> dict:
    """
    Atomically consume one approved ticket.

    The state transition is strictly:

        approved -> consumed

    A consumed, pending or denied ticket cannot be used.
    """
    approval_ticket = str(
        approval_ticket
    ).strip()

    task_handle = str(
        task_handle
    ).strip()

    user = str(user).strip()
    tool = str(tool).strip()

    expected_hash = _approval_request_hash(
        tool=tool,
        params=dict(params or {}),
        data_refs=_normalize_data_refs(
            data_refs
        ),
    )

    connection = connect()

    try:
        _ensure_approval_schema(connection)
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            """
            SELECT
                task_handle,
                user,
                tool,
                request_hash,
                status
            FROM trusted_approval_tickets
            WHERE approval_ticket = ?
            """,
            (approval_ticket,),
        ).fetchone()

        if row is None:
            raise ApprovalTicketNotFoundError(
                "Approval ticket was not found"
            )

        if (
            str(row["task_handle"])
            != task_handle
        ):
            raise ApprovalTicketBindingError(
                "Approval ticket belongs to "
                "another task"
            )

        if str(row["user"]) != user:
            raise ApprovalTicketBindingError(
                "Approval ticket belongs to "
                "another user"
            )

        if str(row["tool"]) != tool:
            raise ApprovalTicketBindingError(
                "Approval ticket is bound to "
                "a different tool"
            )

        if (
            str(row["request_hash"])
            != expected_hash
        ):
            raise ApprovalTicketBindingError(
                "Approval ticket does not match "
                "the requested parameters or "
                "data references"
            )

        if str(row["status"]) != "approved":
            raise ApprovalTicketStateError(
                "Only an approved ticket "
                "can be consumed"
            )

        consumed_at = now_iso()

        cursor = connection.execute(
            """
            UPDATE trusted_approval_tickets
            SET
                status = 'consumed',
                consumed_at = ?
            WHERE approval_ticket = ?
              AND status = 'approved'
            """,
            (
                consumed_at,
                approval_ticket,
            ),
        )

        if cursor.rowcount != 1:
            raise ApprovalTicketStateError(
                "Approval ticket was already "
                "used or changed"
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return get_approval_ticket(
        approval_ticket=approval_ticket,
        expected_task_handle=task_handle,
        expected_user=user,
    )


def _mcp_canonical_json(
    value,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _mcp_sha256_text(
    value: str,
) -> str:
    return hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()


def _ensure_mcp_idempotency_schema(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS
        trusted_mcp_idempotency (
            key_hash TEXT PRIMARY KEY,
            principal_hash TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            claim_token TEXT NOT NULL,
            http_status INTEGER,
            response_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at_epoch INTEGER NOT NULL
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_mcp_idempotency_expiry
        ON trusted_mcp_idempotency(
            expires_at_epoch
        )
        """
    )


def claim_mcp_idempotency_key(
    *,
    subject: str,
    client_id: str,
    idempotency_key: str,
    request_payload: dict,
    ttl_seconds: int,
) -> dict:
    normalized_subject = str(
        subject or ""
    ).strip()

    normalized_client = str(
        client_id or ""
    ).strip()

    normalized_key = str(
        idempotency_key or ""
    ).strip()

    if not normalized_subject:
        raise ValueError(
            "OAuth subject is required."
        )

    if not normalized_key:
        raise ValueError(
            "Idempotency key is required."
        )

    ttl = max(
        60,
        min(
            int(ttl_seconds),
            7 * 24 * 60 * 60,
        ),
    )

    principal_hash = (
        _mcp_sha256_text(
            normalized_subject
            + "\n"
            + normalized_client
        )
    )

    key_hash = _mcp_sha256_text(
        principal_hash
        + "\n"
        + normalized_key
    )

    request_hash = (
        _mcp_sha256_text(
            _mcp_canonical_json(
                request_payload
            )
        )
    )

    claim_token = (
        "agc_"
        + secrets.token_urlsafe(32)
    )

    current_epoch = int(
        time.time()
    )

    expires_at = (
        current_epoch + ttl
    )

    timestamp = now_iso()

    connection = connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        _ensure_mcp_idempotency_schema(
            connection
        )

        connection.execute(
            """
            DELETE FROM
                trusted_mcp_idempotency
            WHERE expires_at_epoch <= ?
            """,
            (current_epoch,),
        )

        row = connection.execute(
            """
            SELECT
                key_hash,
                request_hash,
                status,
                claim_token,
                http_status,
                response_json,
                expires_at_epoch
            FROM trusted_mcp_idempotency
            WHERE key_hash = ?
            """,
            (key_hash,),
        ).fetchone()

        if row is not None:
            if (
                str(row["request_hash"])
                != request_hash
            ):
                connection.commit()

                return {
                    "state": "conflict",
                    "key_hash": key_hash,
                    "request_hash": (
                        request_hash
                    ),
                    "reason": (
                        "The idempotency key "
                        "is already bound to "
                        "a different request."
                    ),
                }

            status = str(
                row["status"]
            )

            if status == "completed":
                try:
                    response_body = (
                        json.loads(
                            str(
                                row[
                                    "response_json"
                                ]
                                or "null"
                            )
                        )
                    )

                except json.JSONDecodeError:
                    connection.commit()

                    return {
                        "state": "corrupted",
                        "key_hash": key_hash,
                        "request_hash": (
                            request_hash
                        ),
                        "reason": (
                            "Stored idempotency "
                            "response is corrupted."
                        ),
                    }

                connection.commit()

                return {
                    "state": "completed",
                    "key_hash": key_hash,
                    "request_hash": (
                        request_hash
                    ),
                    "http_status": int(
                        row["http_status"]
                        or 200
                    ),
                    "response_body": (
                        response_body
                    ),
                }

            connection.commit()

            return {
                "state": "in_progress",
                "key_hash": key_hash,
                "request_hash": (
                    request_hash
                ),
                "expires_at_epoch": int(
                    row[
                        "expires_at_epoch"
                    ]
                ),
                "reason": (
                    "An identical MCP request "
                    "is already being processed."
                ),
            }

        connection.execute(
            """
            INSERT INTO
                trusted_mcp_idempotency (
                    key_hash,
                    principal_hash,
                    request_hash,
                    status,
                    claim_token,
                    http_status,
                    response_json,
                    created_at,
                    updated_at,
                    expires_at_epoch
                )
            VALUES (
                ?, ?, ?, 'processing',
                ?, NULL, NULL, ?, ?, ?
            )
            """,
            (
                key_hash,
                principal_hash,
                request_hash,
                claim_token,
                timestamp,
                timestamp,
                expires_at,
            ),
        )

        connection.commit()

        return {
            "state": "acquired",
            "key_hash": key_hash,
            "request_hash": request_hash,
            "claim_token": claim_token,
            "expires_at_epoch": (
                expires_at
            ),
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def complete_mcp_idempotency_key(
    *,
    key_hash: str,
    request_hash: str,
    claim_token: str,
    http_status: int,
    response_body,
) -> dict:
    response_json = (
        _mcp_canonical_json(
            response_body
        )
    )

    connection = connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        _ensure_mcp_idempotency_schema(
            connection
        )

        cursor = connection.execute(
            """
            UPDATE trusted_mcp_idempotency
            SET
                status = 'completed',
                http_status = ?,
                response_json = ?,
                updated_at = ?
            WHERE key_hash = ?
              AND request_hash = ?
              AND claim_token = ?
              AND status = 'processing'
            """,
            (
                int(http_status),
                response_json,
                now_iso(),
                str(key_hash),
                str(request_hash),
                str(claim_token),
            ),
        )

        completed = (
            cursor.rowcount == 1
        )

        connection.commit()

        return {
            "completed": completed,
            "state": (
                "completed"
                if completed
                else "claim_mismatch"
            ),
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def abandon_mcp_idempotency_key(
    *,
    key_hash: str,
    request_hash: str,
    claim_token: str,
) -> bool:
    connection = connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        _ensure_mcp_idempotency_schema(
            connection
        )

        cursor = connection.execute(
            """
            DELETE FROM
                trusted_mcp_idempotency
            WHERE key_hash = ?
              AND request_hash = ?
              AND claim_token = ?
              AND status = 'processing'
            """,
            (
                str(key_hash),
                str(request_hash),
                str(claim_token),
            ),
        )

        connection.commit()

        return cursor.rowcount == 1

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
