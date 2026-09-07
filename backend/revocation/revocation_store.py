from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.audit.trusted_audit_store import (
    sanitize_audit_payload,
)


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"

REVOCATION_DB_PATH = (
    DATA_DIR
    / "trusted_revocation_registry.db"
)

SUPPORTED_SUBJECT_TYPES = {
    "task",
    "approval_ticket",
    "capability_token",
}


class RevocationStoreError(RuntimeError):
    """Base error for the revocation registry."""


class RevocationBindingError(
    RevocationStoreError
):
    """A revocation belongs to another task or user."""


class SubjectRevokedError(
    RevocationStoreError
):
    """The requested subject has been revoked."""


def _now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _canonical_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_subject_type(
    subject_type: str,
) -> str:
    normalized = str(
        subject_type
    ).strip().lower()

    if (
        normalized
        not in SUPPORTED_SUBJECT_TYPES
    ):
        raise ValueError(
            "subject_type must be one of: "
            + ", ".join(
                sorted(
                    SUPPORTED_SUBJECT_TYPES
                )
            )
        )

    return normalized


def subject_fingerprint(
    *,
    subject_type: str,
    subject_value: str,
) -> str:
    """
    Produce a domain-separated SHA-256 fingerprint.

    The original task handle, approval ticket or capability
    token is never stored in the revocation database.
    """
    normalized_type = (
        _normalize_subject_type(
            subject_type
        )
    )

    normalized_value = str(
        subject_value
    ).strip()

    if not normalized_value:
        raise ValueError(
            "subject_value is required"
        )

    material = (
        normalized_type
        + "\x00"
        + normalized_value
    ).encode("utf-8")

    return hashlib.sha256(
        material
    ).hexdigest()


def connect() -> sqlite3.Connection:
    REVOCATION_DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        REVOCATION_DB_PATH,
        timeout=30,
        isolation_level=None,
    )

    connection.row_factory = (
        sqlite3.Row
    )

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    connection.execute(
        "PRAGMA synchronous=FULL"
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS
        trusted_revocations (
            revocation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_type TEXT NOT NULL,
            subject_hash TEXT NOT NULL,
            task_handle_hash TEXT NOT NULL,
            user_hash TEXT NOT NULL,
            reason TEXT NOT NULL,
            revoked_by TEXT NOT NULL,
            revoked_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            UNIQUE(
                subject_type,
                subject_hash
            )
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_trusted_revocations_task
        ON trusted_revocations(
            task_handle_hash,
            revocation_id
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_trusted_revocations_user
        ON trusted_revocations(
            user_hash,
            revocation_id
        )
        """
    )

    return connection


def _optional_fingerprint(
    *,
    namespace: str,
    value: str,
) -> str:
    normalized = str(
        value or ""
    ).strip()

    if not normalized:
        return ""

    return hashlib.sha256(
        (
            namespace
            + "\x00"
            + normalized
        ).encode("utf-8")
    ).hexdigest()


def _row_to_record(
    row: sqlite3.Row,
) -> Dict[str, Any]:
    try:
        metadata = json.loads(
            row["metadata_json"]
        )

    except json.JSONDecodeError:
        metadata = {
            "_corrupted": True,
        }

    return {
        "revocation_id": int(
            row["revocation_id"]
        ),
        "subject_type": str(
            row["subject_type"]
        ),
        "subject_hash": str(
            row["subject_hash"]
        ),
        "task_handle_hash": str(
            row["task_handle_hash"]
        ),
        "user_hash": str(
            row["user_hash"]
        ),
        "reason": str(
            row["reason"]
        ),
        "revoked_by": str(
            row["revoked_by"]
        ),
        "revoked_at": str(
            row["revoked_at"]
        ),
        "metadata": metadata,
    }


def revoke_subject(
    *,
    subject_type: str,
    subject_value: str,
    task_handle: str = "",
    user: str = "",
    reason: str,
    revoked_by: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    normalized_type = (
        _normalize_subject_type(
            subject_type
        )
    )

    normalized_reason = str(
        reason
    ).strip()

    normalized_revoked_by = str(
        revoked_by
    ).strip()

    if not normalized_reason:
        raise ValueError(
            "reason is required"
        )

    if not normalized_revoked_by:
        raise ValueError(
            "revoked_by is required"
        )

    subject_hash = (
        subject_fingerprint(
            subject_type=normalized_type,
            subject_value=subject_value,
        )
    )

    normalized_task_handle = str(
        task_handle or ""
    ).strip()

    if (
        normalized_type == "task"
        and not normalized_task_handle
    ):
        normalized_task_handle = str(
            subject_value
        ).strip()

    task_handle_hash = (
        _optional_fingerprint(
            namespace="task_handle",
            value=normalized_task_handle,
        )
    )

    user_hash = _optional_fingerprint(
        namespace="user",
        value=str(user or ""),
    )

    sanitized_metadata = (
        sanitize_audit_payload(
            dict(metadata or {})
        )
    )

    metadata_json = _canonical_json(
        sanitized_metadata
    )

    revoked_at = _now_iso()

    connection = connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        existing = connection.execute(
            """
            SELECT
                revocation_id,
                subject_type,
                subject_hash,
                task_handle_hash,
                user_hash,
                reason,
                revoked_by,
                revoked_at,
                metadata_json
            FROM trusted_revocations
            WHERE subject_type = ?
              AND subject_hash = ?
            """,
            (
                normalized_type,
                subject_hash,
            ),
        ).fetchone()

        if existing is not None:
            existing_record = (
                _row_to_record(existing)
            )

            if (
                task_handle_hash
                and existing_record[
                    "task_handle_hash"
                ]
                and task_handle_hash
                != existing_record[
                    "task_handle_hash"
                ]
            ):
                raise RevocationBindingError(
                    "Existing revocation belongs "
                    "to another task"
                )

            if (
                user_hash
                and existing_record[
                    "user_hash"
                ]
                and user_hash
                != existing_record[
                    "user_hash"
                ]
            ):
                raise RevocationBindingError(
                    "Existing revocation belongs "
                    "to another user"
                )

            connection.commit()
            return existing_record

        cursor = connection.execute(
            """
            INSERT INTO trusted_revocations (
                subject_type,
                subject_hash,
                task_handle_hash,
                user_hash,
                reason,
                revoked_by,
                revoked_at,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_type,
                subject_hash,
                task_handle_hash,
                user_hash,
                normalized_reason,
                normalized_revoked_by,
                revoked_at,
                metadata_json,
            ),
        )

        revocation_id = int(
            cursor.lastrowid
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "revocation_id": (
            revocation_id
        ),
        "subject_type": (
            normalized_type
        ),
        "subject_hash": (
            subject_hash
        ),
        "task_handle_hash": (
            task_handle_hash
        ),
        "user_hash": user_hash,
        "reason": normalized_reason,
        "revoked_by": (
            normalized_revoked_by
        ),
        "revoked_at": revoked_at,
        "metadata": (
            sanitized_metadata
        ),
    }


def get_revocation(
    *,
    subject_type: str,
    subject_value: str,
    expected_task_handle: str = "",
    expected_user: str = "",
) -> Optional[Dict[str, Any]]:
    normalized_type = (
        _normalize_subject_type(
            subject_type
        )
    )

    subject_hash = (
        subject_fingerprint(
            subject_type=normalized_type,
            subject_value=subject_value,
        )
    )

    connection = connect()

    try:
        row = connection.execute(
            """
            SELECT
                revocation_id,
                subject_type,
                subject_hash,
                task_handle_hash,
                user_hash,
                reason,
                revoked_by,
                revoked_at,
                metadata_json
            FROM trusted_revocations
            WHERE subject_type = ?
              AND subject_hash = ?
            """,
            (
                normalized_type,
                subject_hash,
            ),
        ).fetchone()

    finally:
        connection.close()

    if row is None:
        return None

    record = _row_to_record(row)

    expected_task_hash = (
        _optional_fingerprint(
            namespace="task_handle",
            value=expected_task_handle,
        )
    )

    expected_user_hash = (
        _optional_fingerprint(
            namespace="user",
            value=expected_user,
        )
    )

    if (
        expected_task_hash
        and record["task_handle_hash"]
        and expected_task_hash
        != record["task_handle_hash"]
    ):
        raise RevocationBindingError(
            "Revocation belongs to "
            "another task"
        )

    if (
        expected_user_hash
        and record["user_hash"]
        and expected_user_hash
        != record["user_hash"]
    ):
        raise RevocationBindingError(
            "Revocation belongs to "
            "another user"
        )

    return record


def is_subject_revoked(
    *,
    subject_type: str,
    subject_value: str,
    expected_task_handle: str = "",
    expected_user: str = "",
) -> bool:
    return (
        get_revocation(
            subject_type=subject_type,
            subject_value=subject_value,
            expected_task_handle=(
                expected_task_handle
            ),
            expected_user=(
                expected_user
            ),
        )
        is not None
    )


def assert_subject_not_revoked(
    *,
    subject_type: str,
    subject_value: str,
    expected_task_handle: str = "",
    expected_user: str = "",
) -> None:
    record = get_revocation(
        subject_type=subject_type,
        subject_value=subject_value,
        expected_task_handle=(
            expected_task_handle
        ),
        expected_user=expected_user,
    )

    if record is None:
        return

    raise SubjectRevokedError(
        (
            f"{record['subject_type']} "
            "has been revoked: "
            f"{record['reason']}"
        )
    )


def list_revocations(
    *,
    task_handle: str = "",
    user: str = "",
    subject_type: str = "",
    limit: int = 100,
) -> List[Dict[str, Any]]:
    normalized_limit = max(
        1,
        min(int(limit), 1000),
    )

    conditions: List[str] = []
    values: List[Any] = []

    if task_handle:
        conditions.append(
            "task_handle_hash = ?"
        )
        values.append(
            _optional_fingerprint(
                namespace="task_handle",
                value=task_handle,
            )
        )

    if user:
        conditions.append(
            "user_hash = ?"
        )
        values.append(
            _optional_fingerprint(
                namespace="user",
                value=user,
            )
        )

    if subject_type:
        conditions.append(
            "subject_type = ?"
        )
        values.append(
            _normalize_subject_type(
                subject_type
            )
        )

    where_clause = ""

    if conditions:
        where_clause = (
            " WHERE "
            + " AND ".join(conditions)
        )

    query = (
        """
        SELECT
            revocation_id,
            subject_type,
            subject_hash,
            task_handle_hash,
            user_hash,
            reason,
            revoked_by,
            revoked_at,
            metadata_json
        FROM trusted_revocations
        """
        + where_clause
        + """
        ORDER BY revocation_id ASC
        LIMIT ?
        """
    )

    values.append(
        normalized_limit
    )

    connection = connect()

    try:
        rows = connection.execute(
            query,
            tuple(values),
        ).fetchall()

    finally:
        connection.close()

    return [
        _row_to_record(row)
        for row in rows
    ]


def revoke_task(
    *,
    task_handle: str,
    user: str,
    reason: str,
    revoked_by: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    return revoke_subject(
        subject_type="task",
        subject_value=task_handle,
        task_handle=task_handle,
        user=user,
        reason=reason,
        revoked_by=revoked_by,
        metadata=metadata,
    )


def revoke_approval_ticket(
    *,
    approval_ticket: str,
    task_handle: str,
    user: str,
    reason: str,
    revoked_by: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    return revoke_subject(
        subject_type=(
            "approval_ticket"
        ),
        subject_value=(
            approval_ticket
        ),
        task_handle=task_handle,
        user=user,
        reason=reason,
        revoked_by=revoked_by,
        metadata=metadata,
    )


def revoke_capability_token(
    *,
    capability_token: str,
    task_handle: str,
    user: str,
    reason: str,
    revoked_by: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    return revoke_subject(
        subject_type=(
            "capability_token"
        ),
        subject_value=(
            capability_token
        ),
        task_handle=task_handle,
        user=user,
        reason=reason,
        revoked_by=revoked_by,
        metadata=metadata,
    )
