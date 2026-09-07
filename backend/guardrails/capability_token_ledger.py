from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[2]
LEDGER_DIR = ROOT / "runtime_workspace"
LEDGER_DB = (
    LEDGER_DIR
    / "capability_token_ledger.db"
)

VALID_FINAL_STATUSES = {
    "consumed",
    "failed",
}


def _now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _connect() -> sqlite3.Connection:
    LEDGER_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        LEDGER_DB,
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
        "PRAGMA busy_timeout=30000"
    )

    _init_db(connection)
    return connection


def _ensure_columns(
    connection: sqlite3.Connection,
) -> None:
    """
    Upgrade an existing token ledger without deleting
    previously issued token records.
    """

    rows = connection.execute(
        "PRAGMA table_info(capability_tokens)"
    ).fetchall()

    existing_columns = {
        str(row["name"])
        for row in rows
    }

    required_columns = {
        "claimed_at": "TEXT",
        "finished_at": "TEXT",
        "execution_id": "TEXT",
        "result_hash": "TEXT",
        "failure_reason": "TEXT",
    }

    for column_name, column_type in (
        required_columns.items()
    ):
        if column_name in existing_columns:
            continue

        connection.execute(
            (
                "ALTER TABLE capability_tokens "
                f"ADD COLUMN {column_name} "
                f"{column_type}"
            )
        )


def _init_db(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS
        capability_tokens (
            token_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            issued_at TEXT,
            claimed_at TEXT,
            consumed_at TEXT,
            finished_at TEXT,
            revoked_at TEXT,
            execution_id TEXT,
            result_hash TEXT,
            failure_reason TEXT,
            revoke_reason TEXT,
            payload_json TEXT
        )
        """
    )

    _ensure_columns(connection)

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS
        capability_token_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL,
            event TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            detail_json TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_capability_token_status
        ON capability_tokens(status)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_capability_token_execution
        ON capability_tokens(execution_id)
        """
    )


def _record_event(
    connection: sqlite3.Connection,
    token_id: str,
    event: str,
    detail: Dict[str, Any] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO capability_token_events (
            token_id,
            event,
            timestamp,
            detail_json
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            token_id,
            event,
            _now(),
            json.dumps(
                detail or {},
                ensure_ascii=False,
                sort_keys=True,
            ),
        ),
    )


def record_token_issued(
    token_id: str,
    payload: Dict[str, Any],
) -> None:
    """
    Persist a newly issued token.

    Existing token IDs are never replaced because replacing
    a consumed or revoked token could resurrect it.
    """

    token_id = str(
        token_id or ""
    ).strip()

    if not token_id:
        return

    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        cursor = connection.execute(
            """
            INSERT INTO capability_tokens (
                token_id,
                status,
                issued_at,
                claimed_at,
                consumed_at,
                finished_at,
                revoked_at,
                execution_id,
                result_hash,
                failure_reason,
                revoke_reason,
                payload_json
            )
            VALUES (
                ?,
                'issued',
                ?,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                '',
                ?
            )
            ON CONFLICT(token_id)
            DO NOTHING
            """,
            (
                token_id,
                _now(),
                json.dumps(
                    payload or {},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            ),
        )

        if cursor.rowcount == 1:
            _record_event(
                connection,
                token_id,
                "issued",
                {
                    "agent_platform": (
                        payload.get(
                            "agent_platform",
                            "",
                        )
                    ),
                },
            )
        else:
            _record_event(
                connection,
                token_id,
                "duplicate_issue_rejected",
                {
                    "reason": (
                        "Existing token state "
                        "was not overwritten."
                    ),
                },
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def claim_token_for_execution(
    token_id: str,
    execution_id: str,
) -> Dict[str, Any]:
    """
    Atomically acquire the one-time right to execute.

    Exactly one caller can change:

        issued -> executing

    Concurrent or replayed requests receive acquired=False.
    """

    token_id = str(
        token_id or ""
    ).strip()

    execution_id = str(
        execution_id or ""
    ).strip()

    if not token_id:
        return {
            "acquired": False,
            "status": "invalid",
            "reason": "token_id is required.",
        }

    if not execution_id:
        return {
            "acquired": False,
            "status": "invalid",
            "reason": "execution_id is required.",
        }

    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                execution_id
            FROM capability_tokens
            WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()

        if row is None:
            connection.rollback()

            return {
                "acquired": False,
                "token_id": token_id,
                "execution_id": execution_id,
                "status": "unknown",
                "reason": (
                    "Capability token is not "
                    "present in the ledger."
                ),
            }

        current_status = str(
            row["status"] or "unknown"
        )

        if current_status != "issued":
            connection.rollback()

            return {
                "acquired": False,
                "token_id": token_id,
                "execution_id": execution_id,
                "existing_execution_id": str(
                    row["execution_id"] or ""
                ),
                "status": current_status,
                "reason": (
                    "Capability token is not "
                    "available for execution."
                ),
            }

        claimed_at = _now()

        cursor = connection.execute(
            """
            UPDATE capability_tokens
            SET
                status = 'executing',
                claimed_at = ?,
                execution_id = ?,
                failure_reason = NULL,
                result_hash = NULL
            WHERE token_id = ?
              AND status = 'issued'
            """,
            (
                claimed_at,
                execution_id,
                token_id,
            ),
        )

        if cursor.rowcount != 1:
            connection.rollback()

            return {
                "acquired": False,
                "token_id": token_id,
                "execution_id": execution_id,
                "status": "conflict",
                "reason": (
                    "Another request acquired "
                    "the capability token first."
                ),
            }

        _record_event(
            connection,
            token_id,
            "execution_claimed",
            {
                "execution_id": execution_id,
                "claimed_at": claimed_at,
            },
        )

        connection.commit()

        return {
            "acquired": True,
            "token_id": token_id,
            "execution_id": execution_id,
            "status": "executing",
            "claimed_at": claimed_at,
            "reason": (
                "Capability token execution "
                "right was acquired atomically."
            ),
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def finalize_token_execution(
    token_id: str,
    execution_id: str,
    outcome: str,
    result_hash: str = "",
    failure_reason: str = "",
) -> Dict[str, Any]:
    """
    Finish the exact execution that previously claimed
    the token.

    Allowed transitions:

        executing -> consumed
        executing -> failed
    """

    token_id = str(
        token_id or ""
    ).strip()

    execution_id = str(
        execution_id or ""
    ).strip()

    outcome = str(
        outcome or ""
    ).strip().lower()

    if outcome not in VALID_FINAL_STATUSES:
        return {
            "finalized": False,
            "status": "invalid",
            "reason": (
                "outcome must be consumed "
                "or failed."
            ),
        }

    if not token_id or not execution_id:
        return {
            "finalized": False,
            "status": "invalid",
            "reason": (
                "token_id and execution_id "
                "are required."
            ),
        }

    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                execution_id
            FROM capability_tokens
            WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()

        if row is None:
            connection.rollback()

            return {
                "finalized": False,
                "status": "unknown",
                "reason": (
                    "Capability token is not "
                    "present in the ledger."
                ),
            }

        current_status = str(
            row["status"] or "unknown"
        )

        existing_execution_id = str(
            row["execution_id"] or ""
        )

        if current_status != "executing":
            connection.rollback()

            return {
                "finalized": False,
                "status": current_status,
                "reason": (
                    "Capability token is not "
                    "in executing state."
                ),
            }

        if (
            existing_execution_id
            != execution_id
        ):
            connection.rollback()

            return {
                "finalized": False,
                "status": current_status,
                "reason": (
                    "execution_id does not match "
                    "the token claim owner."
                ),
            }

        finished_at = _now()

        consumed_at = (
            finished_at
            if outcome == "consumed"
            else None
        )

        cursor = connection.execute(
            """
            UPDATE capability_tokens
            SET
                status = ?,
                consumed_at = ?,
                finished_at = ?,
                result_hash = ?,
                failure_reason = ?
            WHERE token_id = ?
              AND status = 'executing'
              AND execution_id = ?
            """,
            (
                outcome,
                consumed_at,
                finished_at,
                str(result_hash or ""),
                str(failure_reason or ""),
                token_id,
                execution_id,
            ),
        )

        if cursor.rowcount != 1:
            connection.rollback()

            return {
                "finalized": False,
                "status": "conflict",
                "reason": (
                    "Token execution state changed "
                    "before finalization."
                ),
            }

        event_name = (
            "execution_consumed"
            if outcome == "consumed"
            else "execution_failed"
        )

        event_detail = {
            "execution_id": execution_id,
            "result_hash": str(
                result_hash or ""
            ),
            "failure_reason": str(
                failure_reason or ""
            ),
            "finished_at": finished_at,
        }

        # Rich lifecycle event used by the new atomic
        # execution state machine.
        _record_event(
            connection,
            token_id,
            event_name,
            event_detail,
        )

        # Compatibility alias used by existing routes,
        # reports and regression tests.
        _record_event(
            connection,
            token_id,
            outcome,
            {
                **event_detail,
                "compatibility_alias_for": (
                    event_name
                ),
            },
        )

        connection.commit()

        return {
            "finalized": True,
            "token_id": token_id,
            "execution_id": execution_id,
            "status": outcome,
            "consumed": (
                outcome == "consumed"
            ),
            "failed": (
                outcome == "failed"
            ),
            "finished_at": finished_at,
            "reason": (
                "Capability token execution "
                "was finalized atomically."
            ),
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def record_token_consumed(
    token_id: str,
) -> None:
    """
    Legacy compatibility function.

    New execution paths should use claim_token_for_execution
    and finalize_token_execution instead.
    """

    token_id = str(
        token_id or ""
    ).strip()

    if not token_id:
        return

    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        timestamp = _now()

        cursor = connection.execute(
            """
            UPDATE capability_tokens
            SET
                status = 'consumed',
                consumed_at = ?,
                finished_at = ?
            WHERE token_id = ?
              AND status IN (
                  'issued',
                  'executing'
              )
            """,
            (
                timestamp,
                timestamp,
                token_id,
            ),
        )

        if cursor.rowcount == 1:
            _record_event(
                connection,
                token_id,
                "consumed_legacy",
                {
                    "warning": (
                        "Legacy non-claim token "
                        "consumption was used."
                    ),
                },
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def record_token_revoked(
    token_id: str,
    reason: str = "",
) -> None:
    token_id = str(
        token_id or ""
    ).strip()

    if not token_id:
        return

    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        existing = connection.execute(
            """
            SELECT token_id
            FROM capability_tokens
            WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()

        revoked_at = _now()

        if existing:
            connection.execute(
                """
                UPDATE capability_tokens
                SET
                    status = 'revoked',
                    revoked_at = ?,
                    finished_at = ?,
                    revoke_reason = ?
                WHERE token_id = ?
                """,
                (
                    revoked_at,
                    revoked_at,
                    str(reason or ""),
                    token_id,
                ),
            )
        else:
            connection.execute(
                """
                INSERT INTO capability_tokens (
                    token_id,
                    status,
                    issued_at,
                    claimed_at,
                    consumed_at,
                    finished_at,
                    revoked_at,
                    execution_id,
                    result_hash,
                    failure_reason,
                    revoke_reason,
                    payload_json
                )
                VALUES (
                    ?,
                    'revoked',
                    NULL,
                    NULL,
                    NULL,
                    ?,
                    ?,
                    NULL,
                    NULL,
                    NULL,
                    ?,
                    '{}'
                )
                """,
                (
                    token_id,
                    revoked_at,
                    revoked_at,
                    str(reason or ""),
                ),
            )

        _record_event(
            connection,
            token_id,
            "revoked",
            {
                "reason": str(reason or ""),
            },
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_token_status(
    token_id: str,
) -> Dict[str, Any]:
    token_id = str(
        token_id or ""
    ).strip()

    connection = _connect()

    try:
        row = connection.execute(
            """
            SELECT
                token_id,
                status,
                issued_at,
                claimed_at,
                consumed_at,
                finished_at,
                revoked_at,
                execution_id,
                result_hash,
                failure_reason,
                revoke_reason,
                payload_json
            FROM capability_tokens
            WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        return {
            "token_id": token_id,
            "status": "unknown",
            "issued_at": None,
            "claimed_at": None,
            "consumed_at": None,
            "finished_at": None,
            "revoked_at": None,
            "execution_id": "",
            "result_hash": "",
            "failure_reason": "",
            "revoke_reason": "",
            "payload": {},
        }

    payload_text = (
        row["payload_json"]
        or "{}"
    )

    try:
        payload = json.loads(
            payload_text
        )
    except json.JSONDecodeError:
        payload = {}

    return {
        "token_id": row["token_id"],
        "status": row["status"],
        "issued_at": row["issued_at"],
        "claimed_at": row["claimed_at"],
        "consumed_at": row["consumed_at"],
        "finished_at": row["finished_at"],
        "revoked_at": row["revoked_at"],
        "execution_id": (
            row["execution_id"] or ""
        ),
        "result_hash": (
            row["result_hash"] or ""
        ),
        "failure_reason": (
            row["failure_reason"] or ""
        ),
        "revoke_reason": (
            row["revoke_reason"] or ""
        ),
        "payload": payload,
    }


def get_token_events(
    token_id: str = "",
) -> List[Dict[str, Any]]:
    connection = _connect()

    try:
        if token_id:
            rows = connection.execute(
                """
                SELECT
                    token_id,
                    event,
                    timestamp,
                    detail_json
                FROM capability_token_events
                WHERE token_id = ?
                ORDER BY id ASC
                """,
                (token_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT
                    token_id,
                    event,
                    timestamp,
                    detail_json
                FROM capability_token_events
                ORDER BY id ASC
                """
            ).fetchall()

    finally:
        connection.close()

    events: List[
        Dict[str, Any]
    ] = []

    for row in rows:
        try:
            detail = json.loads(
                row["detail_json"]
                or "{}"
            )
        except json.JSONDecodeError:
            detail = {}

        events.append(
            {
                "token_id": row[
                    "token_id"
                ],
                "event": row[
                    "event"
                ],
                "timestamp": row[
                    "timestamp"
                ],
                "detail": detail,
            }
        )

    return events


def reset_token_ledger() -> None:
    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )
        connection.execute(
            "DELETE FROM capability_token_events"
        )
        connection.execute(
            "DELETE FROM capability_tokens"
        )
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
