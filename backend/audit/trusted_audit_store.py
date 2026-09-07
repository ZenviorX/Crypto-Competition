from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"

AUDIT_DB_PATH = (
    DATA_DIR
    / "trusted_audit_chain.db"
)

GENESIS_HASH = "0" * 64
CHAIN_HEAD_ID = 1
MAX_TEXT_LENGTH = 500

SENSITIVE_WORDS = {
    "password",
    "passwd",
    "token",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "private_key",
    "??",
    "??",
}


SENSITIVE_IDENTIFIER_KEYS = {
    "approval_ticket",
    "approvalticket",
    "approval_reference",
    "approvalreference",
    "capability_token",
    "capabilitytoken",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
}


class TrustedAuditError(RuntimeError):
    """Base error for trusted audit storage."""


class TrustedAuditIntegrityError(
    TrustedAuditError
):
    """Audit-chain integrity verification failed."""


def _now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _hash_sensitive_identifier(
    value: Any,
) -> Any:
    """
    Store a stable fingerprint instead of a raw
    approval ticket or authorization token.

    The operation is idempotent: an existing valid
    sha256 fingerprint is returned unchanged.
    """
    if value is None:
        return None

    if isinstance(value, str):
        normalized_string = (
            value.strip()
        )

        if normalized_string.startswith(
            "sha256:"
        ):
            existing_digest = (
                normalized_string[
                    len("sha256:"):
                ]
            )

            if (
                len(existing_digest) == 64
                and all(
                    character
                    in (
                        "0123456789"
                        "abcdefABCDEF"
                    )
                    for character
                    in existing_digest
                )
            ):
                return (
                    "sha256:"
                    + existing_digest.lower()
                )

    if isinstance(
        value,
        (
            dict,
            list,
            tuple,
        ),
    ):
        normalized = _canonical_json(
            value
        )

    else:
        normalized = str(value)

    if not normalized:
        return ""

    digest = hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()

    return "sha256:" + digest


def _sanitize_value(
    key: str,
    value: Any,
) -> Any:
    key_lower = str(key).lower()

    if (
        key_lower
        in SENSITIVE_IDENTIFIER_KEYS
    ):
        return _hash_sensitive_identifier(
            value
        )

    if any(
        word in key_lower
        for word in SENSITIVE_WORDS
    ):
        return "***MASKED***"

    if isinstance(value, dict):
        return {
            str(child_key): _sanitize_value(
                str(child_key),
                child_value,
            )
            for child_key, child_value
            in value.items()
        }

    if isinstance(value, list):
        return [
            _sanitize_value(
                key,
                item,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            _sanitize_value(
                key,
                item,
            )
            for item in value
        ]

    if isinstance(value, str):
        value_lower = value.lower()

        if any(
            word in value_lower
            for word in SENSITIVE_WORDS
        ):
            return "***MASKED***"

        if len(value) > MAX_TEXT_LENGTH:
            return (
                value[:MAX_TEXT_LENGTH]
                + "...[TRUNCATED]"
            )

        return value

    if value is None:
        return None

    if isinstance(
        value,
        (bool, int, float),
    ):
        return value

    return str(value)


def sanitize_audit_payload(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        str(key): _sanitize_value(
            str(key),
            value,
        )
        for key, value in dict(
            payload or {}
        ).items()
    }


def _record_material(
    *,
    sequence: int,
    event_id: str,
    task_handle: str,
    user: str,
    event_type: str,
    payload_json: str,
    created_at: str,
    prev_hash: str,
) -> Dict[str, Any]:
    return {
        "sequence": int(sequence),
        "event_id": str(event_id),
        "task_handle": str(
            task_handle
        ),
        "user": str(user),
        "event_type": str(
            event_type
        ),
        "payload_json": str(
            payload_json
        ),
        "created_at": str(
            created_at
        ),
        "prev_hash": str(
            prev_hash
        ),
    }


def _calculate_record_hash(
    *,
    sequence: int,
    event_id: str,
    task_handle: str,
    user: str,
    event_type: str,
    payload_json: str,
    created_at: str,
    prev_hash: str,
) -> str:
    material = _record_material(
        sequence=sequence,
        event_id=event_id,
        task_handle=task_handle,
        user=user,
        event_type=event_type,
        payload_json=payload_json,
        created_at=created_at,
        prev_hash=prev_hash,
    )

    encoded = _canonical_json(
        material
    ).encode("utf-8")

    return hashlib.sha256(
        encoded
    ).hexdigest()


def connect() -> sqlite3.Connection:
    AUDIT_DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        AUDIT_DB_PATH,
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
        trusted_audit_events (
            sequence INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            task_handle TEXT NOT NULL,
            user TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_trusted_audit_task
        ON trusted_audit_events(
            task_handle,
            sequence
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_trusted_audit_type
        ON trusted_audit_events(
            event_type,
            sequence
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS
        trusted_audit_head (
            head_id INTEGER PRIMARY KEY,
            last_sequence INTEGER NOT NULL,
            last_hash TEXT NOT NULL,
            total_records INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT OR IGNORE INTO
        trusted_audit_head (
            head_id,
            last_sequence,
            last_hash,
            total_records,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            CHAIN_HEAD_ID,
            0,
            GENESIS_HASH,
            0,
            _now_iso(),
        ),
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS
        trusted_audit_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL,
            total_records INTEGER NOT NULL,
            last_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            key_id TEXT NOT NULL,
            public_key_sha256 TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            checkpoint_json TEXT NOT NULL,
            signature TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_trusted_audit_checkpoint_sequence
        ON trusted_audit_checkpoints(
            sequence,
            created_at
        )
        """
    )

    return connection


def append_trusted_audit_event(
    *,
    task_handle: str,
    user: str,
    event_type: str,
    payload: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    task_handle = str(
        task_handle
    ).strip()

    user = str(user).strip()

    event_type = str(
        event_type
    ).strip()

    if not task_handle:
        raise ValueError(
            "task_handle is required"
        )

    if not user:
        raise ValueError(
            "user is required"
        )

    if not event_type:
        raise ValueError(
            "event_type is required"
        )

    sanitized_payload = (
        sanitize_audit_payload(
            dict(payload or {})
        )
    )

    payload_json = _canonical_json(
        sanitized_payload
    )

    event_id = (
        "aud_"
        + secrets.token_urlsafe(24)
    )

    created_at = _now_iso()

    connection = connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        head = connection.execute(
            """
            SELECT
                last_sequence,
                last_hash,
                total_records
            FROM trusted_audit_head
            WHERE head_id = ?
            """,
            (CHAIN_HEAD_ID,),
        ).fetchone()

        if head is None:
            raise TrustedAuditError(
                "Audit chain head is missing"
            )

        sequence = int(
            head["last_sequence"]
        ) + 1

        prev_hash = str(
            head["last_hash"]
        )

        record_hash = (
            _calculate_record_hash(
                sequence=sequence,
                event_id=event_id,
                task_handle=task_handle,
                user=user,
                event_type=event_type,
                payload_json=(
                    payload_json
                ),
                created_at=created_at,
                prev_hash=prev_hash,
            )
        )

        connection.execute(
            """
            INSERT INTO
            trusted_audit_events (
                sequence,
                event_id,
                task_handle,
                user,
                event_type,
                payload_json,
                created_at,
                prev_hash,
                record_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                event_id,
                task_handle,
                user,
                event_type,
                payload_json,
                created_at,
                prev_hash,
                record_hash,
            ),
        )

        connection.execute(
            """
            UPDATE trusted_audit_head
            SET
                last_sequence = ?,
                last_hash = ?,
                total_records = ?,
                updated_at = ?
            WHERE head_id = ?
            """,
            (
                sequence,
                record_hash,
                int(
                    head[
                        "total_records"
                    ]
                )
                + 1,
                created_at,
                CHAIN_HEAD_ID,
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "sequence": sequence,
        "event_id": event_id,
        "task_handle": (
            task_handle
        ),
        "user": user,
        "event_type": event_type,
        "payload": sanitized_payload,
        "created_at": created_at,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }


def get_trusted_audit_events(
    *,
    task_handle: Optional[
        str
    ] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    normalized_limit = max(
        1,
        min(int(limit), 1000),
    )

    connection = connect()

    try:
        if task_handle:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    event_id,
                    task_handle,
                    user,
                    event_type,
                    payload_json,
                    created_at,
                    prev_hash,
                    record_hash
                FROM trusted_audit_events
                WHERE task_handle = ?
                ORDER BY sequence ASC
                LIMIT ?
                """,
                (
                    str(
                        task_handle
                    ).strip(),
                    normalized_limit,
                ),
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    event_id,
                    task_handle,
                    user,
                    event_type,
                    payload_json,
                    created_at,
                    prev_hash,
                    record_hash
                FROM trusted_audit_events
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (
                    normalized_limit,
                ),
            ).fetchall()

            rows = list(
                reversed(rows)
            )

        result: List[
            Dict[str, Any]
        ] = []

        for row in rows:
            try:
                payload = json.loads(
                    row["payload_json"]
                )
            except json.JSONDecodeError:
                payload = {
                    "_corrupted": True,
                    "_raw": str(
                        row[
                            "payload_json"
                        ]
                    ),
                }

            result.append(
                {
                    "sequence": int(
                        row["sequence"]
                    ),
                    "event_id": str(
                        row["event_id"]
                    ),
                    "task_handle": str(
                        row[
                            "task_handle"
                        ]
                    ),
                    "user": str(
                        row["user"]
                    ),
                    "event_type": str(
                        row["event_type"]
                    ),
                    "payload": payload,
                    "created_at": str(
                        row["created_at"]
                    ),
                    "prev_hash": str(
                        row["prev_hash"]
                    ),
                    "record_hash": str(
                        row["record_hash"]
                    ),
                }
            )

        return result

    finally:
        connection.close()


def verify_trusted_audit_chain(
) -> Dict[str, Any]:
    connection = connect()

    try:
        head = connection.execute(
            """
            SELECT
                last_sequence,
                last_hash,
                total_records,
                updated_at
            FROM trusted_audit_head
            WHERE head_id = ?
            """,
            (CHAIN_HEAD_ID,),
        ).fetchone()

        rows = connection.execute(
            """
            SELECT
                sequence,
                event_id,
                task_handle,
                user,
                event_type,
                payload_json,
                created_at,
                prev_hash,
                record_hash
            FROM trusted_audit_events
            ORDER BY sequence ASC
            """
        ).fetchall()

    finally:
        connection.close()

    if head is None:
        return {
            "valid": False,
            "checked_records": 0,
            "broken_sequence": None,
            "reason": (
                "Audit chain head is missing."
            ),
        }

    head_total = int(
        head["total_records"]
    )

    if len(rows) != head_total:
        return {
            "valid": False,
            "checked_records": 0,
            "broken_sequence": None,
            "reason": (
                "Stored record count does not "
                "match the trusted chain head. "
                "Records may have been deleted "
                "or inserted."
            ),
            "expected_records": (
                head_total
            ),
            "actual_records": len(rows),
        }

    previous_hash = GENESIS_HASH
    checked_records = 0

    for row in rows:
        sequence = int(
            row["sequence"]
        )

        prev_hash = str(
            row["prev_hash"]
        )

        record_hash = str(
            row["record_hash"]
        )

        if prev_hash != previous_hash:
            return {
                "valid": False,
                "checked_records": (
                    checked_records
                ),
                "broken_sequence": (
                    sequence
                ),
                "reason": (
                    "prev_hash does not match "
                    "the preceding record."
                ),
            }

        payload_json = str(
            row["payload_json"]
        )

        try:
            parsed_payload = (
                json.loads(
                    payload_json
                )
            )

        except json.JSONDecodeError:
            return {
                "valid": False,
                "checked_records": (
                    checked_records
                ),
                "broken_sequence": (
                    sequence
                ),
                "reason": (
                    "payload_json is not "
                    "valid JSON."
                ),
            }

        if (
            _canonical_json(
                parsed_payload
            )
            != payload_json
        ):
            return {
                "valid": False,
                "checked_records": (
                    checked_records
                ),
                "broken_sequence": (
                    sequence
                ),
                "reason": (
                    "payload_json is not in "
                    "canonical form."
                ),
            }

        recalculated = (
            _calculate_record_hash(
                sequence=sequence,
                event_id=str(
                    row["event_id"]
                ),
                task_handle=str(
                    row["task_handle"]
                ),
                user=str(row["user"]),
                event_type=str(
                    row["event_type"]
                ),
                payload_json=(
                    payload_json
                ),
                created_at=str(
                    row["created_at"]
                ),
                prev_hash=prev_hash,
            )
        )

        if recalculated != record_hash:
            return {
                "valid": False,
                "checked_records": (
                    checked_records
                ),
                "broken_sequence": (
                    sequence
                ),
                "reason": (
                    "record_hash verification "
                    "failed. The audit record "
                    "may have been modified."
                ),
            }

        previous_hash = record_hash
        checked_records += 1

    if rows:
        actual_last_sequence = int(
            rows[-1]["sequence"]
        )

        actual_last_hash = str(
            rows[-1]["record_hash"]
        )

    else:
        actual_last_sequence = 0
        actual_last_hash = (
            GENESIS_HASH
        )

    if (
        actual_last_sequence
        != int(
            head["last_sequence"]
        )
        or actual_last_hash
        != str(head["last_hash"])
    ):
        return {
            "valid": False,
            "checked_records": (
                checked_records
            ),
            "broken_sequence": (
                actual_last_sequence
                or None
            ),
            "reason": (
                "The final audit record does "
                "not match the trusted chain "
                "head. Tail records may have "
                "been deleted or replaced."
            ),
        }

    return {
        "valid": True,
        "checked_records": (
            checked_records
        ),
        "broken_sequence": None,
        "total_records": head_total,
        "last_sequence": int(
            head["last_sequence"]
        ),
        "last_hash": str(
            head["last_hash"]
        ),
        "reason": (
            "Trusted audit chain "
            "verification passed."
        ),
    }


# ============================================================
# Signed audit checkpoints
# ============================================================

AUDIT_CHECKPOINT_SCHEMA = (
    "agentguard.audit_checkpoint.v1"
)

AUDIT_CHECKPOINT_ALGORITHM = (
    "Ed25519"
)

AUDIT_PRIVATE_KEY_ENV = (
    "AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_PEM"
)

AUDIT_PUBLIC_KEY_ENV = (
    "AGENTGUARD_AUDIT_SIGNING_PUBLIC_KEY_PEM"
)

AUDIT_KEY_ID_ENV = (
    "AGENTGUARD_AUDIT_SIGNING_KEY_ID"
)

AUDIT_REQUIRE_CHECKPOINT_ENV = (
    "AGENTGUARD_REQUIRE_AUDIT_CHECKPOINT"
)


def _b64url_encode(
    value: bytes,
) -> str:
    return (
        base64.urlsafe_b64encode(value)
        .decode("ascii")
        .rstrip("=")
    )


def _b64url_decode(
    value: str,
) -> bytes:
    padded = str(value) + (
        "=" * (-len(str(value)) % 4)
    )

    return base64.urlsafe_b64decode(
        padded.encode("ascii")
    )


def _env_enabled(
    name: str,
) -> bool:
    return os.getenv(
        name,
        "",
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _checkpoint_key_id() -> str:
    return (
        os.getenv(
            AUDIT_KEY_ID_ENV,
            "agentguard-audit-ed25519-v1",
        ).strip()
        or "agentguard-audit-ed25519-v1"
    )


def _load_checkpoint_private_key(
) -> Ed25519PrivateKey:
    raw_pem = os.getenv(
        AUDIT_PRIVATE_KEY_ENV,
        "",
    ).strip()

    if not raw_pem:
        raise TrustedAuditError(
            "缺少审计签名私钥环境变量："
            + AUDIT_PRIVATE_KEY_ENV
        )

    try:
        key = (
            serialization
            .load_pem_private_key(
                raw_pem.encode("utf-8"),
                password=None,
            )
        )

    except Exception as exc:
        raise TrustedAuditError(
            "审计签名私钥无法解析。"
        ) from exc

    if not isinstance(
        key,
        Ed25519PrivateKey,
    ):
        raise TrustedAuditError(
            "审计签名私钥必须是 Ed25519。"
        )

    return key


def _load_checkpoint_public_key(
) -> Ed25519PublicKey:
    raw_public_pem = os.getenv(
        AUDIT_PUBLIC_KEY_ENV,
        "",
    ).strip()

    if raw_public_pem:
        try:
            key = (
                serialization
                .load_pem_public_key(
                    raw_public_pem.encode(
                        "utf-8"
                    )
                )
            )

        except Exception as exc:
            raise TrustedAuditError(
                "审计签名公钥无法解析。"
            ) from exc

        if not isinstance(
            key,
            Ed25519PublicKey,
        ):
            raise TrustedAuditError(
                "审计签名公钥必须是 Ed25519。"
            )

        return key

    # 服务端持有私钥时，可自动推导公钥。
    raw_private_pem = os.getenv(
        AUDIT_PRIVATE_KEY_ENV,
        "",
    ).strip()

    if raw_private_pem:
        return (
            _load_checkpoint_private_key()
            .public_key()
        )

    raise TrustedAuditError(
        "缺少审计签名公钥环境变量："
        + AUDIT_PUBLIC_KEY_ENV
    )


def _public_key_fingerprint(
    public_key: Ed25519PublicKey,
) -> str:
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return hashlib.sha256(
        raw_key
    ).hexdigest()


def _checkpoint_body(
    *,
    sequence: int,
    total_records: int,
    last_hash: str,
    created_at: str,
    key_id: str,
    public_key_sha256: str,
) -> Dict[str, Any]:
    return {
        "schema": (
            AUDIT_CHECKPOINT_SCHEMA
        ),
        "sequence": int(sequence),
        "total_records": int(
            total_records
        ),
        "last_hash": str(last_hash),
        "created_at": str(created_at),
        "key_id": str(key_id),
        "public_key_sha256": str(
            public_key_sha256
        ),
    }


def create_signed_audit_checkpoint(
) -> Dict[str, Any]:
    """
    对当前可信审计链头创建 Ed25519 签名。

    返回值可以保存到独立服务器、对象存储、
    比赛证据包或其他不可由业务数据库修改的位置。
    """
    chain_result = (
        verify_trusted_audit_chain()
    )

    if not chain_result.get(
        "valid",
        False,
    ):
        raise TrustedAuditIntegrityError(
            "审计链验证失败，不能创建签名检查点："
            + str(
                chain_result.get(
                    "reason",
                    ""
                )
            )
        )

    private_key = (
        _load_checkpoint_private_key()
    )

    public_key = (
        private_key.public_key()
    )

    public_fingerprint = (
        _public_key_fingerprint(
            public_key
        )
    )

    checkpoint_id = (
        "audchk_"
        + secrets.token_urlsafe(24)
    )

    created_at = _now_iso()

    connection = connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        head = connection.execute(
            """
            SELECT
                last_sequence,
                last_hash,
                total_records
            FROM trusted_audit_head
            WHERE head_id = ?
            """,
            (CHAIN_HEAD_ID,),
        ).fetchone()

        if head is None:
            raise TrustedAuditError(
                "Audit chain head is missing"
            )

        body = _checkpoint_body(
            sequence=int(
                head["last_sequence"]
            ),
            total_records=int(
                head["total_records"]
            ),
            last_hash=str(
                head["last_hash"]
            ),
            created_at=created_at,
            key_id=(
                _checkpoint_key_id()
            ),
            public_key_sha256=(
                public_fingerprint
            ),
        )

        checkpoint_json = (
            _canonical_json(body)
        )

        signature = _b64url_encode(
            private_key.sign(
                checkpoint_json.encode(
                    "utf-8"
                )
            )
        )

        connection.execute(
            """
            INSERT INTO
            trusted_audit_checkpoints (
                checkpoint_id,
                sequence,
                total_records,
                last_hash,
                created_at,
                key_id,
                public_key_sha256,
                algorithm,
                checkpoint_json,
                signature
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint_id,
                body["sequence"],
                body["total_records"],
                body["last_hash"],
                body["created_at"],
                body["key_id"],
                body[
                    "public_key_sha256"
                ],
                (
                    AUDIT_CHECKPOINT_ALGORITHM
                ),
                checkpoint_json,
                signature,
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "checkpoint_id": (
            checkpoint_id
        ),
        "algorithm": (
            AUDIT_CHECKPOINT_ALGORITHM
        ),
        "checkpoint": body,
        "signature": signature,
    }


def get_latest_signed_audit_checkpoint(
) -> Optional[Dict[str, Any]]:
    connection = connect()

    try:
        row = connection.execute(
            """
            SELECT
                checkpoint_id,
                algorithm,
                checkpoint_json,
                signature
            FROM trusted_audit_checkpoints
            ORDER BY
                sequence DESC,
                created_at DESC
            LIMIT 1
            """
        ).fetchone()

    finally:
        connection.close()

    if row is None:
        return None

    try:
        body = json.loads(
            row["checkpoint_json"]
        )

    except json.JSONDecodeError:
        body = {
            "_corrupted": True,
            "_raw": str(
                row["checkpoint_json"]
            ),
        }

    return {
        "checkpoint_id": str(
            row["checkpoint_id"]
        ),
        "algorithm": str(
            row["algorithm"]
        ),
        "checkpoint": body,
        "signature": str(
            row["signature"]
        ),
    }


def verify_signed_audit_checkpoint(
    checkpoint_envelope: Dict[str, Any],
    *,
    require_current_head: bool = False,
) -> Dict[str, Any]:
    """
    验证检查点签名，并确认它锚定的记录仍存在于审计链。

    历史检查点在后续新增日志后仍然有效；
    current_head_match 用于判断它是否覆盖最新链头。
    """
    if not isinstance(
        checkpoint_envelope,
        dict,
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint envelope "
                "must be an object."
            ),
        }

    algorithm = str(
        checkpoint_envelope.get(
            "algorithm",
            "",
        )
    )

    if (
        algorithm
        != AUDIT_CHECKPOINT_ALGORITHM
    ):
        return {
            "valid": False,
            "reason": (
                "Unsupported checkpoint "
                "signature algorithm."
            ),
        }

    body = checkpoint_envelope.get(
        "checkpoint"
    )

    if not isinstance(body, dict):
        return {
            "valid": False,
            "reason": (
                "Checkpoint body is missing."
            ),
        }

    if (
        body.get("schema")
        != AUDIT_CHECKPOINT_SCHEMA
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint schema is invalid."
            ),
        }

    try:
        sequence = int(
            body.get("sequence")
        )

        total_records = int(
            body.get("total_records")
        )

    except (
        TypeError,
        ValueError,
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint sequence "
                "is invalid."
            ),
        }

    if (
        sequence < 0
        or total_records < 0
        or sequence != total_records
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint record count "
                "is inconsistent."
            ),
        }

    try:
        public_key = (
            _load_checkpoint_public_key()
        )

    except TrustedAuditError as exc:
        return {
            "valid": False,
            "reason": str(exc),
        }

    actual_fingerprint = (
        _public_key_fingerprint(
            public_key
        )
    )

    expected_fingerprint = str(
        body.get(
            "public_key_sha256",
            "",
        )
    )

    if (
        actual_fingerprint
        != expected_fingerprint
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint public key "
                "fingerprint mismatch."
            ),
        }

    try:
        signature = _b64url_decode(
            str(
                checkpoint_envelope.get(
                    "signature",
                    "",
                )
            )
        )

        public_key.verify(
            signature,
            _canonical_json(
                body
            ).encode("utf-8"),
        )

    except (
        InvalidSignature,
        ValueError,
        TypeError,
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint signature "
                "verification failed."
            ),
        }

    chain_result = (
        verify_trusted_audit_chain()
    )

    if not chain_result.get(
        "valid",
        False,
    ):
        return {
            "valid": False,
            "reason": (
                "Audit chain verification "
                "failed before checkpoint "
                "validation."
            ),
            "chain": chain_result,
        }

    if sequence == 0:
        anchored_hash = GENESIS_HASH

    else:
        connection = connect()

        try:
            row = connection.execute(
                """
                SELECT record_hash
                FROM trusted_audit_events
                WHERE sequence = ?
                """,
                (sequence,),
            ).fetchone()

        finally:
            connection.close()

        if row is None:
            return {
                "valid": False,
                "reason": (
                    "The audit record anchored "
                    "by the checkpoint is missing."
                ),
            }

        anchored_hash = str(
            row["record_hash"]
        )

    if (
        anchored_hash
        != str(body.get("last_hash", ""))
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint hash does not "
                "match the anchored record."
            ),
        }

    current_head_match = (
        int(
            chain_result.get(
                "last_sequence",
                -1,
            )
        )
        == sequence
        and str(
            chain_result.get(
                "last_hash",
                "",
            )
        )
        == str(
            body.get(
                "last_hash",
                "",
            )
        )
    )

    if (
        require_current_head
        and not current_head_match
    ):
        return {
            "valid": False,
            "reason": (
                "Checkpoint is valid but does "
                "not cover the current chain head."
            ),
            "current_head_match": False,
        }

    return {
        "valid": True,
        "reason": (
            "Signed audit checkpoint "
            "verification passed."
        ),
        "checkpoint_id": (
            checkpoint_envelope.get(
                "checkpoint_id"
            )
        ),
        "key_id": body.get("key_id"),
        "sequence": sequence,
        "total_records": (
            total_records
        ),
        "last_hash": body.get(
            "last_hash"
        ),
        "public_key_sha256": (
            actual_fingerprint
        ),
        "current_head_match": (
            current_head_match
        ),
        "current_last_sequence": (
            chain_result.get(
                "last_sequence"
            )
        ),
    }


def verify_trusted_audit_evidence(
    *,
    require_checkpoint: Optional[
        bool
    ] = None,
) -> Dict[str, Any]:
    """
    同时验证：
    1. SQLite 审计哈希链；
    2. 最新 Ed25519 签名检查点。
    """
    if require_checkpoint is None:
        require_checkpoint = (
            _env_enabled(
                AUDIT_REQUIRE_CHECKPOINT_ENV
            )
        )

    chain_result = (
        verify_trusted_audit_chain()
    )

    if not chain_result.get(
        "valid",
        False,
    ):
        return {
            "valid": False,
            "chain": chain_result,
            "checkpoint": None,
            "reason": (
                "Trusted audit chain "
                "verification failed."
            ),
        }

    checkpoint = (
        get_latest_signed_audit_checkpoint()
    )

    if checkpoint is None:
        return {
            "valid": (
                not require_checkpoint
            ),
            "chain": chain_result,
            "checkpoint": None,
            "checkpoint_required": bool(
                require_checkpoint
            ),
            "reason": (
                "No signed checkpoint exists."
                if require_checkpoint
                else (
                    "Audit chain is valid, "
                    "but no signed checkpoint "
                    "has been created."
                )
            ),
        }

    checkpoint_result = (
        verify_signed_audit_checkpoint(
            checkpoint
        )
    )

    checkpoint_records = int(
        checkpoint.get(
            "checkpoint",
            {},
        ).get(
            "total_records",
            0,
        )
        or 0
    )

    current_records = int(
        chain_result.get(
            "total_records",
            0,
        )
        or 0
    )

    return {
        "valid": bool(
            chain_result.get("valid")
            and checkpoint_result.get(
                "valid"
            )
        ),
        "chain": chain_result,
        "checkpoint": (
            checkpoint_result
        ),
        "checkpoint_required": bool(
            require_checkpoint
        ),
        "checkpointed_records": (
            checkpoint_records
        ),
        "uncheckpointed_records": max(
            0,
            current_records
            - checkpoint_records,
        ),
        "reason": (
            "Audit chain and signed "
            "checkpoint are valid."
            if checkpoint_result.get(
                "valid"
            )
            else (
                "Signed audit checkpoint "
                "verification failed."
            )
        ),
    }
