from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.exceptions import (
    InvalidSignature,
)

from cryptography.hazmat.primitives import (
    serialization,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from backend.audit.decision_snapshot import (
    verify_decision_snapshot,
)
from backend.audit.trusted_audit_store import (
    GENESIS_HASH,
    connect as audit_connect,
    sanitize_audit_payload,
    verify_trusted_audit_chain,
)
from backend.revocation.revocation_store import (
    list_revocations,
)
from backend.task_session.task_store import (
    load_session,
)


EVIDENCE_BUNDLE_VERSION = 2

SUPPORTED_EVIDENCE_BUNDLE_VERSIONS = {
    1,
    2,
}

EVIDENCE_SIGNATURE_SCHEMA = (
    "agentguard.evidence_bundle_signature.v1"
)

EVIDENCE_SIGNATURE_ALGORITHM = (
    "Ed25519"
)

EVIDENCE_SIGNATURE_REQUIRED_ENV = (
    "AGENTGUARD_REQUIRE_EVIDENCE_BUNDLE_SIGNATURE"
)

EVIDENCE_PRIVATE_KEY_ENV = (
    "AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_PEM"
)

EVIDENCE_PUBLIC_KEY_ENV = (
    "AGENTGUARD_AUDIT_SIGNING_PUBLIC_KEY_PEM"
)

EVIDENCE_KEY_ID_ENV = (
    "AGENTGUARD_AUDIT_SIGNING_KEY_ID"
)


class EvidenceBundleError(RuntimeError):
    """Base error for evidence bundle operations."""


class EvidenceBundleIntegrityError(
    EvidenceBundleError
):
    """The supplied evidence bundle is invalid."""


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


def _sha256_value(
    value: Any,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            value
        ).encode("utf-8")
    ).hexdigest()


def _sha256_text(
    value: str,
) -> str:
    return hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()


def _environment_enabled(
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


def _evidence_signature_required(
) -> bool:
    if _environment_enabled(
        EVIDENCE_SIGNATURE_REQUIRED_ENV
    ):
        return True

    return (
        os.getenv(
            "AGENTGUARD_MODE",
            "demo",
        ).strip().lower()
        == "competition"
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
    normalized = str(value or "")

    padded = normalized + (
        "=" * (-len(normalized) % 4)
    )

    return base64.urlsafe_b64decode(
        padded.encode("ascii")
    )


def _load_evidence_private_key(
) -> Ed25519PrivateKey:
    private_pem = os.getenv(
        EVIDENCE_PRIVATE_KEY_ENV,
        "",
    ).strip()

    if not private_pem:
        raise EvidenceBundleError(
            "证据包需要签名，但缺少环境变量："
            + EVIDENCE_PRIVATE_KEY_ENV
        )

    try:
        private_key = (
            serialization
            .load_pem_private_key(
                private_pem.encode(
                    "utf-8"
                ),
                password=None,
            )
        )

    except Exception as exc:
        raise EvidenceBundleError(
            "证据包 Ed25519 私钥无法解析。"
        ) from exc

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise EvidenceBundleError(
            "证据包签名私钥必须是 "
            "Ed25519 私钥。"
        )

    return private_key


def _load_evidence_public_key(
    public_key_pem: str = "",
) -> tuple[
    Optional[Ed25519PublicKey],
    str,
]:
    configured_pem = (
        str(public_key_pem or "").strip()
        or os.getenv(
            EVIDENCE_PUBLIC_KEY_ENV,
            "",
        ).strip()
    )

    if not configured_pem:
        return (
            None,
            "缺少可信 Ed25519 公钥。",
        )

    try:
        public_key = (
            serialization
            .load_pem_public_key(
                configured_pem.encode(
                    "utf-8"
                )
            )
        )

    except Exception:
        return (
            None,
            "可信 Ed25519 公钥无法解析。",
        )

    if not isinstance(
        public_key,
        Ed25519PublicKey,
    ):
        return (
            None,
            "可信公钥不是 Ed25519 公钥。",
        )

    return (
        public_key,
        "",
    )


def _public_key_fingerprint(
    public_key: Ed25519PublicKey,
) -> str:
    raw_public_key = (
        public_key.public_bytes(
            encoding=(
                serialization.Encoding.Raw
            ),
            format=(
                serialization
                .PublicFormat
                .Raw
            ),
        )
    )

    return hashlib.sha256(
        raw_public_key
    ).hexdigest()


def _build_bundle_signature(
    *,
    bundle_hash: str,
    bundle_version: int,
) -> Dict[str, Any]:
    private_key = (
        _load_evidence_private_key()
    )

    public_key = (
        private_key.public_key()
    )

    key_id = (
        os.getenv(
            EVIDENCE_KEY_ID_ENV,
            "agentguard-audit-ed25519-v1",
        ).strip()
        or "agentguard-audit-ed25519-v1"
    )

    payload = {
        "schema": (
            EVIDENCE_SIGNATURE_SCHEMA
        ),
        "algorithm": (
            EVIDENCE_SIGNATURE_ALGORITHM
        ),
        "bundle_version": int(
            bundle_version
        ),
        "bundle_hash": str(
            bundle_hash
        ),
        "signed_at": _now_iso(),
        "key_id": key_id,
        "public_key_sha256": (
            _public_key_fingerprint(
                public_key
            )
        ),
    }

    signature = private_key.sign(
        _canonical_json(
            payload
        ).encode("utf-8")
    )

    return {
        "payload": payload,
        "signature": (
            _b64url_encode(signature)
        ),
    }


def _verify_bundle_signature(
    *,
    signature_envelope: Any,
    bundle_hash: str,
    bundle_version: int,
    public_key_pem: str = "",
) -> Dict[str, Any]:
    if not isinstance(
        signature_envelope,
        dict,
    ):
        return {
            "present": False,
            "valid": False,
            "key_id": "",
            "public_key_sha256": "",
            "reason": (
                "Evidence bundle signature "
                "is not present."
            ),
        }

    payload = signature_envelope.get(
        "payload"
    )

    if not isinstance(payload, dict):
        return {
            "present": True,
            "valid": False,
            "key_id": "",
            "public_key_sha256": "",
            "reason": (
                "Evidence bundle signature "
                "payload is missing."
            ),
        }

    key_id = str(
        payload.get(
            "key_id",
            "",
        )
        or ""
    )

    expected_fingerprint = str(
        payload.get(
            "public_key_sha256",
            "",
        )
        or ""
    )

    if (
        payload.get("schema")
        != EVIDENCE_SIGNATURE_SCHEMA
    ):
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                expected_fingerprint
            ),
            "reason": (
                "Evidence signature schema "
                "is invalid."
            ),
        }

    if (
        payload.get("algorithm")
        != EVIDENCE_SIGNATURE_ALGORITHM
    ):
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                expected_fingerprint
            ),
            "reason": (
                "Evidence signature algorithm "
                "is invalid."
            ),
        }

    try:
        signed_bundle_version = int(
            payload.get(
                "bundle_version",
                0,
            )
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):
        signed_bundle_version = 0

    if (
        signed_bundle_version
        != int(bundle_version)
    ):
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                expected_fingerprint
            ),
            "reason": (
                "Signed evidence bundle "
                "version does not match."
            ),
        }

    if (
        str(
            payload.get(
                "bundle_hash",
                "",
            )
            or ""
        )
        != str(bundle_hash)
    ):
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                expected_fingerprint
            ),
            "reason": (
                "Signed bundle hash does "
                "not match the evidence bundle."
            ),
        }

    if not key_id:
        return {
            "present": True,
            "valid": False,
            "key_id": "",
            "public_key_sha256": (
                expected_fingerprint
            ),
            "reason": (
                "Evidence signature Key ID "
                "is missing."
            ),
        }

    public_key, public_key_error = (
        _load_evidence_public_key(
            public_key_pem
        )
    )

    if public_key is None:
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                expected_fingerprint
            ),
            "reason": public_key_error,
        }

    actual_fingerprint = (
        _public_key_fingerprint(
            public_key
        )
    )

    if not hmac.compare_digest(
        actual_fingerprint,
        expected_fingerprint,
    ):
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                actual_fingerprint
            ),
            "reason": (
                "Evidence signature public-key "
                "fingerprint does not match."
            ),
        }

    try:
        signature = _b64url_decode(
            str(
                signature_envelope.get(
                    "signature",
                    "",
                )
                or ""
            )
        )

        public_key.verify(
            signature,
            _canonical_json(
                payload
            ).encode("utf-8"),
        )

    except (
        InvalidSignature,
        ValueError,
        TypeError,
    ):
        return {
            "present": True,
            "valid": False,
            "key_id": key_id,
            "public_key_sha256": (
                actual_fingerprint
            ),
            "reason": (
                "Evidence bundle Ed25519 "
                "signature verification failed."
            ),
        }

    return {
        "present": True,
        "valid": True,
        "key_id": key_id,
        "public_key_sha256": (
            actual_fingerprint
        ),
        "signed_at": str(
            payload.get(
                "signed_at",
                "",
            )
            or ""
        ),
        "reason": (
            "Evidence bundle Ed25519 "
            "signature verification passed."
        ),
    }


def _load_all_task_events(
    *,
    task_handle: str,
) -> List[Dict[str, Any]]:
    connection = audit_connect()

    try:
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
            """,
            (task_handle,),
        ).fetchall()

    finally:
        connection.close()

    events: List[
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
                    row["payload_json"]
                ),
            }

        events.append(
            {
                "sequence": int(
                    row["sequence"]
                ),
                "event_id": str(
                    row["event_id"]
                ),
                "task_handle": str(
                    row["task_handle"]
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

    return events


def _load_global_chain_proof(
) -> Dict[str, Any]:
    connection = audit_connect()

    try:
        head = connection.execute(
            """
            SELECT
                last_sequence,
                last_hash,
                total_records,
                updated_at
            FROM trusted_audit_head
            WHERE head_id = 1
            """
        ).fetchone()

        rows = connection.execute(
            """
            SELECT
                sequence,
                prev_hash,
                record_hash
            FROM trusted_audit_events
            ORDER BY sequence ASC
            """
        ).fetchall()

    finally:
        connection.close()

    if head is None:
        raise EvidenceBundleError(
            "Trusted audit chain head "
            "was not found."
        )

    proof = [
        {
            "sequence": int(
                row["sequence"]
            ),
            "prev_hash": str(
                row["prev_hash"]
            ),
            "record_hash": str(
                row["record_hash"]
            ),
        }
        for row in rows
    ]

    return {
        "head": {
            "last_sequence": int(
                head["last_sequence"]
            ),
            "last_hash": str(
                head["last_hash"]
            ),
            "total_records": int(
                head["total_records"]
            ),
            "updated_at": str(
                head["updated_at"]
            ),
        },
        "proof": proof,
    }


def _runtime_step_summary(
    step: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "step_index": int(
            step.get(
                "step_index",
                0,
            )
            or 0
        ),
        "tool": str(
            step.get("tool")
            or ""
        ),
        "decision": str(
            step.get("decision")
            or ""
        ),
        "risk_score": int(
            step.get(
                "risk_score",
                0,
            )
            or 0
        ),
        "executed": bool(
            step.get("executed")
        ),
        "blocked": bool(
            step.get("blocked")
        ),
        "requires_confirmation": bool(
            step.get(
                "requires_confirmation"
            )
        ),
        "confirmed": bool(
            step.get("confirmed")
        ),
        "confirmation_status": str(
            step.get(
                "confirmation_status"
            )
            or ""
        ),
        "input_from_steps": [
            int(value)
            for value in (
                step.get(
                    "input_from_steps"
                )
                or []
            )
        ],
        "input_labels": [
            str(value)
            for value in (
                step.get(
                    "input_labels"
                )
                or []
            )
        ],
        "output_labels": [
            str(value)
            for value in (
                step.get(
                    "output_labels"
                )
                or []
            )
        ],
        "reason": [
            str(value)
            for value in (
                step.get("reason")
                or []
            )
        ],
    }


def _runtime_summary(
    runtime_state: Any,
) -> Dict[str, Any]:
    if not isinstance(
        runtime_state,
        dict,
    ):
        return {
            "present": False,
            "current_step": 0,
            "used_risk": 0,
            "final_decision": "",
            "pending_confirm_steps": [],
            "steps": [],
        }

    raw_steps = (
        runtime_state.get("steps")
        or []
    )

    steps = [
        _runtime_step_summary(
            dict(step)
        )
        for step in raw_steps
        if isinstance(step, dict)
    ]

    return {
        "present": True,
        "current_step": int(
            runtime_state.get(
                "current_step",
                0,
            )
            or 0
        ),
        "used_risk": int(
            runtime_state.get(
                "used_risk",
                0,
            )
            or 0
        ),
        "final_decision": str(
            runtime_state.get(
                "final_decision"
            )
            or ""
        ),
        "pending_confirm_steps": [
            int(value)
            for value in (
                runtime_state.get(
                    "pending_confirm_steps"
                )
                or []
            )
        ],
        "steps": steps,
    }


def _task_snapshot(
    *,
    task_handle: str,
    session: Any,
    version: int,
) -> Dict[str, Any]:
    contract = dict(
        getattr(
            session,
            "contract",
            {},
        )
        or {}
    )

    if (
        not contract
        and isinstance(
            getattr(
                session,
                "runtime_state",
                None,
            ),
            dict,
        )
    ):
        runtime_contract = (
            session.runtime_state.get(
                "contract"
            )
            or {}
        )

        if isinstance(
            runtime_contract,
            dict,
        ):
            contract = dict(
                runtime_contract
            )

    snapshot = {
        "task_handle": task_handle,
        "task_owner": str(
            getattr(
                session,
                "user",
                "",
            )
            or ""
        ),
        "task_version": int(
            version
        ),
        "session_id": str(
            getattr(
                session,
                "session_id",
                "",
            )
            or ""
        ),
        "agent_type": str(
            getattr(
                session,
                "agent_type",
                "",
            )
            or ""
        ),
        "original_task_sha256": (
            _sha256_text(
                str(
                    getattr(
                        session,
                        "original_input",
                        "",
                    )
                    or ""
                )
            )
        ),
        "contract": contract,
        "runtime_summary": (
            _runtime_summary(
                getattr(
                    session,
                    "runtime_state",
                    None,
                )
            )
        ),
    }

    return sanitize_audit_payload(
        snapshot
    )


def _audit_record_hash(
    event: Dict[str, Any],
) -> str:
    payload_json = _canonical_json(
        event.get(
            "payload",
            {},
        )
    )

    material = {
        "sequence": int(
            event["sequence"]
        ),
        "event_id": str(
            event["event_id"]
        ),
        "task_handle": str(
            event["task_handle"]
        ),
        "user": str(
            event["user"]
        ),
        "event_type": str(
            event["event_type"]
        ),
        "payload_json": payload_json,
        "created_at": str(
            event["created_at"]
        ),
        "prev_hash": str(
            event["prev_hash"]
        ),
    }

    return _sha256_value(
        material
    )


def _snapshot_verifications(
    events: List[
        Dict[str, Any]
    ],
    *,
    compare_current_policy: bool,
) -> List[Dict[str, Any]]:
    results: List[
        Dict[str, Any]
    ] = []

    for event in events:
        payload = event.get(
            "payload"
        )

        if not isinstance(
            payload,
            dict,
        ):
            continue

        snapshot = payload.get(
            "decision_snapshot"
        )

        if not isinstance(
            snapshot,
            dict,
        ):
            continue

        verification = (
            verify_decision_snapshot(
                snapshot,
                compare_current_policy=(
                    compare_current_policy
                ),
            )
        )

        results.append(
            {
                "sequence": int(
                    event["sequence"]
                ),
                "snapshot_hash": str(
                    snapshot.get(
                        "snapshot_hash"
                    )
                    or ""
                ),
                "verification": (
                    verification
                ),
            }
        )

    return results


def build_task_evidence_bundle(
    *,
    task_handle: str,
    expected_user: str = "",
) -> Dict[str, Any]:
    normalized_handle = str(
        task_handle
    ).strip()

    if not normalized_handle:
        raise ValueError(
            "task_handle is required"
        )

    session, version = load_session(
        task_handle=normalized_handle,
        expected_user=(
            str(expected_user).strip()
            or None
        ),
    )

    task_snapshot = _task_snapshot(
        task_handle=normalized_handle,
        session=session,
        version=version,
    )

    task_events = (
        _load_all_task_events(
            task_handle=(
                normalized_handle
            ),
        )
    )

    chain_data = (
        _load_global_chain_proof()
    )

    revocations = list_revocations(
        task_handle=normalized_handle,
        limit=1000,
    )

    snapshot_checks = (
        _snapshot_verifications(
            task_events,
            compare_current_policy=True,
        )
    )

    chain_integrity = (
        verify_trusted_audit_chain()
    )

    body = {
        "bundle_version": (
            EVIDENCE_BUNDLE_VERSION
        ),
        "generated_at": _now_iso(),
        "task": task_snapshot,
        "task_snapshot_hash": (
            _sha256_value(
                task_snapshot
            )
        ),
        "task_event_count": len(
            task_events
        ),
        "task_events": (
            task_events
        ),
        "decision_snapshot_count": len(
            snapshot_checks
        ),
        "decision_snapshot_verifications": (
            snapshot_checks
        ),
        "revocation_count": len(
            revocations
        ),
        "revocations": revocations,
        "global_chain_head": (
            chain_data["head"]
        ),
        "global_chain_proof": (
            chain_data["proof"]
        ),
        "chain_integrity_at_export": (
            chain_integrity
        ),
    }

    # Do not sanitize the completed bundle again.
    #
    # Trusted audit event payloads were already sanitized before
    # their record_hash values were calculated. Sanitizing them a
    # second time could alter an event while leaving record_hash
    # unchanged, which would invalidate offline verification.
    #
    # Other bundle sections are sanitized at their own trust
    # boundaries:
    # - task snapshot: _task_snapshot()
    # - audit payloads: append_trusted_audit_event()
    # - revocation metadata: revoke_subject()
    body["bundle_hash"] = (
        _sha256_value(body)
    )

    private_key_configured = bool(
        os.getenv(
            EVIDENCE_PRIVATE_KEY_ENV,
            "",
        ).strip()
    )

    if (
        _evidence_signature_required()
        or private_key_configured
    ):
        body["bundle_signature"] = (
            _build_bundle_signature(
                bundle_hash=(
                    body["bundle_hash"]
                ),
                bundle_version=(
                    body["bundle_version"]
                ),
            )
        )

    return body


def verify_task_evidence_bundle(
    bundle: Dict[str, Any],
    *,
    require_signature: Optional[
        bool
    ] = None,
    public_key_pem: str = "",
) -> Dict[str, Any]:
    candidate = dict(
        bundle or {}
    )

    signature_envelope = (
        candidate.pop(
            "bundle_signature",
            None,
        )
    )

    stored_bundle_hash = str(
        candidate.pop(
            "bundle_hash",
            "",
        )
        or ""
    )

    recalculated_bundle_hash = (
        _sha256_value(candidate)
    )

    bundle_hash_valid = bool(
        stored_bundle_hash
        and stored_bundle_hash
        == recalculated_bundle_hash
    )

    try:
        bundle_version = int(
            candidate.get(
                "bundle_version",
                0,
            )
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):
        bundle_version = 0

    version_valid = (
        bundle_version
        in SUPPORTED_EVIDENCE_BUNDLE_VERSIONS
    )

    if require_signature is None:
        signature_required = (
            _evidence_signature_required()
        )
    else:
        signature_required = bool(
            require_signature
        )

    signature_result = (
        _verify_bundle_signature(
            signature_envelope=(
                signature_envelope
            ),
            bundle_hash=(
                stored_bundle_hash
            ),
            bundle_version=(
                bundle_version
            ),
            public_key_pem=(
                public_key_pem
            ),
        )
    )

    signature_present = bool(
        signature_result.get(
            "present"
        )
    )

    if signature_present:
        signature_check_valid = bool(
            signature_result.get(
                "valid"
            )
        )
    else:
        signature_check_valid = (
            not signature_required
        )

    task = candidate.get(
        "task"
    )

    if not isinstance(
        task,
        dict,
    ):
        task = {}

    stored_task_hash = str(
        candidate.get(
            "task_snapshot_hash"
        )
        or ""
    )

    task_snapshot_hash_valid = bool(
        stored_task_hash
        and stored_task_hash
        == _sha256_value(task)
    )

    proof = candidate.get(
        "global_chain_proof"
    )

    if not isinstance(
        proof,
        list,
    ):
        proof = []

    head = candidate.get(
        "global_chain_head"
    )

    if not isinstance(
        head,
        dict,
    ):
        head = {}

    proof_valid = True
    proof_reason = (
        "Global chain proof passed."
    )

    previous_hash = GENESIS_HASH

    for expected_sequence, item in enumerate(
        proof,
        start=1,
    ):
        if not isinstance(
            item,
            dict,
        ):
            proof_valid = False
            proof_reason = (
                "Global chain proof contains "
                "a non-object item."
            )
            break

        sequence = int(
            item.get(
                "sequence",
                0,
            )
            or 0
        )

        prev_hash = str(
            item.get(
                "prev_hash"
            )
            or ""
        )

        record_hash = str(
            item.get(
                "record_hash"
            )
            or ""
        )

        if sequence != expected_sequence:
            proof_valid = False
            proof_reason = (
                "Global chain sequence is "
                "not contiguous."
            )
            break

        if prev_hash != previous_hash:
            proof_valid = False
            proof_reason = (
                "Global chain prev_hash "
                "does not match."
            )
            break

        if not record_hash:
            proof_valid = False
            proof_reason = (
                "Global chain record_hash "
                "is missing."
            )
            break

        previous_hash = record_hash

    if proof_valid:
        expected_total = int(
            head.get(
                "total_records",
                0,
            )
            or 0
        )

        expected_last_sequence = int(
            head.get(
                "last_sequence",
                0,
            )
            or 0
        )

        expected_last_hash = str(
            head.get(
                "last_hash"
            )
            or ""
        )

        actual_last_sequence = (
            int(
                proof[-1][
                    "sequence"
                ]
            )
            if proof
            else 0
        )

        actual_last_hash = (
            str(
                proof[-1][
                    "record_hash"
                ]
            )
            if proof
            else GENESIS_HASH
        )

        if (
            expected_total
            != len(proof)
            or expected_last_sequence
            != actual_last_sequence
            or expected_last_hash
            != actual_last_hash
        ):
            proof_valid = False
            proof_reason = (
                "Global chain proof does not "
                "match the captured chain head."
            )

    proof_by_sequence = {
        int(item["sequence"]): item
        for item in proof
        if isinstance(item, dict)
        and "sequence" in item
    }

    task_events = candidate.get(
        "task_events"
    )

    if not isinstance(
        task_events,
        list,
    ):
        task_events = []

    task_handle = str(
        task.get(
            "task_handle"
        )
        or ""
    )

    task_event_hashes_valid = True
    task_event_membership_valid = True
    broken_task_sequence: Optional[
        int
    ] = None

    for event in task_events:
        if not isinstance(
            event,
            dict,
        ):
            task_event_hashes_valid = False
            broken_task_sequence = None
            break

        sequence = int(
            event.get(
                "sequence",
                0,
            )
            or 0
        )

        if (
            str(
                event.get(
                    "task_handle"
                )
                or ""
            )
            != task_handle
        ):
            task_event_hashes_valid = False
            broken_task_sequence = sequence
            break

        recalculated_record_hash = (
            _audit_record_hash(event)
        )

        if (
            recalculated_record_hash
            != str(
                event.get(
                    "record_hash"
                )
                or ""
            )
        ):
            task_event_hashes_valid = False
            broken_task_sequence = sequence
            break

        proof_item = (
            proof_by_sequence.get(
                sequence
            )
        )

        if (
            proof_item is None
            or str(
                proof_item.get(
                    "record_hash"
                )
                or ""
            )
            != str(
                event.get(
                    "record_hash"
                )
                or ""
            )
            or str(
                proof_item.get(
                    "prev_hash"
                )
                or ""
            )
            != str(
                event.get(
                    "prev_hash"
                )
                or ""
            )
        ):
            task_event_membership_valid = False
            broken_task_sequence = sequence
            break

    task_event_count_valid = (
        int(
            candidate.get(
                "task_event_count",
                -1,
            )
            or 0
        )
        == len(task_events)
    )

    snapshot_results = (
        _snapshot_verifications(
            [
                dict(event)
                for event in task_events
                if isinstance(
                    event,
                    dict,
                )
            ],
            compare_current_policy=False,
        )
    )

    decision_snapshots_valid = all(
        bool(
            item["verification"].get(
                "valid"
            )
        )
        for item in snapshot_results
    )

    snapshot_count_valid = (
        int(
            candidate.get(
                "decision_snapshot_count",
                -1,
            )
            or 0
        )
        == len(snapshot_results)
    )

    exported_chain_integrity = (
        candidate.get(
            "chain_integrity_at_export"
        )
    )

    chain_valid_at_export = bool(
        isinstance(
            exported_chain_integrity,
            dict,
        )
        and exported_chain_integrity.get(
            "valid"
        )
        is True
    )

    checks = {
        "bundle_hash_valid": (
            bundle_hash_valid
        ),
        "bundle_version_valid": (
            version_valid
        ),
        "bundle_signature_valid": (
            signature_check_valid
        ),
        "task_snapshot_hash_valid": (
            task_snapshot_hash_valid
        ),
        "global_chain_proof_valid": (
            proof_valid
        ),
        "task_event_hashes_valid": (
            task_event_hashes_valid
        ),
        "task_event_membership_valid": (
            task_event_membership_valid
        ),
        "task_event_count_valid": (
            task_event_count_valid
        ),
        "decision_snapshots_valid": (
            decision_snapshots_valid
        ),
        "decision_snapshot_count_valid": (
            snapshot_count_valid
        ),
        "chain_valid_at_export": (
            chain_valid_at_export
        ),
    }

    valid = all(
        checks.values()
    )

    return {
        "valid": valid,
        **checks,
        "broken_task_sequence": (
            broken_task_sequence
        ),
        "bundle_signature_present": (
            signature_present
        ),
        "bundle_signature_required": (
            signature_required
        ),
        "bundle_signature_key_id": str(
            signature_result.get(
                "key_id",
                "",
            )
            or ""
        ),
        "bundle_signature_public_key_sha256": str(
            signature_result.get(
                "public_key_sha256",
                "",
            )
            or ""
        ),
        "bundle_signature_reason": str(
            signature_result.get(
                "reason",
                "",
            )
            or ""
        ),
        "global_chain_reason": (
            proof_reason
        ),
        "verified_task_event_count": (
            len(task_events)
        ),
        "verified_decision_snapshot_count": (
            len(snapshot_results)
        ),
        "reason": (
            "Task evidence bundle verification passed."
            if valid
            else (
                "Task evidence bundle verification failed."
            )
        ),
    }


def write_task_evidence_bundle(
    *,
    bundle: Dict[str, Any],
    output_path: str | Path,
) -> Path:
    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            bundle,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return path


def load_task_evidence_bundle(
    path: str | Path,
) -> Dict[str, Any]:
    loaded = json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        loaded,
        dict,
    ):
        raise EvidenceBundleError(
            "Evidence bundle must be "
            "a JSON object."
        )

    return loaded


def assert_task_evidence_bundle_valid(
    bundle: Dict[str, Any],
) -> None:
    result = (
        verify_task_evidence_bundle(
            bundle
        )
    )

    if result["valid"]:
        return

    raise EvidenceBundleIntegrityError(
        str(result["reason"])
    )
