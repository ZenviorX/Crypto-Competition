from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.audit.trusted_audit_store import (
    sanitize_audit_payload,
)
from backend.task_session.task_store import (
    load_session,
)


BASE_DIR = Path(__file__).resolve().parents[2]

SNAPSHOT_VERSION = 1

POLICY_DIRECTORIES = (
    BASE_DIR / "backend" / "capability",
    BASE_DIR / "backend" / "runtime",
    BASE_DIR / "backend" / "proxy",
    BASE_DIR / "backend" / "sandbox",
    BASE_DIR / "backend" / "oauth",
)


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


def _sha256_text(
    value: str,
) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def _hash_value(
    value: Any,
) -> str:
    return _sha256_text(
        _canonical_json(value)
    )


def _file_sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def build_policy_manifest(
) -> List[Dict[str, str]]:
    """
    Build a deterministic manifest of authorization-related
    Python source files.

    File paths are represented by hashes instead of raw names,
    avoiding accidental disclosure or masking of filenames.
    """
    files: List[Path] = []

    for directory in POLICY_DIRECTORIES:
        if not directory.exists():
            continue

        files.extend(
            path
            for path in directory.rglob("*.py")
            if "__pycache__"
            not in path.parts
        )

    files = sorted(
        set(files),
        key=lambda path: str(
            path.relative_to(BASE_DIR)
        ).replace("\\", "/"),
    )

    manifest: List[
        Dict[str, str]
    ] = []

    for path in files:
        relative_path = str(
            path.relative_to(BASE_DIR)
        ).replace("\\", "/")

        manifest.append(
            {
                "path_sha256": (
                    _sha256_text(
                        relative_path
                    )
                ),
                "content_sha256": (
                    _file_sha256(path)
                ),
            }
        )

    return manifest


def calculate_policy_bundle_hash(
    manifest: Optional[
        List[Dict[str, str]]
    ] = None,
) -> str:
    normalized_manifest = (
        list(manifest)
        if manifest is not None
        else build_policy_manifest()
    )

    return _hash_value(
        normalized_manifest
    )


def _load_contract_snapshot(
    *,
    task_handle: str,
    user: str,
) -> Dict[str, Any]:
    if not task_handle:
        return {
            "task_version": None,
            "contract": {},
            "load_status": (
                "missing_task_handle"
            ),
        }

    try:
        session, version = load_session(
            task_handle=task_handle,
            expected_user=user,
        )

    except Exception as exc:
        return {
            "task_version": None,
            "contract": {},
            "load_status": (
                "load_failed"
            ),
            "error_type": (
                type(exc).__name__
            ),
        }

    contract = dict(
        session.contract
        or {}
    )

    if (
        not contract
        and isinstance(
            session.runtime_state,
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

    return {
        "task_version": int(
            version
        ),
        "contract": contract,
        "load_status": "loaded",
    }


def build_decision_snapshot(
    *,
    request: Any,
    result_dict: Dict[str, Any],
    executed: bool,
    tool_result: Optional[
        Dict[str, Any]
    ],
) -> Dict[str, Any]:
    """
    Create a reproducible authorization evidence snapshot.

    The snapshot fixes:

    1. Exact raw request hash.
    2. Sanitized request summary.
    3. Capability-contract snapshot and hash.
    4. Authorization policy source-code bundle hash.
    5. Decision material and decision hash.
    6. Overall snapshot hash.
    """
    task_handle = str(
        getattr(
            request,
            "task_handle",
            "",
        )
        or ""
    ).strip()

    user = str(
        getattr(
            request,
            "user",
            "",
        )
        or ""
    ).strip()

    metadata = dict(
        getattr(
            request,
            "external_agent_metadata",
            {},
        )
        or {}
    )

    approval_reference = str(
        getattr(
            request,
            "approval_ticket",
            "",
        )
        or ""
    ).strip()

    raw_request_material = {
        "task_handle": task_handle,
        "user": user,
        "original_task": str(
            getattr(
                request,
                "original_task",
                "",
            )
            or ""
        ),
        "tool": str(
            getattr(
                request,
                "tool",
                "",
            )
            or ""
        ),
        "params": dict(
            getattr(
                request,
                "params",
                {},
            )
            or {}
        ),
        "data_refs": list(
            metadata.get(
                "trusted_data_refs"
            )
            or []
        ),
        "input_from_steps": list(
            getattr(
                request,
                "input_from_steps",
                [],
            )
            or []
        ),
        "input_labels": list(
            getattr(
                request,
                "input_labels",
                [],
            )
            or []
        ),
        "execute": bool(
            getattr(
                request,
                "execute",
                False,
            )
        ),
        "approval_reference": (
            approval_reference
        ),
        "sandbox_profile": str(
            getattr(
                request,
                "sandbox_profile",
                "",
            )
            or ""
        ),
        "auth_mode": str(
            getattr(
                request,
                "auth_mode",
                "",
            )
            or ""
        ),
        "requested_scopes": list(
            getattr(
                request,
                "requested_scopes",
                [],
            )
            or []
        ),
    }

    request_hash = _hash_value(
        raw_request_material
    )

    request_summary = (
        sanitize_audit_payload(
            {
                "task_handle": (
                    task_handle
                ),
                "user": user,
                "original_task_hash": (
                    _sha256_text(
                        raw_request_material[
                            "original_task"
                        ]
                    )
                ),
                "tool": (
                    raw_request_material[
                        "tool"
                    ]
                ),
                "params": (
                    raw_request_material[
                        "params"
                    ]
                ),
                "data_refs": (
                    raw_request_material[
                        "data_refs"
                    ]
                ),
                "input_from_steps": (
                    raw_request_material[
                        "input_from_steps"
                    ]
                ),
                "input_labels": (
                    raw_request_material[
                        "input_labels"
                    ]
                ),
                "execute": (
                    raw_request_material[
                        "execute"
                    ]
                ),
                "approval_reference_hash": (
                    _sha256_text(
                        approval_reference
                    )
                    if approval_reference
                    else ""
                ),
                "sandbox_profile": (
                    raw_request_material[
                        "sandbox_profile"
                    ]
                ),
                "auth_mode": (
                    raw_request_material[
                        "auth_mode"
                    ]
                ),
                "requested_scopes": (
                    raw_request_material[
                        "requested_scopes"
                    ]
                ),
            }
        )
    )

    contract_result = (
        _load_contract_snapshot(
            task_handle=task_handle,
            user=user,
        )
    )

    contract_snapshot = (
        sanitize_audit_payload(
            {
                "task_version": (
                    contract_result[
                        "task_version"
                    ]
                ),
                "load_status": (
                    contract_result[
                        "load_status"
                    ]
                ),
                "error_type": (
                    contract_result.get(
                        "error_type"
                    )
                ),
                "contract": (
                    contract_result[
                        "contract"
                    ]
                ),
            }
        )
    )

    contract_hash = _hash_value(
        contract_snapshot
    )

    policy_manifest = (
        build_policy_manifest()
    )

    policy_bundle_hash = (
        calculate_policy_bundle_hash(
            policy_manifest
        )
    )

    decision_material = (
        sanitize_audit_payload(
            {
                "decision": str(
                    result_dict.get(
                        "decision",
                        "deny",
                    )
                ),
                "risk_score": int(
                    result_dict.get(
                        "risk_score",
                        0,
                    )
                    or 0
                ),
                "reason": [
                    str(item)
                    for item in (
                        result_dict.get(
                            "reason"
                        )
                        or []
                    )
                ],
                "executed": bool(
                    executed
                ),
                "authorization_phase": str(
                    metadata.get(
                        "authorization_phase"
                    )
                    or (
                        "execute"
                        if bool(
                            getattr(
                                request,
                                "execute",
                                False,
                            )
                        )
                        else "prepare"
                    )
                ),
                "tool_success": (
                    bool(
                        tool_result.get(
                            "success"
                        )
                    )
                    if isinstance(
                        tool_result,
                        dict,
                    )
                    and "success"
                    in tool_result
                    else None
                ),
            }
        )
    )

    decision_hash = _hash_value(
        decision_material
    )

    snapshot = {
        "snapshot_version": (
            SNAPSHOT_VERSION
        ),
        "created_at": _now_iso(),
        "request_hash": request_hash,
        "request_summary": (
            request_summary
        ),
        "contract_hash": (
            contract_hash
        ),
        "contract_snapshot": (
            contract_snapshot
        ),
        "policy_file_count": len(
            policy_manifest
        ),
        "policy_manifest": (
            policy_manifest
        ),
        "policy_bundle_hash": (
            policy_bundle_hash
        ),
        "decision_material": (
            decision_material
        ),
        "decision_hash": (
            decision_hash
        ),
    }

    snapshot = (
        sanitize_audit_payload(
            snapshot
        )
    )

    snapshot["snapshot_hash"] = (
        _hash_value(snapshot)
    )

    return snapshot


def verify_decision_snapshot(
    snapshot: Dict[str, Any],
    *,
    compare_current_policy: bool = True,
) -> Dict[str, Any]:
    """
    Verify internal decision snapshot consistency.

    This validation is independent from the outer audit
    hash chain. Both checks should pass for trusted evidence.
    """
    candidate = dict(
        snapshot or {}
    )

    stored_snapshot_hash = str(
        candidate.pop(
            "snapshot_hash",
            "",
        )
        or ""
    )

    recalculated_snapshot_hash = (
        _hash_value(candidate)
    )

    contract_snapshot = (
        candidate.get(
            "contract_snapshot"
        )
        or {}
    )

    recalculated_contract_hash = (
        _hash_value(
            contract_snapshot
        )
    )

    decision_material = (
        candidate.get(
            "decision_material"
        )
        or {}
    )

    recalculated_decision_hash = (
        _hash_value(
            decision_material
        )
    )

    policy_manifest = list(
        candidate.get(
            "policy_manifest"
        )
        or []
    )

    recalculated_policy_hash = (
        calculate_policy_bundle_hash(
            policy_manifest
        )
    )

    checks = {
        "snapshot_hash_valid": (
            bool(stored_snapshot_hash)
            and stored_snapshot_hash
            == recalculated_snapshot_hash
        ),
        "contract_hash_valid": (
            str(
                candidate.get(
                    "contract_hash"
                )
                or ""
            )
            == recalculated_contract_hash
        ),
        "decision_hash_valid": (
            str(
                candidate.get(
                    "decision_hash"
                )
                or ""
            )
            == recalculated_decision_hash
        ),
        "policy_manifest_hash_valid": (
            str(
                candidate.get(
                    "policy_bundle_hash"
                )
                or ""
            )
            == recalculated_policy_hash
        ),
    }

    current_policy_hash = None
    current_policy_matches = None

    if compare_current_policy:
        current_policy_hash = (
            calculate_policy_bundle_hash()
        )

        current_policy_matches = (
            current_policy_hash
            == str(
                candidate.get(
                    "policy_bundle_hash"
                )
                or ""
            )
        )

    internally_valid = all(
        checks.values()
    )

    return {
        "valid": internally_valid,
        **checks,
        "captured_policy_hash": str(
            candidate.get(
                "policy_bundle_hash"
            )
            or ""
        ),
        "current_policy_hash": (
            current_policy_hash
        ),
        "current_policy_matches": (
            current_policy_matches
        ),
        "reason": (
            "Decision snapshot verification passed."
            if internally_valid
            else (
                "Decision snapshot verification "
                "failed."
            )
        ),
    }
