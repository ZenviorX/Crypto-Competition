from __future__ import annotations

from typing import Any, Dict, List

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    Request,
)

from backend.audit import (
    get_logs,
    verify_audit_chain,
)
from backend.audit.decision_snapshot import (
    verify_decision_snapshot,
)
from backend.audit.trusted_audit_store import (
    get_trusted_audit_events,
    verify_trusted_audit_chain,
)
from backend.routes.trusted_audit_routes import (
    _authenticate,
    _authorize_task_audit_read,
    _no_store_json,
)


router = APIRouter()


# ============================================================
# ???? JSONL ????
# ============================================================

@router.get("/audit/logs")
def audit_logs(
    limit: int = 50,
):
    return {
        "logs": get_logs(limit),
    }


@router.get("/audit/verify")
def audit_verify():
    """
    ???? JSONL ????????
    """
    return verify_audit_chain()


# ============================================================
# ??????
# ============================================================

def _decision_snapshot_events(
    *,
    task_handle: str,
    limit: int,
) -> List[Dict[str, Any]]:
    events = get_trusted_audit_events(
        task_handle=task_handle,
        limit=limit,
    )

    result: List[
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
                compare_current_policy=True,
            )
        )

        decision_material = (
            snapshot.get(
                "decision_material"
            )
            or {}
        )

        request_summary = (
            snapshot.get(
                "request_summary"
            )
            or {}
        )

        contract_snapshot = (
            snapshot.get(
                "contract_snapshot"
            )
            or {}
        )

        result.append(
            {
                "sequence": int(
                    event["sequence"]
                ),
                "event_id": str(
                    event["event_id"]
                ),
                "event_type": str(
                    event["event_type"]
                ),
                "created_at": str(
                    event["created_at"]
                ),
                "record_hash": str(
                    event["record_hash"]
                ),
                "decision": str(
                    decision_material.get(
                        "decision"
                    )
                    or ""
                ),
                "risk_score": int(
                    decision_material.get(
                        "risk_score"
                    )
                    or 0
                ),
                "executed": bool(
                    decision_material.get(
                        "executed"
                    )
                ),
                "authorization_phase": str(
                    decision_material.get(
                        "authorization_phase"
                    )
                    or ""
                ),
                "tool": str(
                    request_summary.get(
                        "tool"
                    )
                    or ""
                ),
                "task_version": (
                    contract_snapshot.get(
                        "task_version"
                    )
                ),
                "snapshot_hash": str(
                    snapshot.get(
                        "snapshot_hash"
                    )
                    or ""
                ),
                "request_hash": str(
                    snapshot.get(
                        "request_hash"
                    )
                    or ""
                ),
                "contract_hash": str(
                    snapshot.get(
                        "contract_hash"
                    )
                    or ""
                ),
                "policy_bundle_hash": str(
                    snapshot.get(
                        "policy_bundle_hash"
                    )
                    or ""
                ),
                "verification": (
                    verification
                ),
                "snapshot": snapshot,
            }
        )

    return result


@router.get(
    "/audit/decision-snapshots/"
    "tasks/{task_handle}"
)
def list_task_decision_snapshots(
    task_handle: str,
    request: Request,
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
):
    """
    ??????????????????

    ???????
    1. ?? mcp:tasks:manage ???????
    2. ??? mcp:approvals:read ???????
    """
    normalized_handle = str(
        task_handle
    ).strip()

    if not normalized_handle:
        raise HTTPException(
            status_code=400,
            detail=(
                "task_handle is required."
            ),
        )

    principal = _authenticate(
        request
    )

    access = (
        _authorize_task_audit_read(
            principal=principal,
            task_handle=(
                normalized_handle
            ),
        )
    )

    snapshots = (
        _decision_snapshot_events(
            task_handle=(
                normalized_handle
            ),
            limit=limit,
        )
    )

    if not snapshots:
        raise HTTPException(
            status_code=404,
            detail=(
                "No authorization decision "
                "snapshots were found for "
                "this task."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    chain_integrity = (
        verify_trusted_audit_chain()
    )

    valid_snapshot_count = sum(
        1
        for item in snapshots
        if item["verification"].get(
            "valid"
        )
    )

    current_policy_match_count = sum(
        1
        for item in snapshots
        if item["verification"].get(
            "current_policy_matches"
        )
        is True
    )

    policy_changed_count = sum(
        1
        for item in snapshots
        if item["verification"].get(
            "current_policy_matches"
        )
        is False
    )

    return _no_store_json(
        {
            "message": (
                "Authorization decision "
                "snapshots loaded."
            ),
            "task_handle": (
                normalized_handle
            ),
            "requested_by": str(
                principal.get("sub")
                or ""
            ),
            "access": access,
            "snapshot_count": len(
                snapshots
            ),
            "valid_snapshot_count": (
                valid_snapshot_count
            ),
            "current_policy_match_count": (
                current_policy_match_count
            ),
            "policy_changed_count": (
                policy_changed_count
            ),
            "chain_integrity": (
                chain_integrity
            ),
            "snapshots": snapshots,
        }
    )


@router.get(
    "/audit/decision-snapshots/"
    "tasks/{task_handle}/"
    "{sequence}/verify"
)
def verify_task_decision_snapshot(
    task_handle: str,
    sequence: int,
    request: Request,
):
    """
    ?????????????????

    ?????
    1. ???????
    2. ???????
    3. ???????
    4. ?????????
    5. ??????????????
    6. ????????????
    """
    normalized_handle = str(
        task_handle
    ).strip()

    if not normalized_handle:
        raise HTTPException(
            status_code=400,
            detail=(
                "task_handle is required."
            ),
        )

    if int(sequence) <= 0:
        raise HTTPException(
            status_code=400,
            detail=(
                "sequence must be positive."
            ),
        )

    principal = _authenticate(
        request
    )

    access = (
        _authorize_task_audit_read(
            principal=principal,
            task_handle=(
                normalized_handle
            ),
        )
    )

    snapshots = (
        _decision_snapshot_events(
            task_handle=(
                normalized_handle
            ),
            limit=1000,
        )
    )

    selected = next(
        (
            item
            for item in snapshots
            if int(
                item["sequence"]
            )
            == int(sequence)
        ),
        None,
    )

    if selected is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "The requested decision "
                "snapshot was not found."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    snapshot_verification = (
        selected["verification"]
    )

    chain_integrity = (
        verify_trusted_audit_chain()
    )

    evidence_valid = bool(
        snapshot_verification.get(
            "valid"
        )
        and chain_integrity.get(
            "valid"
        )
    )

    return _no_store_json(
        {
            "message": (
                "Authorization decision "
                "snapshot verification "
                "completed."
            ),
            "task_handle": (
                normalized_handle
            ),
            "sequence": int(
                sequence
            ),
            "requested_by": str(
                principal.get("sub")
                or ""
            ),
            "access": access,
            "evidence_valid": (
                evidence_valid
            ),
            "snapshot_verification": (
                snapshot_verification
            ),
            "chain_integrity": (
                chain_integrity
            ),
            "decision_snapshot": (
                selected
            ),
        }
    )
