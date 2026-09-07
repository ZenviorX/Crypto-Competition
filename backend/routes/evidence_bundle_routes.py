from __future__ import annotations

from typing import Any, Dict

from fastapi import (
    APIRouter,
    Body,
    HTTPException,
    Request,
)

from backend.evidence.evidence_bundle import (
    EvidenceBundleError,
    build_task_evidence_bundle,
    verify_task_evidence_bundle,
)
from backend.routes.trusted_audit_routes import (
    _authenticate,
    _authorize_task_audit_read,
    _no_store_json,
)
from backend.task_session.task_store import (
    TaskBindingError,
    TaskNotFoundError,
)


router = APIRouter(
    prefix="/api/evidence",
    tags=["Trusted Evidence Bundle"],
)


def _normalized_task_handle(
    value: str,
) -> str:
    task_handle = str(
        value or ""
    ).strip()

    if not task_handle:
        raise HTTPException(
            status_code=400,
            detail=(
                "task_handle is required."
            ),
            headers={
                "Cache-Control": "no-store",
            },
        )

    return task_handle


@router.get(
    "/tasks/{task_handle}/bundle"
)
def export_task_evidence_bundle(
    task_handle: str,
    request: Request,
):
    """
    Export a self-contained task evidence package.

    Access is limited to:
    1. The authenticated task owner.
    2. A security reviewer with audit-read permission.
    """
    normalized_handle = (
        _normalized_task_handle(
            task_handle
        )
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

    task_owner = str(
        access.get(
            "task_owner"
        )
        or ""
    ).strip()

    if not task_owner:
        raise HTTPException(
            status_code=404,
            detail=(
                "The live trusted task session "
                "is unavailable, so a new "
                "evidence bundle cannot be "
                "exported."
            ),
            headers={
                "Cache-Control": "no-store",
            },
        )

    try:
        bundle = (
            build_task_evidence_bundle(
                task_handle=(
                    normalized_handle
                ),
                expected_user=(
                    task_owner
                ),
            )
        )

    except TaskBindingError as exc:
        raise HTTPException(
            status_code=403,
            detail=(
                "The evidence task binding "
                "does not match."
            ),
            headers={
                "Cache-Control": "no-store",
            },
        ) from exc

    except TaskNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=(
                "Trusted task session "
                "was not found."
            ),
            headers={
                "Cache-Control": "no-store",
            },
        ) from exc

    except EvidenceBundleError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
            headers={
                "Cache-Control": "no-store",
            },
        ) from exc

    return _no_store_json(
        {
            "message": (
                "Trusted task evidence "
                "bundle exported."
            ),
            "requested_by": str(
                principal.get("sub")
                or ""
            ),
            "access": access,
            "bundle": bundle,
        }
    )


@router.post("/verify")
def verify_exported_evidence_bundle(
    request: Request,
    bundle: Dict[str, Any] = Body(
        ...,
    ),
):
    """
    Verify an exported evidence package without
    trusting the current task runtime state.

    The package still contains a task handle, so
    authorization is checked before verification.
    A security reviewer may verify an archived
    package even if the live task was deleted.
    """
    principal = _authenticate(
        request
    )

    task_data = bundle.get(
        "task"
    )

    if not isinstance(
        task_data,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Evidence bundle task "
                "snapshot is missing."
            ),
            headers={
                "Cache-Control": "no-store",
            },
        )

    task_handle = (
        _normalized_task_handle(
            str(
                task_data.get(
                    "task_handle"
                )
                or ""
            )
        )
    )

    access = (
        _authorize_task_audit_read(
            principal=principal,
            task_handle=task_handle,
        )
    )

    verification = (
        verify_task_evidence_bundle(
            bundle
        )
    )

    return _no_store_json(
        {
            "message": (
                "Trusted evidence bundle "
                "verification completed."
            ),
            "task_handle": task_handle,
            "requested_by": str(
                principal.get("sub")
                or ""
            ),
            "access": access,
            "evidence_valid": bool(
                verification.get(
                    "valid"
                )
            ),
            "verification": (
                verification
            ),
        }
    )
