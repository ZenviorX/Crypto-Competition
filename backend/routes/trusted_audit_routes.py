from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from backend.audit.trusted_audit_store import (
    get_trusted_audit_events,
    verify_trusted_audit_chain,
)
from backend.oauth.token_service import (
    mcp_resource,
    normalize_scopes,
    oauth_issuer,
    verify_access_token,
)
from backend.task_session.task_store import (
    TaskBindingError,
    TaskNotFoundError,
    load_session,
)


router = APIRouter(
    prefix="/api/trusted-audit",
    tags=["Trusted Audit Chain"],
)


TASK_OWNER_SCOPE = "mcp:tasks:manage"
AUDIT_REVIEW_SCOPE = "mcp:approvals:read"


def _extract_bearer_token(
    request: Request,
) -> str:
    authorization = str(
        request.headers.get(
            "authorization"
        )
        or ""
    ).strip()

    scheme, separator, token = (
        authorization.partition(" ")
    )

    if (
        not separator
        or scheme.lower() != "bearer"
    ):
        return ""

    return token.strip()


def _authenticate(
    request: Request,
) -> Dict[str, Any]:
    token = _extract_bearer_token(
        request
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail=(
                "A Bearer access token "
                "is required."
            ),
            headers={
                "WWW-Authenticate": (
                    "Bearer"
                ),
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    verified = verify_access_token(
        token,
        expected_audience=mcp_resource(),
        expected_issuer=oauth_issuer(),
    )

    if not verified.get("valid"):
        raise HTTPException(
            status_code=401,
            detail=str(
                verified.get("reason")
                or "Access token is invalid."
            ),
            headers={
                "WWW-Authenticate": (
                    'Bearer error="invalid_token"'
                ),
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    principal = dict(
        verified.get("payload")
        or {}
    )

    subject = str(
        principal.get("sub")
        or ""
    ).strip()

    if not subject:
        raise HTTPException(
            status_code=401,
            detail=(
                "The access token does not "
                "contain a subject."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    return principal


def _principal_scopes(
    principal: Dict[str, Any],
) -> set[str]:
    return set(
        normalize_scopes(
            principal.get("scopes")
            or principal.get("scope")
            or []
        )
    )


def _is_audit_reviewer(
    principal: Dict[str, Any],
) -> bool:
    return (
        AUDIT_REVIEW_SCOPE
        in _principal_scopes(principal)
    )


def _authorize_task_audit_read(
    *,
    principal: Dict[str, Any],
    task_handle: str,
) -> Dict[str, Any]:
    """
    A task audit chain may be read by:

    1. The task owner holding mcp:tasks:manage.
    2. A security reviewer holding mcp:approvals:read.

    Reviewers may still inspect audit evidence after
    the live task session has been removed.
    """
    subject = str(
        principal.get("sub")
        or ""
    ).strip()

    scopes = _principal_scopes(
        principal
    )

    if _is_audit_reviewer(principal):
        try:
            session, version = load_session(
                task_handle=task_handle,
            )

            return {
                "access_role": (
                    "security_reviewer"
                ),
                "task_owner": str(
                    session.user
                ),
                "task_version": int(
                    version
                ),
                "task_exists": True,
            }

        except TaskNotFoundError:
            return {
                "access_role": (
                    "security_reviewer"
                ),
                "task_owner": None,
                "task_version": None,
                "task_exists": False,
            }

    if TASK_OWNER_SCOPE not in scopes:
        raise HTTPException(
            status_code=403,
            detail=(
                "Reading task audit evidence "
                "requires mcp:tasks:manage or "
                "mcp:approvals:read."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    try:
        session, version = load_session(
            task_handle=task_handle,
            expected_user=subject,
        )

    except TaskBindingError as exc:
        raise HTTPException(
            status_code=403,
            detail=(
                "The authenticated user does not "
                "own this trusted task."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
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
                "Cache-Control": (
                    "no-store"
                ),
            },
        ) from exc

    return {
        "access_role": "task_owner",
        "task_owner": str(
            session.user
        ),
        "task_version": int(
            version
        ),
        "task_exists": True,
    }


def _no_store_json(
    content: Dict[str, Any],
    *,
    status_code: int = 200,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers={
            "Cache-Control": (
                "no-store"
            ),
        },
    )


@router.get("/verify")
def verify_audit_integrity(
    request: Request,
):
    """
    Verify the complete global trusted audit chain.

    Only a security reviewer may inspect the global
    chain head and integrity result.
    """
    principal = _authenticate(
        request
    )

    if not _is_audit_reviewer(
        principal
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Global audit verification "
                "requires mcp:approvals:read."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    result = (
        verify_trusted_audit_chain()
    )

    return _no_store_json(
        {
            "message": (
                "Trusted audit chain "
                "verification completed."
            ),
            "verified_by": str(
                principal.get("sub")
            ),
            "integrity": result,
        }
    )


@router.get(
    "/tasks/{task_handle}"
)
def read_task_audit(
    task_handle: str,
    request: Request,
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
):
    """
    Return the ordered trusted audit events for one task.

    The integrity result covers the complete global chain,
    because deleting or altering another linked event can
    also invalidate this task's evidence chain.
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
            task_handle=normalized_handle,
        )
    )

    events = (
        get_trusted_audit_events(
            task_handle=(
                normalized_handle
            ),
            limit=limit,
        )
    )

    if not events:
        raise HTTPException(
            status_code=404,
            detail=(
                "No trusted audit events "
                "were found for this task."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    integrity = (
        verify_trusted_audit_chain()
    )

    return _no_store_json(
        {
            "message": (
                "Trusted task audit "
                "evidence loaded."
            ),
            "task_handle": (
                normalized_handle
            ),
            "requested_by": str(
                principal.get("sub")
            ),
            "access": access,
            "event_count": len(events),
            "events": events,
            "chain_integrity": integrity,
        }
    )
