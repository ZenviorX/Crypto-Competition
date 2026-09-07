from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.audit.trusted_audit_store import (
    append_trusted_audit_event,
    get_trusted_audit_events,
)
from backend.revocation.revocation_store import (
    get_revocation,
    list_revocations,
    revoke_approval_ticket,
    revoke_capability_token,
    revoke_task,
)
from backend.task_session.task_store import (
    TaskBindingError,
    TaskNotFoundError,
    get_approval_ticket,
    load_session,
)


TASK_MANAGE_SCOPE = "mcp:tasks:manage"
APPROVAL_DECIDE_SCOPE = (
    "mcp:approvals:decide"
)
REVOCATION_READ_SCOPE = (
    "mcp:revocations:read"
)
REVOCATION_WRITE_SCOPE = (
    "mcp:revocations:write"
)


class RevocationServiceError(
    RuntimeError
):
    """Base error for revocation operations."""


class RevocationAuthorizationError(
    RevocationServiceError
):
    """The principal cannot perform this operation."""


class RevocationTargetError(
    RevocationServiceError
):
    """The requested revocation target is invalid."""


def _principal_subject(
    principal: Dict[str, Any],
) -> str:
    subject = str(
        principal.get("sub")
        or ""
    ).strip()

    if not subject:
        raise RevocationAuthorizationError(
            "Authenticated principal has "
            "no subject."
        )

    return subject


def _principal_scopes(
    principal: Dict[str, Any],
) -> set[str]:
    raw_scopes = (
        principal.get("scopes")
        or principal.get("scope")
        or []
    )

    if isinstance(raw_scopes, str):
        values = raw_scopes.replace(
            ",",
            " ",
        ).split()

    elif isinstance(
        raw_scopes,
        (
            list,
            tuple,
            set,
        ),
    ):
        values = [
            str(item)
            for item in raw_scopes
        ]

    else:
        values = [
            str(raw_scopes)
        ]

    return {
        value.strip()
        for value in values
        if value.strip()
    }


def _has_scope(
    principal: Dict[str, Any],
    scope: str,
) -> bool:
    return (
        scope
        in _principal_scopes(
            principal
        )
    )


def _load_task_binding(
    *,
    task_handle: str,
) -> Dict[str, Any]:
    normalized_handle = str(
        task_handle
    ).strip()

    if not normalized_handle:
        raise RevocationTargetError(
            "task_handle is required."
        )

    try:
        session, version = load_session(
            task_handle=normalized_handle,
        )

    except TaskNotFoundError as exc:
        raise RevocationTargetError(
            "Trusted task session "
            "was not found."
        ) from exc

    return {
        "task_handle": (
            normalized_handle
        ),
        "task_owner": str(
            session.user
        ),
        "task_version": int(
            version
        ),
    }


def _authorize_task_operation(
    *,
    principal: Dict[str, Any],
    task_binding: Dict[str, Any],
    allow_approval_reviewer: bool = False,
) -> str:
    actor = _principal_subject(
        principal
    )

    if _has_scope(
        principal,
        REVOCATION_WRITE_SCOPE,
    ):
        return actor

    if (
        allow_approval_reviewer
        and _has_scope(
            principal,
            APPROVAL_DECIDE_SCOPE,
        )
    ):
        return actor

    is_owner = (
        actor
        == task_binding[
            "task_owner"
        ]
    )

    if (
        is_owner
        and _has_scope(
            principal,
            TASK_MANAGE_SCOPE,
        )
    ):
        return actor

    raise RevocationAuthorizationError(
        "The principal cannot revoke "
        "authorization for this task."
    )


def _authorize_task_read(
    *,
    principal: Dict[str, Any],
    task_binding: Dict[str, Any],
) -> str:
    actor = _principal_subject(
        principal
    )

    scopes = _principal_scopes(
        principal
    )

    if (
        REVOCATION_READ_SCOPE
        in scopes
        or REVOCATION_WRITE_SCOPE
        in scopes
    ):
        return actor

    if (
        actor
        == task_binding[
            "task_owner"
        ]
        and TASK_MANAGE_SCOPE
        in scopes
    ):
        return actor

    raise RevocationAuthorizationError(
        "The principal cannot read "
        "revocations for this task."
    )


def _find_revocation_audit_event(
    *,
    task_handle: str,
    revocation_id: int,
) -> Optional[Dict[str, Any]]:
    events = get_trusted_audit_events(
        task_handle=task_handle,
        limit=1000,
    )

    for event in events:
        if not str(
            event.get(
                "event_type"
            )
            or ""
        ).startswith(
            "revocation."
        ):
            continue

        payload = event.get(
            "payload"
        )

        if not isinstance(
            payload,
            dict,
        ):
            continue

        if int(
            payload.get(
                "revocation_id"
            )
            or 0
        ) == int(revocation_id):
            return event

    return None


def _ensure_revocation_audit_event(
    *,
    record: Dict[str, Any],
    task_binding: Dict[str, Any],
    actor: str,
) -> Dict[str, Any]:
    existing_event = (
        _find_revocation_audit_event(
            task_handle=(
                task_binding[
                    "task_handle"
                ]
            ),
            revocation_id=int(
                record[
                    "revocation_id"
                ]
            ),
        )
    )

    if existing_event is not None:
        return existing_event

    return append_trusted_audit_event(
        task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        user=actor,
        event_type=(
            "revocation."
            + str(
                record[
                    "subject_type"
                ]
            )
        ),
        payload={
            "revocation_id": int(
                record[
                    "revocation_id"
                ]
            ),
            "subject_type": str(
                record[
                    "subject_type"
                ]
            ),
            "subject_hash": str(
                record[
                    "subject_hash"
                ]
            ),
            "task_owner": str(
                task_binding[
                    "task_owner"
                ]
            ),
            "task_version": int(
                task_binding[
                    "task_version"
                ]
            ),
            "reason": str(
                record["reason"]
            ),
            "revoked_by": str(
                record[
                    "revoked_by"
                ]
            ),
            "revoked_at": str(
                record[
                    "revoked_at"
                ]
            ),
            "metadata": dict(
                record.get(
                    "metadata"
                )
                or {}
            ),
        },
    )


def _service_result(
    *,
    record: Dict[str, Any],
    task_binding: Dict[str, Any],
    audit_event: Dict[str, Any],
    created: bool,
) -> Dict[str, Any]:
    return {
        "status": "revoked",
        "created": bool(
            created
        ),
        "revocation_id": int(
            record[
                "revocation_id"
            ]
        ),
        "subject_type": str(
            record[
                "subject_type"
            ]
        ),
        "subject_hash": str(
            record[
                "subject_hash"
            ]
        ),
        "task_handle": str(
            task_binding[
                "task_handle"
            ]
        ),
        "task_owner": str(
            task_binding[
                "task_owner"
            ]
        ),
        "task_version": int(
            task_binding[
                "task_version"
            ]
        ),
        "reason": str(
            record["reason"]
        ),
        "revoked_by": str(
            record[
                "revoked_by"
            ]
        ),
        "revoked_at": str(
            record[
                "revoked_at"
            ]
        ),
        "metadata": dict(
            record.get(
                "metadata"
            )
            or {}
        ),
        "audit_sequence": int(
            audit_event[
                "sequence"
            ]
        ),
        "audit_event_id": str(
            audit_event[
                "event_id"
            ]
        ),
        "audit_record_hash": str(
            audit_event[
                "record_hash"
            ]
        ),
    }


def revoke_task_for_principal(
    *,
    principal: Dict[str, Any],
    task_handle: str,
    reason: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    task_binding = (
        _load_task_binding(
            task_handle=task_handle,
        )
    )

    actor = (
        _authorize_task_operation(
            principal=principal,
            task_binding=(
                task_binding
            ),
        )
    )

    existing = get_revocation(
        subject_type="task",
        subject_value=(
            task_binding[
                "task_handle"
            ]
        ),
        expected_task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        expected_user=(
            task_binding[
                "task_owner"
            ]
        ),
    )

    record = revoke_task(
        task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        user=(
            task_binding[
                "task_owner"
            ]
        ),
        reason=reason,
        revoked_by=actor,
        metadata=metadata,
    )

    audit_event = (
        _ensure_revocation_audit_event(
            record=record,
            task_binding=(
                task_binding
            ),
            actor=actor,
        )
    )

    return _service_result(
        record=record,
        task_binding=task_binding,
        audit_event=audit_event,
        created=existing is None,
    )


def revoke_approval_ticket_for_principal(
    *,
    principal: Dict[str, Any],
    task_handle: str,
    approval_ticket: str,
    reason: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    task_binding = (
        _load_task_binding(
            task_handle=task_handle,
        )
    )

    actor = (
        _authorize_task_operation(
            principal=principal,
            task_binding=(
                task_binding
            ),
            allow_approval_reviewer=True,
        )
    )

    normalized_ticket = str(
        approval_ticket
    ).strip()

    if not normalized_ticket:
        raise RevocationTargetError(
            "approval_ticket is required."
        )

    try:
        ticket_record = (
            get_approval_ticket(
                approval_ticket=(
                    normalized_ticket
                ),
                expected_task_handle=(
                    task_binding[
                        "task_handle"
                    ]
                ),
                expected_user=(
                    task_binding[
                        "task_owner"
                    ]
                ),
            )
        )

    except (
        TaskBindingError,
        TaskNotFoundError,
    ) as exc:
        raise RevocationTargetError(
            "Approval ticket does not "
            "belong to this task."
        ) from exc

    existing = get_revocation(
        subject_type=(
            "approval_ticket"
        ),
        subject_value=(
            normalized_ticket
        ),
        expected_task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        expected_user=(
            task_binding[
                "task_owner"
            ]
        ),
    )

    record = revoke_approval_ticket(
        approval_ticket=(
            normalized_ticket
        ),
        task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        user=(
            task_binding[
                "task_owner"
            ]
        ),
        reason=reason,
        revoked_by=actor,
        metadata={
            **dict(metadata or {}),
            "approval_status": str(
                ticket_record[
                    "status"
                ]
            ),
            "step_index": int(
                ticket_record[
                    "step_index"
                ]
            ),
            "tool": str(
                ticket_record[
                    "tool"
                ]
            ),
        },
    )

    audit_event = (
        _ensure_revocation_audit_event(
            record=record,
            task_binding=(
                task_binding
            ),
            actor=actor,
        )
    )

    return _service_result(
        record=record,
        task_binding=task_binding,
        audit_event=audit_event,
        created=existing is None,
    )


def revoke_capability_token_for_principal(
    *,
    principal: Dict[str, Any],
    task_handle: str,
    capability_token: str,
    reason: str,
    metadata: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    task_binding = (
        _load_task_binding(
            task_handle=task_handle,
        )
    )

    actor = (
        _authorize_task_operation(
            principal=principal,
            task_binding=(
                task_binding
            ),
        )
    )

    normalized_token = str(
        capability_token
    ).strip()

    if not normalized_token:
        raise RevocationTargetError(
            "capability_token is required."
        )

    existing = get_revocation(
        subject_type=(
            "capability_token"
        ),
        subject_value=(
            normalized_token
        ),
        expected_task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        expected_user=(
            task_binding[
                "task_owner"
            ]
        ),
    )

    record = revoke_capability_token(
        capability_token=(
            normalized_token
        ),
        task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        user=(
            task_binding[
                "task_owner"
            ]
        ),
        reason=reason,
        revoked_by=actor,
        metadata=metadata,
    )

    audit_event = (
        _ensure_revocation_audit_event(
            record=record,
            task_binding=(
                task_binding
            ),
            actor=actor,
        )
    )

    return _service_result(
        record=record,
        task_binding=task_binding,
        audit_event=audit_event,
        created=existing is None,
    )


def list_task_revocations_for_principal(
    *,
    principal: Dict[str, Any],
    task_handle: str,
    limit: int = 100,
) -> Dict[str, Any]:
    task_binding = (
        _load_task_binding(
            task_handle=task_handle,
        )
    )

    actor = _authorize_task_read(
        principal=principal,
        task_binding=(
            task_binding
        ),
    )

    records: List[
        Dict[str, Any]
    ] = list_revocations(
        task_handle=(
            task_binding[
                "task_handle"
            ]
        ),
        limit=limit,
    )

    return {
        "task_handle": str(
            task_binding[
                "task_handle"
            ]
        ),
        "task_owner": str(
            task_binding[
                "task_owner"
            ]
        ),
        "task_version": int(
            task_binding[
                "task_version"
            ]
        ),
        "requested_by": actor,
        "revocation_count": len(
            records
        ),
        "revocations": records,
    }
