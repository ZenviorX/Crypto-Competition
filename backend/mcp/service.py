from __future__ import annotations
import os
import hmac
import hashlib

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from backend.mcp.tool_registry import (
    MCP_LIST_SCOPE,
    MCP_TASK_SCOPE,
    get_tool_definition,
    tool_definitions_for_scopes,
    tool_manifest_attestation,
)
from backend.oauth.token_service import normalize_scopes
from backend.proxy.oauth_profile import get_required_scopes
from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.tool_proxy_service import authorize_tool_call
from backend.task_session.session_executor import model_to_dict
from backend.task_session.session_models import TaskSession
from backend.task_session.task_store import (
    TaskBindingError,
    TaskNotFoundError,
    create_session,
    load_session,
)
from backend.task_session.task_store import DataReferenceBindingError, DataReferenceNotFoundError, resolve_data_references
from backend.mcp.tool_registry import MCP_APPROVAL_DECIDE_SCOPE, MCP_APPROVAL_READ_SCOPE
from backend.task_session.task_store import ApprovalTicketBindingError, ApprovalTicketNotFoundError, ApprovalTicketStateError, decide_approval_ticket, get_approval_ticket
from backend.audit.trusted_audit_store import append_trusted_audit_event
from backend.revocation.revocation_service import (
    APPROVAL_DECIDE_SCOPE as REVOCATION_APPROVAL_DECIDE_SCOPE,
    REVOCATION_READ_SCOPE,
    REVOCATION_WRITE_SCOPE,
    TASK_MANAGE_SCOPE as REVOCATION_TASK_MANAGE_SCOPE,
    RevocationAuthorizationError,
    RevocationServiceError,
    RevocationTargetError,
    list_task_revocations_for_principal,
    revoke_approval_ticket_for_principal,
    revoke_capability_token_for_principal,
    revoke_task_for_principal,
)


CURRENT_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (
    CURRENT_PROTOCOL_VERSION,
    "2025-06-18",
)


@dataclass
class McpProtocolError(Exception):
    code: int
    message: str
    data: Optional[Dict[str, Any]] = None


@dataclass
class InsufficientScopeError(Exception):
    required_scopes: List[str]
    message: str = "The OAuth access token does not contain all scopes required for this MCP operation."


def _require_tool_manifest_integrity() -> Dict[str, Any]:
    attestation = (
        tool_manifest_attestation()
    )

    if not attestation.get(
        "valid",
        False,
    ):
        raise McpProtocolError(
            -32010,
            (
                "AgentGuard tool manifest "
                "integrity verification failed."
            ),
            data={
                "toolManifest": (
                    attestation
                ),
            },
        )

    return attestation


def _response(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def protocol_error_response(request_id: Any, error: McpProtocolError) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": int(error.code),
            "message": str(error.message),
        },
    }

    if error.data:
        body["error"]["data"] = error.data

    return body


def _principal_scopes(principal: Dict[str, Any]) -> List[str]:
    return normalize_scopes(principal.get("scopes") or principal.get("scope") or [])


def _require_scopes(principal: Dict[str, Any], required: List[str]) -> None:
    granted = set(_principal_scopes(principal))
    missing = [scope for scope in normalize_scopes(required) if scope not in granted]

    if missing:
        raise InsufficientScopeError(required_scopes=missing)


def _select_protocol_version(requested: Any) -> str:
    requested_value = str(requested or "")
    if requested_value in SUPPORTED_PROTOCOL_VERSIONS:
        return requested_value
    return CURRENT_PROTOCOL_VERSION


def _initialize_result(params: Dict[str, Any]) -> Dict[str, Any]:
    attestation = (
        _require_tool_manifest_integrity()
    )

    return {
        "protocolVersion": _select_protocol_version(params.get("protocolVersion")),
        "capabilities": {
            "tools": {
                "listChanged": False,
            }
        },
        "serverInfo": {
            "name": "agentguard-mcp-gateway",
            "version": "0.7.0",
        },
        "_meta": {
            "agentguard/toolManifest": (
                attestation
            ),
        },
        "instructions": (
            "OAuth scopes provide coarse-grained access. AgentGuard additionally applies "
            "task-bound capability checks, runtime monitoring, sandbox policy and audit evidence "
            "before any MCP tool is executed. Standard MCP clients should first call "
            "agentguard.task.create with the user's original task, then pass the returned "
            "taskHandle in the taskHandle argument of subsequent protected tool calls."
        ),
    }


def _tool_result_payload(
    *,
    decision: str,
    risk_score: int,
    reason: List[str],
    executed: bool,
    tool_result: Optional[Dict[str, Any]] = None,
    sandbox_evidence: Optional[Dict[str, Any]] = None,
    capability_token_validation: Optional[Dict[str, Any]] = None,
    task_handle: str = "",
    task_version: int = 0,
    data_ref: str = "",
    approval_ticket: str = "",
    approval_status: str = "",
) -> Dict[str, Any]:
    structured = {
        "task_handle": str(
            task_handle or ""
        ),
        "task_version": int(
            task_version or 0
        ),
        "data_ref": str(
            data_ref or ""
        ),
        "approval_ticket": str(
            approval_ticket or ""
        ),
        "approval_status": str(
            approval_status or ""
        ),
        "decision": str(decision),
        "risk_score": int(
            risk_score or 0
        ),
        "reason": [
            str(item)
            for item in reason or []
        ],
        "executed": bool(executed),
        "tool_result": tool_result,
        "sandbox_evidence": sandbox_evidence,
        "capability_token_validation": (
            capability_token_validation
            or {}
        ),
    }

    tool_failed = bool(
        isinstance(tool_result, dict)
        and tool_result.get("success") is False
    )

    is_error = (
        decision != "allow"
        or not executed
        or tool_failed
    )

    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    structured,
                    ensure_ascii=False,
                    indent=2,
                ),
            }
        ],
        "structuredContent": structured,
        "isError": is_error,
    }


def _extract_meta(params: Dict[str, Any]) -> Dict[str, Any]:
    meta = params.get("_meta", {}) or {}
    if not isinstance(meta, dict):
        raise McpProtocolError(-32602, "params._meta must be an object when provided.")
    return meta


def _prepare_proxy_request(
    *,
    principal: Dict[str, Any],
    name: str,
    arguments: Dict[str, Any],
    meta: Dict[str, Any],
) -> ToolProxyAuthorizeRequest:
    """
    Build a Tool Proxy request using only server-trusted
    task state and data references.
    """
    task_handle = str(
        meta.get("agentguard/taskHandle")
        or meta.get("agentguard.task_handle")
        or ""
    ).strip()

    raw_data_refs = (
        meta.get("agentguard/dataRefs")
        or meta.get("agentguard.data_refs")
        or []
    )

    if not isinstance(raw_data_refs, list):
        raise McpProtocolError(
            -32602,
            "agentguard/dataRefs must be an array.",
        )

    data_refs: List[str] = []

    for item in raw_data_refs:
        value = str(item).strip()

        if value and value not in data_refs:
            data_refs.append(value)

    user = str(
        principal.get("sub")
        or "oauth-user"
    )

    # OAuth_TASK_BINDING_CHECK:_prepare_proxy_request
    if task_handle:
        try:
            (
                trusted_session,
                _trusted_version,
            ) = load_session(
                task_handle=task_handle,
                expected_user=user,
            )

        except TaskNotFoundError as exc:
            raise McpProtocolError(
                -32004,
                (
                    "Trusted task session "
                    "was not found."
                ),
            ) from exc

        except TaskBindingError as exc:
            raise McpProtocolError(
                -32003,
                (
                    "Trusted task session "
                    "does not belong to this "
                    "OAuth subject."
                ),
            ) from exc

        _assert_task_authorization_binding(
            session=trusted_session,
            principal=principal,
        )

    trusted_steps: List[int] = []
    trusted_labels: List[str] = []

    if data_refs:
        if not task_handle:
            raise McpProtocolError(
                -32602,
                (
                    "agentguard/dataRefs requires a "
                    "server-issued task handle."
                ),
            )

        try:
            (
                trusted_steps,
                trusted_labels,
            ) = resolve_data_references(
                task_handle=task_handle,
                user=user,
                data_refs=data_refs,
            )

        except DataReferenceNotFoundError as exc:
            raise McpProtocolError(
                -32004,
                "One or more data references were not found.",
            ) from exc

        except DataReferenceBindingError as exc:
            raise McpProtocolError(
                -32003,
                (
                    "A data reference does not belong "
                    "to this task or OAuth subject."
                ),
            ) from exc

    ignored_client_fields: List[str] = []

    for field_name in (
        "agentguard/inputLabels",
        "agentguard/inputFromSteps",
        "agentguard/agentConfidence",
        "agentguard/originalTask",
        "agentguard.original_task",
    ):
        if field_name in meta:
            ignored_client_fields.append(
                field_name
            )

    approval_ticket = str(
        meta.get(
            "agentguard/approvalTicket"
        )
        or meta.get(
            "agentguard.approval_ticket"
        )
        or ""
    ).strip()

    return ToolProxyAuthorizeRequest(
        user=user,
        original_task="",
        task_handle=task_handle,
        tool=name,
        params=dict(arguments),
        input_labels=list(trusted_labels),
        input_from_steps=list(trusted_steps),
        agent_confidence=1.0,
        execute=False,
        agent_platform=str(
            meta.get("agentguard/agentPlatform")
            or principal.get("client_id")
            or "mcp-client"
        ),
        auth_mode="oauth_scope",
        requested_scopes=_principal_scopes(
            principal
        ),
        oauth_token_claims=dict(principal),
        capability_token="",
        sandbox_profile=str(
            meta.get("agentguard/sandboxProfile")
            or "default"
        ),
        external_agent_metadata={
            "transport": "mcp_streamable_http",
            "mcp_protocol_version": str(
                meta.get(
                    "agentguard/protocolVersion"
                )
                or CURRENT_PROTOCOL_VERSION
            ),
            "authorization_phase": "prepare",
            "security_context_source": (
                "agentguard_server"
            ),
            "trusted_data_refs": list(
                data_refs
            ),
            "resolved_source_steps": list(
                trusted_steps
            ),
            "resolved_input_labels": list(
                trusted_labels
            ),
            "ignored_client_security_fields": (
                ignored_client_fields
            ),
        },
        approval_ticket=approval_ticket,
    )




OAUTH_TASK_BINDING_SCHEMA = (
    "agentguard.oauth_task_binding.v1"
)


def _normalized_oauth_audience(
    value: Any,
) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        candidates = [value]

    elif isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        candidates = [
            str(item)
            for item in value
        ]

    else:
        candidates = [
            str(value)
        ]

    normalized: List[str] = []

    for item in candidates:
        audience = str(
            item
        ).strip()

        if (
            audience
            and audience
            not in normalized
        ):
            normalized.append(
                audience
            )

    return sorted(normalized)


def _principal_task_authorization_binding(
    principal: Dict[str, Any],
) -> Dict[str, Any]:
    principal = dict(
        principal or {}
    )

    scopes = sorted(
        set(
            _principal_scopes(
                principal
            )
        )
    )

    return {
        "schema": (
            OAUTH_TASK_BINDING_SCHEMA
        ),
        "issuer": str(
            principal.get("iss")
            or ""
        ).strip(),
        "subject": str(
            principal.get("sub")
            or ""
        ).strip(),
        "client_id": str(
            principal.get("client_id")
            or principal.get("azp")
            or ""
        ).strip(),
        "audience": (
            _normalized_oauth_audience(
                principal.get("aud")
            )
        ),
        "scope_ceiling": scopes,
    }


def _oauth_task_binding_fingerprint(
    binding: Dict[str, Any],
) -> str:
    encoded = json.dumps(
        binding,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return (
        "sha256:"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def _competition_mode() -> bool:
    return (
        os.getenv(
            "AGENTGUARD_MODE",
            "demo",
        ).strip().lower()
        == "competition"
    )


def _bind_task_session_authorization(
    *,
    session: TaskSession,
    principal: Dict[str, Any],
) -> None:
    binding = (
        _principal_task_authorization_binding(
            principal
        )
    )

    if not binding["subject"]:
        raise McpProtocolError(
            -32600,
            (
                "OAuth principal does not "
                "contain a subject."
            ),
        )

    if _competition_mode():
        missing_fields = [
            field_name
            for field_name in (
                "issuer",
                "client_id",
            )
            if not binding[field_name]
        ]

        if not binding["audience"]:
            missing_fields.append(
                "audience"
            )

        if missing_fields:
            raise McpProtocolError(
                -32600,
                (
                    "Competition mode requires "
                    "a complete OAuth task "
                    "authorization context. "
                    "Missing fields: "
                    + ", ".join(
                        missing_fields
                    )
                ),
            )

    session.oauth_authorization_binding = (
        dict(binding)
    )

    session.oauth_authorization_fingerprint = (
        _oauth_task_binding_fingerprint(
            binding
        )
    )


def _assert_task_authorization_binding(
    *,
    session: TaskSession,
    principal: Dict[str, Any],
) -> None:
    stored_binding = dict(
        getattr(
            session,
            "oauth_authorization_binding",
            {},
        )
        or {}
    )

    stored_fingerprint = str(
        getattr(
            session,
            "oauth_authorization_fingerprint",
            "",
        )
        or ""
    ).strip()

    if not stored_binding:
        if _competition_mode():
            raise McpProtocolError(
                -32003,
                (
                    "Trusted task session does "
                    "not contain an OAuth "
                    "authorization binding."
                ),
            )

        # Demo 模式兼容创建于旧版本的任务。
        return

    if (
        stored_binding.get("schema")
        != OAUTH_TASK_BINDING_SCHEMA
    ):
        raise McpProtocolError(
            -32003,
            (
                "Trusted task OAuth binding "
                "uses an unsupported schema."
            ),
        )

    expected_fingerprint = (
        _oauth_task_binding_fingerprint(
            stored_binding
        )
    )

    if (
        not stored_fingerprint
        or not hmac.compare_digest(
            stored_fingerprint,
            expected_fingerprint,
        )
    ):
        raise McpProtocolError(
            -32003,
            (
                "Trusted task OAuth binding "
                "fingerprint verification failed."
            ),
        )

    current_binding = (
        _principal_task_authorization_binding(
            principal
        )
    )

    identity_fields = (
        "issuer",
        "subject",
        "client_id",
        "audience",
    )

    mismatched_fields: List[str] = []

    for field_name in identity_fields:
        if (
            stored_binding.get(
                field_name
            )
            != current_binding.get(
                field_name
            )
        ):
            mismatched_fields.append(
                field_name
            )

    if mismatched_fields:
        raise McpProtocolError(
            -32003,
            (
                "Trusted task belongs to a "
                "different OAuth authorization "
                "context. Mismatched fields: "
                + ", ".join(
                    mismatched_fields
                )
            ),
        )

    scope_ceiling = set(
        normalize_scopes(
            stored_binding.get(
                "scope_ceiling"
            )
            or []
        )
    )

    current_scopes = set(
        normalize_scopes(
            current_binding.get(
                "scope_ceiling"
            )
            or []
        )
    )

    expanded_scopes = sorted(
        current_scopes
        - scope_ceiling
    )

    if expanded_scopes:
        raise McpProtocolError(
            -32003,
            (
                "OAuth scopes exceed the "
                "authority ceiling recorded "
                "when the task was created. "
                "Unexpected scopes: "
                + ", ".join(
                    expanded_scopes
                )
            ),
        )


def _create_trusted_task(
    *,
    principal: Dict[str, Any],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    _require_scopes(
        principal,
        [MCP_TASK_SCOPE],
    )

    original_task = str(
        params.get("originalTask")
        or params.get("original_task")
        or ""
    ).strip()

    if not original_task:
        raise McpProtocolError(
            -32602,
            "agentguard/tasks/create requires params.originalTask.",
        )

    if len(original_task) > 8000:
        raise McpProtocolError(
            -32602,
            "The original task exceeds the 8000 character limit.",
        )

    user = str(
        principal.get("sub")
        or ""
    ).strip()

    if not user:
        raise McpProtocolError(
            -32600,
            "The OAuth principal does not contain a subject.",
        )

    session = TaskSession(
        user=user,
        original_input=original_task,
        agent_type="mcp",
        status="created",
    )

    _bind_task_session_authorization(
        session=session,
        principal=principal,
    )

    task_handle, version = create_session(
        session
    )

    return {
        "taskHandle": task_handle,
        "version": version,
        "status": session.status,
        "user": user,
        "createdAt": session.created_at,
    }


def _get_trusted_task(
    *,
    principal: Dict[str, Any],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    _require_scopes(
        principal,
        [MCP_TASK_SCOPE],
    )

    task_handle = str(
        params.get("taskHandle")
        or params.get("task_handle")
        or ""
    ).strip()

    if not task_handle:
        raise McpProtocolError(
            -32602,
            "agentguard/tasks/get requires params.taskHandle.",
        )

    user = str(
        principal.get("sub")
        or ""
    ).strip()

    try:
        session, version = load_session(
            task_handle=task_handle,
            expected_user=user,
        )

    except TaskNotFoundError as exc:
        raise McpProtocolError(
            -32004,
            "Trusted task session was not found.",
        ) from exc

    except TaskBindingError as exc:
        raise McpProtocolError(
            -32003,
            "Trusted task session does not belong to this OAuth subject.",
        ) from exc


    # OAuth_TASK_BINDING_CHECK:_get_trusted_task
    _assert_task_authorization_binding(
        session=session,
        principal=principal,
    )
    return {
        "taskHandle": task_handle,
        "version": version,
        "session": model_to_dict(session),
    }

def _call_tool(
    *,
    principal: Dict[str, Any],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    _require_tool_manifest_integrity()

    name = str(params.get("name") or "")
    arguments = params.get("arguments", {}) or {}

    if not name:
        raise McpProtocolError(-32602, "tools/call requires params.name.")

    if not isinstance(arguments, dict):
        raise McpProtocolError(-32602, "tools/call params.arguments must be an object.")

    if get_tool_definition(name) is None:
        raise McpProtocolError(-32602, f"Unknown MCP tool: {name}")

    # Standard MCP compatibility:
    # expose trusted-task creation through tools/call.
    if name == "agentguard.task.create":
        created = _create_trusted_task(
            principal=principal,
            params=arguments,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        created,
                        ensure_ascii=False,
                        indent=2,
                    ),
                }
            ],
            "structuredContent": created,
            "isError": False,
        }

    # Generic MCP clients normally cannot inject custom params._meta.
    # Accept taskHandle as a normal tool argument, then convert it
    # internally into AgentGuard's trusted metadata representation.
    tool_arguments = dict(arguments)

    task_handle_argument = str(
        tool_arguments.pop("taskHandle", "")
        or tool_arguments.pop("task_handle", "")
        or ""
    ).strip()

    dynamic_required_scopes = get_required_scopes(
        name,
        tool_arguments,
    )
    _require_scopes(
        principal,
        dynamic_required_scopes,
    )

    meta = dict(_extract_meta(params))

    if (
        task_handle_argument
        and not meta.get("agentguard/taskHandle")
        and not meta.get("agentguard.task_handle")
    ):
        meta["agentguard/taskHandle"] = task_handle_argument

    prepare_request = _prepare_proxy_request(
        principal=principal,
        name=name,
        arguments=tool_arguments,
        meta=meta,
    )

    if not prepare_request.task_handle:
        raise McpProtocolError(
            -32602,
            (
                "MCP tools/call requires a server-issued task handle in "
                "params._meta['agentguard/taskHandle']. "
                "Create one with agentguard/tasks/create."
            ),
        )

    prepare_result = authorize_tool_call(
        prepare_request
    )

    missing_scopes = list((prepare_result.agent_auth_profile or {}).get("missing_scopes", []))
    if missing_scopes:
        raise InsufficientScopeError(required_scopes=[str(item) for item in missing_scopes])

    if prepare_result.decision != "allow":
        return _tool_result_payload(
            decision=prepare_result.decision,
            risk_score=prepare_result.risk_score,
            reason=prepare_result.reason,
            executed=False,
            tool_result=None,
            sandbox_evidence=None,
            capability_token_validation=prepare_result.capability_token_validation,
            task_handle=prepare_result.task_handle,
            task_version=prepare_result.task_version,
            approval_ticket=prepare_result.approval_ticket,
            approval_status=prepare_result.approval_status,
        )

    token = str((prepare_result.capability_token or {}).get("token") or "")
    if not token:
        return _tool_result_payload(
            decision="deny",
            risk_score=max(100, int(prepare_result.risk_score or 0)),
            reason=list(prepare_result.reason) + [
                "AgentGuard did not issue the required task-scoped capability token."
            ],
            executed=False,
            task_handle=prepare_result.task_handle,
            task_version=prepare_result.task_version,
            approval_ticket=prepare_result.approval_ticket,
            approval_status=prepare_result.approval_status,
        )

    execute_metadata = dict(
        prepare_request.external_agent_metadata or {}
    )
    execute_metadata["authorization_phase"] = "execute"

    execute_request = prepare_request.model_copy(
        update={
            "execute": True,
            "capability_token": token,
            "external_agent_metadata": execute_metadata,
        }
    )
    execute_result = authorize_tool_call(execute_request)

    return _tool_result_payload(
        decision=execute_result.decision,
        risk_score=execute_result.risk_score,
        reason=execute_result.reason,
        executed=execute_result.executed,
        tool_result=execute_result.tool_result,
        sandbox_evidence=execute_result.sandbox_evidence,
        capability_token_validation=execute_result.capability_token_validation,
        task_handle=execute_result.task_handle,
        task_version=execute_result.task_version,
        data_ref=execute_result.data_ref,
        approval_ticket=execute_result.approval_ticket,
        approval_status=execute_result.approval_status,
    )


def _approval_ticket_from_params(
    params: Dict[str, Any],
) -> str:
    approval_ticket = str(
        params.get("approvalTicket")
        or params.get("approval_ticket")
        or ""
    ).strip()

    if not approval_ticket:
        raise McpProtocolError(
            -32602,
            "An approvalTicket is required.",
        )

    return approval_ticket


def _approval_task_handle_from_params(
    params: Dict[str, Any],
) -> str:
    task_handle = str(
        params.get("taskHandle")
        or params.get("task_handle")
        or ""
    ).strip()

    if not task_handle:
        raise McpProtocolError(
            -32602,
            "A taskHandle is required.",
        )

    return task_handle


def _get_approval_request(
    *,
    principal: Dict[str, Any],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    _require_scopes(
        principal,
        [MCP_APPROVAL_READ_SCOPE],
    )

    approval_ticket = (
        _approval_ticket_from_params(params)
    )
    task_handle = (
        _approval_task_handle_from_params(params)
    )

    try:
        ticket = get_approval_ticket(
            approval_ticket=approval_ticket,
            expected_task_handle=task_handle,
        )

    except ApprovalTicketNotFoundError as exc:
        raise McpProtocolError(
            -32004,
            "Approval ticket was not found.",
        ) from exc

    except ApprovalTicketBindingError as exc:
        raise McpProtocolError(
            -32003,
            (
                "Approval ticket does not belong "
                "to the supplied task."
            ),
        ) from exc

    return {
        "approvalTicket": ticket[
            "approval_ticket"
        ],
        "taskHandle": ticket[
            "task_handle"
        ],
        "taskOwner": ticket["user"],
        "stepIndex": ticket[
            "step_index"
        ],
        "tool": ticket["tool"],
        "params": ticket["params"],
        "dataRefs": ticket[
            "data_refs"
        ],
        "status": ticket["status"],
        "requestedAt": ticket[
            "requested_at"
        ],
        "decidedAt": ticket[
            "decided_at"
        ],
        "decidedBy": ticket[
            "decided_by"
        ],
        "consumedAt": ticket[
            "consumed_at"
        ],
    }


def _decide_approval_request(
    *,
    principal: Dict[str, Any],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    _require_scopes(
        principal,
        [MCP_APPROVAL_DECIDE_SCOPE],
    )

    approval_ticket = (
        _approval_ticket_from_params(params)
    )
    task_handle = (
        _approval_task_handle_from_params(params)
    )

    decision = str(
        params.get("decision")
        or ""
    ).strip().lower()

    if decision not in {
        "approve",
        "approved",
        "deny",
        "denied",
    }:
        raise McpProtocolError(
            -32602,
            (
                "decision must be "
                "approve or deny."
            ),
        )

    reviewer = str(
        principal.get("sub")
        or ""
    ).strip()

    if not reviewer:
        raise McpProtocolError(
            -32600,
            (
                "The OAuth principal does not "
                "contain a reviewer subject."
            ),
        )

    try:
        current = get_approval_ticket(
            approval_ticket=approval_ticket,
            expected_task_handle=task_handle,
        )

    except ApprovalTicketNotFoundError as exc:
        raise McpProtocolError(
            -32004,
            "Approval ticket was not found.",
        ) from exc

    except ApprovalTicketBindingError as exc:
        raise McpProtocolError(
            -32003,
            (
                "Approval ticket does not belong "
                "to the supplied task."
            ),
        ) from exc

    is_approval = decision in {
        "approve",
        "approved",
    }

    if (
        is_approval
        and reviewer == current["user"]
    ):
        raise McpProtocolError(
            -32010,
            (
                "The task owner cannot approve "
                "its own request."
            ),
        )

    try:
        updated = decide_approval_ticket(
            approval_ticket=approval_ticket,
            task_handle=task_handle,
            user=current["user"],
            decided_by=reviewer,
            decision=decision,
        )

    except ApprovalTicketStateError as exc:
        raise McpProtocolError(
            -32009,
            str(exc),
        ) from exc

    except ApprovalTicketBindingError as exc:
        raise McpProtocolError(
            -32003,
            (
                "Approval ticket does not belong "
                "to the supplied task."
            ),
        ) from exc

    append_trusted_audit_event(
        task_handle=str(
            updated["task_handle"]
        ),
        user=reviewer,
        event_type=(
            "approval."
            + str(
                updated["status"]
            )
        ),
        payload={
            "approval_ticket": str(
                updated["approval_ticket"]
            ),
            "task_owner": str(
                updated["user"]
            ),
            "step_index": int(
                updated["step_index"]
            ),
            "tool": str(
                updated["tool"]
            ),
            "status": str(
                updated["status"]
            ),
            "decided_by": str(
                updated["decided_by"]
                or reviewer
            ),
        },
    )

    return {
        "approvalTicket": updated[
            "approval_ticket"
        ],
        "taskHandle": updated[
            "task_handle"
        ],
        "taskOwner": updated["user"],
        "stepIndex": updated[
            "step_index"
        ],
        "tool": updated["tool"],
        "status": updated["status"],
        "decidedAt": updated[
            "decided_at"
        ],
        "decidedBy": updated[
            "decided_by"
        ],
    }

def _handle_mcp_request_without_revocation(
    payload: Dict[str, Any],
    *,
    principal: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        raise McpProtocolError(-32600, "MCP request must be a JSON object.")

    if payload.get("jsonrpc") != "2.0":
        raise McpProtocolError(-32600, "MCP uses JSON-RPC 2.0 and requires jsonrpc='2.0'.")

    request_id = payload.get("id")
    method = str(payload.get("method") or "")
    params = payload.get("params", {}) or {}

    if not method:
        raise McpProtocolError(-32600, "JSON-RPC method is required.")

    if not isinstance(params, dict):
        raise McpProtocolError(-32602, "JSON-RPC params must be an object.")

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return _response(request_id, _initialize_result(params))

    if method == "ping":
        return _response(request_id, {})

    if method == "tools/list":
        _require_scopes(
            principal,
            [MCP_LIST_SCOPE],
        )

        attestation = (
            _require_tool_manifest_integrity()
        )

        return _response(
            request_id,
            {
                "tools": (
                    tool_definitions_for_scopes(
                        _principal_scopes(
                            principal
                        )
                    )
                ),
                "_meta": {
                    "agentguard/toolManifest": (
                        attestation
                    ),
                },
            },
        )

    if method == "agentguard/tasks/create":
        return _response(
            request_id,
            _create_trusted_task(
                principal=principal,
                params=params,
            ),
        )

    if method == "agentguard/tasks/get":
        return _response(
            request_id,
            _get_trusted_task(
                principal=principal,
                params=params,
            ),
        )

    if method == "agentguard/approvals/get":
        return _response(
            request_id,
            _get_approval_request(
                principal=principal,
                params=params,
            ),
        )

    if method == "agentguard/approvals/decide":
        return _response(
            request_id,
            _decide_approval_request(
                principal=principal,
                params=params,
            ),
        )

    if method == "tools/call":
        return _response(
            request_id,
            _call_tool(principal=principal, params=params),
        )

    raise McpProtocolError(-32601, f"MCP method not found: {method}")


REVOCATION_MCP_METHODS = {
    "agentguard/revocations/task/revoke",
    "agentguard/revocations/approval/revoke",
    "agentguard/revocations/capability/revoke",
    "agentguard/revocations/list",
}


def _revocation_principal_scopes(
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


def _require_any_revocation_scope(
    *,
    principal: Dict[str, Any],
    required_scopes: set[str],
) -> None:
    principal_scopes = (
        _revocation_principal_scopes(
            principal
        )
    )

    if (
        principal_scopes
        & required_scopes
    ):
        return

    raise McpProtocolError(
        -32003,
        (
            "Insufficient OAuth scope. "
            "At least one of the following "
            "scopes is required: "
            + ", ".join(
                sorted(required_scopes)
            )
        ),
    )


def _revocation_params(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    params = payload.get(
        "params",
        {},
    )

    if not isinstance(
        params,
        dict,
    ):
        raise McpProtocolError(
            -32602,
            "params must be an object.",
        )

    return params


def _required_text_param(
    params: Dict[str, Any],
    *names: str,
) -> str:
    for name in names:
        value = str(
            params.get(name)
            or ""
        ).strip()

        if value:
            return value

    raise McpProtocolError(
        -32602,
        (
            "Missing required parameter: "
            + names[0]
        ),
    )


def _optional_metadata_param(
    params: Dict[str, Any],
) -> Dict[str, Any]:
    metadata = params.get(
        "metadata",
        {},
    )

    if metadata is None:
        return {}

    if not isinstance(
        metadata,
        dict,
    ):
        raise McpProtocolError(
            -32602,
            "metadata must be an object.",
        )

    return dict(metadata)


def _revocation_jsonrpc_result(
    *,
    request_id: Any,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def _handle_revocation_mcp_request(
    payload: Dict[str, Any],
    *,
    principal: Dict[str, Any],
) -> Dict[str, Any]:
    method = str(
        payload.get("method")
        or ""
    )

    params = _revocation_params(
        payload
    )

    task_handle = (
        _required_text_param(
            params,
            "taskHandle",
            "task_handle",
        )
    )

    try:
        if (
            method
            == "agentguard/revocations/task/revoke"
        ):
            _require_any_revocation_scope(
                principal=principal,
                required_scopes={
                    REVOCATION_TASK_MANAGE_SCOPE,
                    REVOCATION_WRITE_SCOPE,
                },
            )

            result = (
                revoke_task_for_principal(
                    principal=principal,
                    task_handle=task_handle,
                    reason=_required_text_param(
                        params,
                        "reason",
                    ),
                    metadata=(
                        _optional_metadata_param(
                            params
                        )
                    ),
                )
            )

        elif (
            method
            == "agentguard/revocations/approval/revoke"
        ):
            _require_any_revocation_scope(
                principal=principal,
                required_scopes={
                    REVOCATION_TASK_MANAGE_SCOPE,
                    REVOCATION_APPROVAL_DECIDE_SCOPE,
                    REVOCATION_WRITE_SCOPE,
                },
            )

            result = (
                revoke_approval_ticket_for_principal(
                    principal=principal,
                    task_handle=task_handle,
                    approval_ticket=(
                        _required_text_param(
                            params,
                            "approvalTicket",
                            "approval_ticket",
                        )
                    ),
                    reason=_required_text_param(
                        params,
                        "reason",
                    ),
                    metadata=(
                        _optional_metadata_param(
                            params
                        )
                    ),
                )
            )

        elif (
            method
            == "agentguard/revocations/capability/revoke"
        ):
            _require_any_revocation_scope(
                principal=principal,
                required_scopes={
                    REVOCATION_TASK_MANAGE_SCOPE,
                    REVOCATION_WRITE_SCOPE,
                },
            )

            result = (
                revoke_capability_token_for_principal(
                    principal=principal,
                    task_handle=task_handle,
                    capability_token=(
                        _required_text_param(
                            params,
                            "capabilityToken",
                            "capability_token",
                        )
                    ),
                    reason=_required_text_param(
                        params,
                        "reason",
                    ),
                    metadata=(
                        _optional_metadata_param(
                            params
                        )
                    ),
                )
            )

        elif (
            method
            == "agentguard/revocations/list"
        ):
            _require_any_revocation_scope(
                principal=principal,
                required_scopes={
                    REVOCATION_TASK_MANAGE_SCOPE,
                    REVOCATION_READ_SCOPE,
                    REVOCATION_WRITE_SCOPE,
                },
            )

            try:
                limit = int(
                    params.get(
                        "limit",
                        100,
                    )
                )

            except (
                TypeError,
                ValueError,
            ) as exc:
                raise McpProtocolError(
                    -32602,
                    "limit must be an integer.",
                ) from exc

            if (
                limit < 1
                or limit > 1000
            ):
                raise McpProtocolError(
                    -32602,
                    (
                        "limit must be between "
                        "1 and 1000."
                    ),
                )

            result = (
                list_task_revocations_for_principal(
                    principal=principal,
                    task_handle=task_handle,
                    limit=limit,
                )
            )

        else:
            raise McpProtocolError(
                -32601,
                "Revocation method not found.",
            )

    except RevocationAuthorizationError as exc:
        raise McpProtocolError(
            -32003,
            str(exc),
        ) from exc

    except RevocationTargetError as exc:
        raise McpProtocolError(
            -32602,
            str(exc),
        ) from exc

    except RevocationServiceError as exc:
        raise McpProtocolError(
            -32000,
            str(exc),
        ) from exc

    return _revocation_jsonrpc_result(
        request_id=payload.get("id"),
        result=result,
    )


def handle_mcp_request(
    payload: Dict[str, Any],
    *,
    principal: Dict[str, Any],
):
    method = str(
        payload.get("method")
        or ""
    )

    if method in REVOCATION_MCP_METHODS:
        return _handle_revocation_mcp_request(
            payload,
            principal=principal,
        )

    return _handle_mcp_request_without_revocation(
        payload,
        principal=principal,
    )
