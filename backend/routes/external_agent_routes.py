from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.adapters.external_agent_adapter import (
    ExternalAgentSimulateRequest,
    ExternalAgentSimulateResponse,
    simulate_external_agent_call,
)


router = APIRouter(
    prefix="/external-agent",
    tags=["External Agent Adapter"],
)


@router.get("/health")
def external_agent_adapter_health():
    return {
        "success": True,
        "message": "External Agent Adapter is ready.",
        "supported_platforms": [
            "openclaw",
            "workbuddy",
            "custom",
        ],
        "supported_scenarios": [
            "valid_public_read",
            "insufficient_scope_email",
            "valid_internal_email_confirm",
            "sandbox_block_shell",
        ],
    }


@router.post(
    "/simulate",
    response_model=ExternalAgentSimulateResponse,
)
def simulate_external_agent(
    request: ExternalAgentSimulateRequest,
) -> ExternalAgentSimulateResponse:
    try:
        return simulate_external_agent_call(request)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"External Agent Adapter simulation failed: {exc}",
        ) from exc
