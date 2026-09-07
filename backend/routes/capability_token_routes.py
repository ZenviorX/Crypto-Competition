from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter

from backend.guardrails.capability_token import verify_capability_token
from backend.guardrails.capability_token_ledger import get_token_events, get_token_status, record_token_revoked


class CapabilityTokenStatusRequest(BaseModel):
    token: str


class CapabilityTokenRevokeRequest(BaseModel):
    token: str
    reason: str = "manual revoke"


router = APIRouter(
    prefix="/tool-proxy/capability-token",
    tags=["Capability Token"],
)


@router.post("/status")
def get_capability_token_status(request: CapabilityTokenStatusRequest):
    verified = verify_capability_token(request.token)

    if not verified.get("valid"):
        return {
            "valid": False,
            "reason": verified.get("reason", "Invalid capability token."),
            "ledger_status": "invalid",
        }

    payload = verified["payload"]
    token_id = payload.get("token_id", "")
    status = get_token_status(token_id)

    return {
        "valid": True,
        "token_id": token_id,
        "ledger_status": status["status"],
        "issued_at": status["issued_at"],
        "consumed_at": status["consumed_at"],
        "payload": payload,
    }



@router.post("/revoke")
def revoke_capability_token(request: CapabilityTokenRevokeRequest):
    verified = verify_capability_token(request.token)

    if not verified.get("valid"):
        return {
            "success": False,
            "valid": False,
            "reason": verified.get("reason", "Invalid capability token."),
        }

    payload = verified["payload"]
    token_id = payload.get("token_id", "")

    record_token_revoked(token_id, request.reason)

    status = get_token_status(token_id)

    return {
        "success": True,
        "valid": True,
        "token_id": token_id,
        "ledger_status": status["status"],
        "reason": request.reason,
    }



@router.post("/events")
def get_capability_token_events(request: CapabilityTokenStatusRequest):
    verified = verify_capability_token(request.token)

    if not verified.get("valid"):
        return {
            "valid": False,
            "reason": verified.get("reason", "Invalid capability token."),
            "events": [],
        }

    payload = verified["payload"]
    token_id = payload.get("token_id", "")

    return {
        "valid": True,
        "token_id": token_id,
        "events": get_token_events(token_id),
    }
