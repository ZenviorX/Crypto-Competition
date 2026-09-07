from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from backend.guardrails.capability_token_ledger import (
    claim_token_for_execution,
    finalize_token_execution,
    get_token_status,
    record_token_consumed,
    record_token_issued,
)





_PROCESS_CAPABILITY_SECRET = (
    secrets.token_urlsafe(48)
    .encode("utf-8")
)

_LEGACY_INSECURE_CAPABILITY_SECRET = (
    "agentguard-dev-capability-secret"
)


def capability_secret_readiness(
) -> Dict[str, Any]:
    """
    返回 Capability Token 签名密钥状态。

    demo 模式允许使用进程级随机密钥；
    competition/生产部署应显式配置至少
    32 字节的 AGENTGUARD_CAPABILITY_SECRET。
    """
    mode = str(
        os.getenv(
            "AGENTGUARD_MODE",
            "demo",
        )
        or "demo"
    ).strip().lower()

    configured_value = str(
        os.getenv(
            "AGENTGUARD_CAPABILITY_SECRET",
            "",
        )
        or ""
    )

    configured_bytes = (
        configured_value.encode(
            "utf-8"
        )
    )

    legacy_insecure = (
        configured_value
        == _LEGACY_INSECURE_CAPABILITY_SECRET
    )

    configured_securely = bool(
        configured_value
        and len(configured_bytes) >= 32
        and not legacy_insecure
    )

    production_ready = (
        configured_securely
    )

    runtime_ready = bool(
        configured_securely
        or mode != "competition"
    )

    if configured_securely:
        source = "environment"

    elif configured_value:
        source = (
            "invalid_environment"
        )

    else:
        source = "process_random"

    if configured_securely:
        reason = (
            "Capability Token signing uses "
            "an explicitly configured secret."
        )

    elif legacy_insecure:
        reason = (
            "The legacy hard-coded Capability "
            "Token secret is forbidden."
        )

    elif configured_value:
        reason = (
            "AGENTGUARD_CAPABILITY_SECRET "
            "must contain at least 32 UTF-8 bytes."
        )

    elif mode == "competition":
        reason = (
            "Competition mode requires an explicit "
            "AGENTGUARD_CAPABILITY_SECRET."
        )

    else:
        reason = (
            "Demo mode uses a process-random "
            "Capability Token signing secret."
        )

    return {
        "ready": runtime_ready,
        "production_ready": (
            production_ready
        ),
        "mode": mode,
        "configured": bool(
            configured_value
        ),
        "configured_securely": (
            configured_securely
        ),
        "source": source,
        "minimum_bytes": 32,
        "configured_bytes": len(
            configured_bytes
        ),
        "legacy_insecure": (
            legacy_insecure
        ),
        "reason": reason,
    }


def _secret() -> bytes:
    configured_value = str(
        os.getenv(
            "AGENTGUARD_CAPABILITY_SECRET",
            "",
        )
        or ""
    )

    if not configured_value:
        return (
            _PROCESS_CAPABILITY_SECRET
        )

    if (
        configured_value
        == _LEGACY_INSECURE_CAPABILITY_SECRET
    ):
        raise RuntimeError(
            "The legacy hard-coded "
            "AGENTGUARD_CAPABILITY_SECRET "
            "is forbidden."
        )

    configured_bytes = (
        configured_value.encode(
            "utf-8"
        )
    )

    if len(configured_bytes) < 32:
        raise RuntimeError(
            "AGENTGUARD_CAPABILITY_SECRET "
            "must contain at least "
            "32 UTF-8 bytes."
        )

    return configured_bytes



def _b64(data: bytes) -> str:
    return (
        base64.urlsafe_b64encode(data)
        .decode("utf-8")
        .rstrip("=")
    )


def _json_b64(
    payload: Dict[str, Any],
) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return _b64(raw)


def _stable_hash(value: Any) -> str:
    raw = json.dumps(
        value or {},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        raw
    ).hexdigest()[:16]


def _sign(data: str) -> str:
    digest = hmac.new(
        _secret(),
        data.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return _b64(digest)


def _decode_payload_part(
    payload_part: str,
) -> Dict[str, Any]:
    padded = (
        payload_part
        + "=" * (-len(payload_part) % 4)
    )

    decoded = base64.urlsafe_b64decode(
        padded.encode("utf-8")
    ).decode("utf-8")

    payload = json.loads(decoded)

    if not isinstance(payload, dict):
        raise ValueError(
            "Capability token payload must be an object."
        )

    return payload


def _ledger_denial_reason(
    ledger_state: str,
) -> str:
    reasons = {
        "unknown": (
            "Capability token is not present "
            "in the trusted ledger."
        ),
        "executing": (
            "Capability token is already reserved "
            "by another execution."
        ),
        "consumed": (
            "Capability token has already been consumed."
        ),
        "failed": (
            "Capability token belongs to a previous "
            "failed execution and cannot be reused."
        ),
        "revoked": (
            "Capability token has been revoked."
        ),
    }

    return reasons.get(
        ledger_state,
        (
            "Capability token is not in an "
            "executable ledger state."
        ),
    )


def issue_capability_token(
    user: str,
    agent_platform: str,
    original_task: str,
    capability_contract: Dict[str, Any],
    tool: str = "",
    params: Optional[Dict[str, Any]] = None,
    sandbox_profile: str = "",
    ttl_minutes: int = 15,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    # Negative TTL values intentionally create an already
    # expired token. This is safe and is also required for
    # deterministic expiry and security regression tests.
    ttl_value = int(
        ttl_minutes
    )

    expires_at = now + timedelta(
        minutes=ttl_value
    )

    payload = {
        "type": (
            "agentguard_capability_token"
        ),
        "version": "v1",
        "token_id": hashlib.sha256(
            (
                f"{user}:"
                f"{agent_platform}:"
                f"{original_task}:"
                f"{tool}:"
                f"{_stable_hash(params or {})}:"
                f"{now.isoformat()}"
            ).encode("utf-8")
        ).hexdigest()[:16],
        "user": str(user),
        "agent_platform": str(
            agent_platform
        ),
        "task_hash": hashlib.sha256(
            str(original_task).encode(
                "utf-8"
            )
        ).hexdigest()[:16],
        "tool": str(tool),
        "params_hash": _stable_hash(
            params or {}
        ),
        "sandbox_profile": str(
            sandbox_profile
        ),
        "capability_contract": (
            capability_contract
        ),
        "issued_at": now.isoformat(),
        "expires_at": (
            expires_at.isoformat()
        ),
    }

    payload_part = _json_b64(
        payload
    )
    signature = _sign(
        payload_part
    )
    token = (
        f"{payload_part}.{signature}"
    )

    record_token_issued(
        str(
            payload.get(
                "token_id",
                "",
            )
        ),
        payload,
    )

    return {
        "token_type": (
            "agentguard_capability_token"
        ),
        "token": token,
        "payload": payload,
    }


def verify_capability_token(
    token: str,
) -> Dict[str, Any]:
    try:
        payload_part, signature = (
            str(token).split(
                ".",
                1,
            )
        )
    except ValueError:
        return {
            "valid": False,
            "reason": (
                "Malformed capability token."
            ),
        }

    expected = _sign(
        payload_part
    )

    if not hmac.compare_digest(
        signature,
        expected,
    ):
        return {
            "valid": False,
            "reason": (
                "Invalid capability token "
                "signature."
            ),
        }

    try:
        payload = _decode_payload_part(
            payload_part
        )
    except Exception as exc:
        return {
            "valid": False,
            "reason": (
                "Capability token payload "
                f"cannot be decoded: {exc}"
            ),
        }

    if (
        payload.get("type")
        != "agentguard_capability_token"
    ):
        return {
            "valid": False,
            "reason": (
                "Unexpected capability token type."
            ),
            "payload": payload,
        }

    try:
        expires_at = (
            datetime.fromisoformat(
                str(payload["expires_at"])
            )
        )
    except Exception:
        return {
            "valid": False,
            "reason": (
                "Capability token expiry "
                "is missing or invalid."
            ),
            "payload": payload,
        }

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if (
        datetime.now(timezone.utc)
        > expires_at
    ):
        return {
            "valid": False,
            "reason": (
                "Capability token expired."
            ),
            "payload": payload,
        }

    token_id = str(
        payload.get(
            "token_id",
            "",
        )
    ).strip()

    if not token_id:
        return {
            "valid": False,
            "reason": (
                "Capability token does not "
                "contain token_id."
            ),
            "payload": payload,
        }

    return {
        "valid": True,
        "reason": (
            "Capability token signature "
            "and expiry are valid."
        ),
        "payload": payload,
    }


def validate_capability_token_for_request(
    token: str,
    user: str,
    agent_platform: str,
    original_task: str,
    expected_contract: Dict[str, Any],
    tool: str = "",
    params: Optional[Dict[str, Any]] = None,
    sandbox_profile: str = "",
    require_token: bool = False,
) -> Dict[str, Any]:
    if not token:
        if require_token:
            return {
                "provided": False,
                "decision": "deny",
                "risk_delta": 100,
                "ledger_status": (
                    "not_provided"
                ),
                "reason": [
                    (
                        "Execution request must "
                        "provide a valid task-scoped "
                        "capability token."
                    )
                ],
            }

        return {
            "provided": False,
            "decision": "allow",
            "risk_delta": 0,
            "ledger_status": (
                "not_provided"
            ),
            "reason": [
                (
                    "No capability token provided; "
                    "this request is treated as an "
                    "initial authorization request."
                )
            ],
        }

    verified = verify_capability_token(
        token
    )

    if not verified.get("valid"):
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": "invalid",
            "reason": [
                str(
                    verified.get(
                        "reason",
                        (
                            "Invalid capability "
                            "token."
                        ),
                    )
                )
            ],
        }

    payload = dict(
        verified["payload"]
    )

    expected_task_hash = (
        hashlib.sha256(
            str(original_task).encode(
                "utf-8"
            )
        ).hexdigest()[:16]
    )

    reasons = [
        (
            "Capability token signature "
            "and expiry were verified."
        )
    ]

    token_id = str(
        payload.get(
            "token_id",
            "",
        )
    )

    ledger_status = get_token_status(
        token_id
    )

    ledger_state = str(
        ledger_status.get(
            "status",
            "unknown",
        )
    )

    # A cryptographically valid token is not enough.
    # It must also exist in the trusted ledger and
    # remain in the single executable state: issued.
    if ledger_state != "issued":
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": ledger_state,
            "token_id": token_id,
            "reason": reasons
            + [
                _ledger_denial_reason(
                    ledger_state
                )
            ],
        }

    if payload.get("user") != user:
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token user does "
                    "not match current request user."
                )
            ],
        }

    if (
        payload.get("agent_platform")
        != agent_platform
    ):
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token agent platform "
                    "does not match current request."
                )
            ],
        }

    if (
        payload.get("task_hash")
        != expected_task_hash
    ):
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token is bound "
                    "to a different original task."
                )
            ],
        }

    if payload.get(
        "tool",
        "",
    ) != tool:
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token is bound "
                    "to a different tool."
                )
            ],
        }

    if payload.get(
        "params_hash",
        "",
    ) != _stable_hash(
        params or {}
    ):
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token is bound "
                    "to different tool parameters."
                )
            ],
        }

    if payload.get(
        "sandbox_profile",
        "",
    ) != sandbox_profile:
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token is bound "
                    "to a different sandbox profile."
                )
            ],
        }

    if (
        payload.get(
            "capability_contract"
        )
        != expected_contract
    ):
        return {
            "provided": True,
            "decision": "deny",
            "risk_delta": 100,
            "ledger_status": (
                ledger_state
            ),
            "token_id": token_id,
            "reason": reasons
            + [
                (
                    "Capability token contract "
                    "does not match the current "
                    "derived contract."
                )
            ],
        }

    return {
        "provided": True,
        "decision": "allow",
        "risk_delta": 0,
        "ledger_status": (
            ledger_state
        ),
        "token_id": token_id,
        "reason": reasons
        + [
            (
                "Capability token matches the "
                "current task, user, agent, tool, "
                "parameters and sandbox profile."
            ),
            (
                "Capability token is available "
                "for atomic execution claim."
            ),
        ],
    }


def claim_capability_token_for_execution(
    token: str,
    execution_id: str,
) -> Dict[str, Any]:
    """
    Atomically reserve a verified capability token
    for one exact execution attempt.
    """

    verified = verify_capability_token(
        token
    )

    if not verified.get("valid"):
        return {
            "acquired": False,
            "status": "invalid",
            "reason": str(
                verified.get(
                    "reason",
                    (
                        "Invalid capability "
                        "token."
                    ),
                )
            ),
        }

    payload = dict(
        verified.get(
            "payload",
            {},
        )
    )

    token_id = str(
        payload.get(
            "token_id",
            "",
        )
    ).strip()

    result = claim_token_for_execution(
        token_id=token_id,
        execution_id=str(
            execution_id
        ),
    )

    result = dict(result)
    result["token_id"] = token_id
    result["token_verified"] = True

    return result


def finalize_capability_token_execution(
    token: str,
    execution_id: str,
    outcome: str,
    result_hash: str = "",
    failure_reason: str = "",
) -> Dict[str, Any]:
    """
    Finalize the exact execution that atomically
    claimed the capability token.
    """

    verified = verify_capability_token(
        token
    )

    if not verified.get("valid"):
        return {
            "finalized": False,
            "status": "invalid",
            "reason": str(
                verified.get(
                    "reason",
                    (
                        "Invalid capability "
                        "token."
                    ),
                )
            ),
        }

    payload = dict(
        verified.get(
            "payload",
            {},
        )
    )

    token_id = str(
        payload.get(
            "token_id",
            "",
        )
    ).strip()

    result = finalize_token_execution(
        token_id=token_id,
        execution_id=str(
            execution_id
        ),
        outcome=str(outcome),
        result_hash=str(
            result_hash or ""
        ),
        failure_reason=str(
            failure_reason or ""
        ),
    )

    result = dict(result)
    result["token_id"] = token_id
    result["token_verified"] = True

    return result


def mark_capability_token_consumed(
    token: str,
) -> Dict[str, Any]:
    """
    Legacy compatibility wrapper.

    New execution code must use:
      claim_capability_token_for_execution()
      finalize_capability_token_execution()
    """

    verified = verify_capability_token(
        token
    )

    if not verified.get("valid"):
        return {
            "consumed": False,
            "reason": str(
                verified.get(
                    "reason",
                    (
                        "Invalid capability "
                        "token."
                    ),
                )
            ),
        }

    payload = dict(
        verified.get(
            "payload",
            {},
        )
    )

    token_id = str(
        payload.get(
            "token_id",
            "",
        )
    )

    if not token_id:
        return {
            "consumed": False,
            "reason": (
                "Capability token does not "
                "contain token_id."
            ),
        }

    record_token_consumed(
        token_id
    )

    return {
        "consumed": True,
        "token_id": token_id,
        "reason": (
            "Capability token was consumed "
            "through the legacy compatibility path."
        ),
    }
