from __future__ import annotations

from typing import Any, Dict, List, Optional


def _stage(name: str, decision: str, reason: Any, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if isinstance(reason, list):
        reasons = [str(item) for item in reason]
    elif reason:
        reasons = [str(reason)]
    else:
        reasons = []

    return {
        "stage": name,
        "decision": decision,
        "reason": reasons,
        "extra": extra or {},
    }


def build_authorization_trace(
    agent_auth_profile: Dict[str, Any],
    capability_token_validation: Optional[Dict[str, Any]],
    task_boundary_evaluation: Dict[str, Any],
    sandbox_evaluation: Dict[str, Any],
    final_decision: str,
    final_risk_score: int,
    executed: bool,
) -> List[Dict[str, Any]]:
    capability_token_validation = capability_token_validation or {
        "provided": False,
        "decision": "allow",
        "risk_delta": 0,
        "reason": ["No capability token validation result."],
    }

    return [
        _stage(
            "oauth_scope",
            str(agent_auth_profile.get("scope_decision", "pass")),
            agent_auth_profile.get("explanation"),
            {
                "required_scopes": agent_auth_profile.get("required_scopes", []),
                "declared_scopes": agent_auth_profile.get("declared_scopes", []),
                "missing_scopes": agent_auth_profile.get("missing_scopes", []),
            },
        ),
        _stage(
            "capability_token",
            str(capability_token_validation.get("decision", "allow")),
            capability_token_validation.get("reason", []),
            {
                "provided": capability_token_validation.get("provided", False),
                "ledger_status": capability_token_validation.get("ledger_status", "unknown"),
                "risk_delta": capability_token_validation.get("risk_delta", 0),
                "consumption": capability_token_validation.get("consumption", {}),
            },
        ),
        _stage(
            "task_boundary",
            str(task_boundary_evaluation.get("decision", "allow")),
            task_boundary_evaluation.get("reason", []),
            {
                "policy": task_boundary_evaluation.get("policy"),
                "risk_delta": task_boundary_evaluation.get("risk_delta", 0),
                "capability_contract": task_boundary_evaluation.get("capability_contract", {}),
            },
        ),
        _stage(
            "sandbox_policy",
            str(sandbox_evaluation.get("decision", "allow")),
            sandbox_evaluation.get("reason", []),
            {
                "profile": sandbox_evaluation.get("profile"),
                "risk_delta": sandbox_evaluation.get("risk_delta", 0),
            },
        ),
        _stage(
            "final_decision",
            final_decision,
            [f"Final risk score = {final_risk_score}", f"Executed = {executed}"],
            {},
        ),
    ]
