from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.tool_proxy_service import (
    _enforce_proxy_response_invariants,
    authorize_tool_call,
)


def test_execute_request_without_capability_token_is_denied():
    request = ToolProxyAuthorizeRequest(
        user="user",
        original_task="请读取 public/notice.txt 并总结",
        tool="file.read",
        params={"path": "public/notice.txt"},
        requested_scopes=["tool:file:read"],
        oauth_token_claims={"scope": "tool:file:read"},
        auth_mode="oauth_scope",
        agent_platform="openclaw",
        sandbox_profile="local_readonly",
        execute=True,
        capability_token="",
    )

    result = authorize_tool_call(request)

    assert result.decision == "deny"
    assert result.executed is False

    token_stage = next(
        item for item in result.authorization_trace
        if item["stage"] == "capability_token"
    )

    assert token_stage["decision"] == "deny"
    assert token_stage["extra"]["provided"] is False



def _invariant_request(
    *,
    execute: bool,
) -> ToolProxyAuthorizeRequest:
    return ToolProxyAuthorizeRequest(
        user="user",
        original_task=(
            "请读取 public/notice.txt"
        ),
        tool="file.read",
        params={
            "path": "public/notice.txt"
        },
        execute=execute,
    )


def test_execution_allow_requires_consumed_capability_token():
    result, token = (
        _enforce_proxy_response_invariants(
            request=_invariant_request(
                execute=True
            ),
            result_dict={
                "decision": "allow",
                "risk_score": 10,
                "reason": [],
            },
            executed=True,
            capability_token={
                "issued": False
            },
            capability_token_validation={
                "execution_claim": {
                    "acquired": True
                },
                "execution_finalization": {
                    "finalized": False,
                    "status": "executing",
                },
            },
            sandbox_evidence={
                "executed": True
            },
        )
    )

    assert result["decision"] == "deny"
    assert result["risk_score"] == 100
    assert token["issued"] is False

    assert any(
        "token_finalization" in item
        or "token_consumption" in item
        for item in result["reason"]
    )


def test_successful_execution_preserves_allow():
    result, token = (
        _enforce_proxy_response_invariants(
            request=_invariant_request(
                execute=True
            ),
            result_dict={
                "decision": "allow",
                "risk_score": 10,
                "reason": [],
            },
            executed=True,
            capability_token={
                "issued": False
            },
            capability_token_validation={
                "execution_claim": {
                    "acquired": True
                },
                "execution_finalization": {
                    "finalized": True,
                    "consumed": True,
                    "status": "consumed",
                },
                "consumption": {
                    "acquired": True,
                    "finalized": True,
                    "consumed": True,
                    "status": "consumed",
                },
            },
            sandbox_evidence={
                "executed": True
            },
        )
    )

    assert result["decision"] == "allow"
    assert token["issued"] is False


def test_prepare_allow_requires_issued_token():
    result, token = (
        _enforce_proxy_response_invariants(
            request=_invariant_request(
                execute=False
            ),
            result_dict={
                "decision": "allow",
                "risk_score": 10,
                "reason": [],
            },
            executed=False,
            capability_token={
                "issued": False
            },
            capability_token_validation={},
            sandbox_evidence=None,
        )
    )

    assert result["decision"] == "deny"
    assert result["risk_score"] == 100
    assert token["issued"] is False


def test_prepare_allow_with_token_remains_allow():
    result, token = (
        _enforce_proxy_response_invariants(
            request=_invariant_request(
                execute=False
            ),
            result_dict={
                "decision": "allow",
                "risk_score": 10,
                "reason": [],
            },
            executed=False,
            capability_token={
                "token_type": (
                    "agentguard_capability_token"
                ),
                "issued": True,
                "token": "private-test-token",
            },
            capability_token_validation={},
            sandbox_evidence=None,
        )
    )

    assert result["decision"] == "allow"
    assert token["issued"] is True
    assert (
        token["token"]
        == "private-test-token"
    )


def test_denied_result_scrubs_capability_token():
    result, token = (
        _enforce_proxy_response_invariants(
            request=_invariant_request(
                execute=False
            ),
            result_dict={
                "decision": "deny",
                "risk_score": 100,
                "reason": ["blocked"],
            },
            executed=False,
            capability_token={
                "token_type": (
                    "agentguard_capability_token"
                ),
                "issued": True,
                "token": (
                    "must-not-leave-service"
                ),
            },
            capability_token_validation={},
            sandbox_evidence=None,
        )
    )

    assert result["decision"] == "deny"
    assert token["issued"] is False
    assert "token" not in token


def test_unknown_final_decision_fails_closed():
    result, token = (
        _enforce_proxy_response_invariants(
            request=_invariant_request(
                execute=False
            ),
            result_dict={
                "decision": "maybe",
                "risk_score": 0,
                "reason": [],
            },
            executed=False,
            capability_token={
                "issued": True,
                "token": "must-be-removed",
            },
            capability_token_validation={},
            sandbox_evidence=None,
        )
    )

    assert result["decision"] == "deny"
    assert result["risk_score"] == 100
    assert token["issued"] is False
    assert "token" not in token
