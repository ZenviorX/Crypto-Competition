from backend.guardrails.capability_token import verify_capability_token
from backend.research.oauth_comparison import OAuthComparisonRequest, run_oauth_comparison


def test_agentguard_issues_task_scoped_capability_token():
    result = run_oauth_comparison(
        OAuthComparisonRequest(scenario="normal_public_read")
    )

    token_info = result.agentguard["capability_token"]

    assert token_info["token_type"] == "agentguard_capability_token"
    assert token_info["payload"]["type"] == "agentguard_capability_token"

    verified = verify_capability_token(token_info["token"])

    assert verified["valid"] is True
    assert verified["payload"]["capability_contract"]["contract_version"] == "capability_contract_v1"


def test_capability_token_signature_detects_tampering():
    result = run_oauth_comparison(
        OAuthComparisonRequest(scenario="normal_public_read")
    )

    token = result.agentguard["capability_token"]["token"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    verified = verify_capability_token(tampered)

    assert verified["valid"] is False



def test_capability_secret_demo_uses_process_random_secret(
    monkeypatch,
):
    from backend.guardrails import (
        capability_token,
    )

    monkeypatch.setenv(
        "AGENTGUARD_MODE",
        "demo",
    )

    monkeypatch.delenv(
        "AGENTGUARD_CAPABILITY_SECRET",
        raising=False,
    )

    first = capability_token._secret()
    second = capability_token._secret()

    assert first == second
    assert len(first) >= 32

    readiness = (
        capability_token
        .capability_secret_readiness()
    )

    assert readiness["ready"] is True

    assert (
        readiness["production_ready"]
        is False
    )

    assert (
        readiness["source"]
        == "process_random"
    )


def test_capability_secret_rejects_legacy_default(
    monkeypatch,
):
    import pytest

    from backend.guardrails import (
        capability_token,
    )

    monkeypatch.setenv(
        "AGENTGUARD_CAPABILITY_SECRET",
        (
            "agentguard-dev-"
            "capability-secret"
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="legacy hard-coded",
    ):
        capability_token._secret()

    readiness = (
        capability_token
        .capability_secret_readiness()
    )

    assert (
        readiness["legacy_insecure"]
        is True
    )

    assert (
        readiness["production_ready"]
        is False
    )


def test_capability_secret_rejects_short_value(
    monkeypatch,
):
    import pytest

    from backend.guardrails import (
        capability_token,
    )

    monkeypatch.setenv(
        "AGENTGUARD_CAPABILITY_SECRET",
        "too-short",
    )

    with pytest.raises(
        RuntimeError,
        match="at least 32",
    ):
        capability_token._secret()


def test_capability_secret_accepts_secure_environment_value(
    monkeypatch,
):
    from backend.guardrails import (
        capability_token,
    )

    configured = (
        "agentguard-test-capability-secret-"
        "0123456789abcdef"
    )

    monkeypatch.setenv(
        "AGENTGUARD_MODE",
        "competition",
    )

    monkeypatch.setenv(
        "AGENTGUARD_CAPABILITY_SECRET",
        configured,
    )

    assert (
        capability_token._secret()
        == configured.encode("utf-8")
    )

    readiness = (
        capability_token
        .capability_secret_readiness()
    )

    assert readiness["ready"] is True

    assert (
        readiness["production_ready"]
        is True
    )

    assert (
        readiness["source"]
        == "environment"
    )
