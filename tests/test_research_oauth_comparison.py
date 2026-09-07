from backend.research.oauth_comparison import (
    OAuthComparisonRequest,
    run_oauth_comparison,
)


def test_oauth_only_allows_but_agentguard_denies_risky_external_email():
    result = run_oauth_comparison(
        OAuthComparisonRequest(
            scenario="scope_enough_but_sandbox_denies"
        )
    )

    assert result.oauth_only["decision"] == "allow"
    assert result.agentguard["decision"] == "deny"
    assert result.conclusion["research_value"] == "high"


def test_missing_scope_is_denied_by_both():
    result = run_oauth_comparison(
        OAuthComparisonRequest(
            scenario="scope_missing_email"
        )
    )

    assert result.oauth_only["decision"] == "deny"
    assert result.agentguard["decision"] == "deny"


def test_normal_public_read_is_safe():
    result = run_oauth_comparison(
        OAuthComparisonRequest(
            scenario="normal_public_read"
        )
    )

    assert result.oauth_only["decision"] == "allow"
    assert result.agentguard["decision"] in {"allow", "confirm"}
