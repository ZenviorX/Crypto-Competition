from backend.research.oauth_comparison import OAuthComparisonRequest, run_oauth_comparison


def test_capability_token_is_not_issued_for_denied_request():
    result = run_oauth_comparison(
        OAuthComparisonRequest(scenario="scope_enough_but_task_boundary_denies")
    )

    assert result.agentguard["decision"] == "deny"

    token_info = result.agentguard["capability_token"]

    assert token_info["token_type"] == "agentguard_capability_token"
    assert token_info["issued"] is False
    assert "token" not in token_info
