from backend.research.oauth_comparison import OAuthComparisonRequest, run_oauth_comparison


def test_untrusted_input_cannot_trigger_side_effect_tool():
    result = run_oauth_comparison(
        OAuthComparisonRequest(
            scenario="scope_enough_but_untrusted_input_drives_email_denies"
        )
    )

    assert result.oauth_only["decision"] == "allow"
    assert result.agentguard["decision"] == "deny"

    task_stage = next(
        item for item in result.agentguard["authorization_trace"]
        if item["stage"] == "task_boundary"
    )

    assert task_stage["decision"] == "deny"

    reasons = " ".join(task_stage["reason"])
    assert "Untrusted" in reasons or "prompt-injected" in reasons
