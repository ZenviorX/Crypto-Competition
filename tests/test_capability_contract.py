from backend.research.oauth_comparison import OAuthComparisonRequest, run_oauth_comparison


def test_capability_contract_blocks_external_transmission():
    result = run_oauth_comparison(
        OAuthComparisonRequest(scenario="scope_enough_but_task_boundary_denies")
    )

    assert result.agentguard["decision"] == "deny"

    trace = result.agentguard["authorization_trace"]
    task_stage = next(item for item in trace if item["stage"] == "task_boundary")

    assert task_stage["decision"] == "deny"

    contract = task_stage["extra"]["capability_contract"]

    assert contract["contract_version"] == "capability_contract_v1"
    assert contract["external_transmission_allowed"] is False
