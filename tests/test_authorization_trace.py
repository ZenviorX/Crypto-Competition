from backend.research.multi_strategy_comparison import run_multi_strategy_comparison


def test_agentguard_block_stage_is_recorded():
    report = run_multi_strategy_comparison()

    rows = {row["scenario"]: row for row in report["cases"]}

    assert rows["normal_public_read"]["agentguard_block_stage"] == "none"

    assert rows["scope_enough_but_task_boundary_denies"]["agentguard_block_stage"] == "task_boundary"

    assert rows["scope_enough_but_sandbox_denies"]["agentguard_block_stage"] in {
        "task_boundary",
        "sandbox_policy",
    }

    assert rows["scope_enough_but_no_shell_sandbox_denies"]["agentguard_block_stage"] in {
        "task_boundary",
        "sandbox_policy",
    }
