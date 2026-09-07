from backend.research.multi_strategy_comparison import run_multi_strategy_comparison


def test_multi_strategy_comparison_metrics():
    report = run_multi_strategy_comparison()

    assert report["total_cases"] == 8
    assert report["risky_cases"] == 7

    metrics = report["metrics"]

    assert metrics["noguard_unsafe_allow_rate"] == 1.0
    assert abs(metrics["oauth_only_unsafe_allow_rate"] - (6 / 7)) < 0.000001
    assert metrics["agentguard_unsafe_allow_rate"] == 0.0


def test_agentguard_is_safer_than_oauth_only():
    report = run_multi_strategy_comparison()
    metrics = report["metrics"]

    assert metrics["agentguard_unsafe_allow_rate"] < metrics["oauth_only_unsafe_allow_rate"]
    assert metrics["oauth_only_unsafe_allow_rate"] < metrics["noguard_unsafe_allow_rate"]
