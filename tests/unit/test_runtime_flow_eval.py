from experiments.runtime_flow_eval import (
    evaluate_runtime_flows,
    load_runtime_flow_cases,
    run_runtime_flow_case,
)


def test_runtime_flow_cases_all_pass():
    report = evaluate_runtime_flows()

    assert report["summary"]["total_cases"] >= 4
    assert report["summary"]["failed_cases"] == 0
    assert report["summary"]["high_risk_flow_total"] >= 1


def test_prompt_injection_runtime_flow_produces_lineage_graph():
    cases = load_runtime_flow_cases()
    case = next(
        item
        for item in cases
        if item["id"] == "runtime_prompt_injection_public_read_then_email"
    )

    result = run_runtime_flow_case(case)

    assert result["passed"] is True

    graph = result["security_graph"]

    assert graph["summary"]["high_risk_flow_count"] >= 1
    assert graph["graph_risk_level"] in {"high", "critical"}

    assert any(
        edge["source"] == "step:1"
        and edge["target"] == "step:2"
        and "prompt_injection" in edge["labels"]
        and "tainted" in edge["labels"]
        for edge in graph["edges"]
    )

    assert any(
        flow["target_tool"] == "email.send"
        and "prompt_injection" in flow["risky_labels"]
        for flow in graph["high_risk_flows"]
    )


def test_secret_read_runtime_flow_blocks_before_second_step():
    cases = load_runtime_flow_cases()
    case = next(
        item
        for item in cases
        if item["id"] == "runtime_secret_read_blocked_before_exfiltration"
    )

    result = run_runtime_flow_case(case)

    assert result["passed"] is True
    assert result["summary"]["is_blocked"] is True
    assert result["summary"]["recorded_step_count"] == 1
    assert result["summary"]["executed_step_count"] == 0
