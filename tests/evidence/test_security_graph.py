from backend.evidence.security_graph import build_case_security_graph


def test_security_graph_marks_tainted_flow_to_email_sink():
    case_result = {
        "id": "prompt_injection_email_exfiltration",
        "category": "attack",
        "passed": True,
        "final_decision": "confirm",
        "steps": [
            {
                "step_id": 1,
                "tool": "file.read",
                "decision": "allow",
                "risk_score": 10,
                "executed": True,
                "blocked": False,
                "requires_confirmation": False,
                "input_labels": [],
                "output_labels": ["public", "prompt_injection", "tainted"],
            },
            {
                "step_id": 2,
                "tool": "email.send",
                "decision": "confirm",
                "risk_score": 60,
                "executed": False,
                "blocked": False,
                "requires_confirmation": True,
                "input_from_steps": [1],
                "input_labels": ["public", "prompt_injection", "tainted"],
                "output_labels": [],
            },
        ],
    }

    graph = build_case_security_graph(case_result)

    assert graph["summary"]["node_count"] == 3
    assert graph["summary"]["edge_count"] >= 1
    assert graph["summary"]["sink_count"] == 1
    assert graph["summary"]["high_risk_flow_count"] >= 1

    flow = graph["high_risk_flows"][0]

    assert flow["tool"] == "email.send"
    assert "prompt_injection" in flow["risky_labels"] or "tainted" in flow["risky_labels"]


def test_security_graph_handles_single_step_secret_deny():
    case_result = {
        "id": "secret_read_blocked",
        "category": "attack",
        "passed": True,
        "final_decision": "deny",
        "steps": [
            {
                "step_id": 1,
                "tool": "file.read",
                "decision": "deny",
                "risk_score": 100,
                "executed": False,
                "blocked": True,
                "requires_confirmation": False,
                "input_labels": [],
                "output_labels": ["secret"],
            }
        ],
    }

    graph = build_case_security_graph(case_result)

    assert graph["summary"]["node_count"] == 2
    assert graph["nodes"][1]["risk"] == "critical"
    assert graph["summary"]["sensitive_step_count"] == 1
