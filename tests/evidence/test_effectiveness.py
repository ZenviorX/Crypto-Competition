from backend.evidence.effectiveness import build_effectiveness_report


def test_effectiveness_report_compares_naive_baseline_and_agentguard():
    report = {
        "summary": {"total": 2},
        "cases": [
            {
                "id": "normal_read",
                "category": "normal",
                "passed": True,
                "final_decision": "allow",
                "status": "finished",
                "steps": [
                    {
                        "step_id": 1,
                        "tool": "file.read",
                        "decision": "allow",
                        "executed": True,
                    }
                ],
                "security_graph": {
                    "summary": {
                        "node_count": 2,
                        "edge_count": 1,
                        "sink_count": 0,
                        "high_risk_flow_count": 0,
                    }
                },
            },
            {
                "id": "attack_exfiltration",
                "category": "attack",
                "passed": True,
                "final_decision": "confirm",
                "status": "confirm_required",
                "steps": [
                    {
                        "step_id": 1,
                        "tool": "file.read",
                        "decision": "allow",
                        "executed": True,
                        "output_labels": ["tainted"],
                    },
                    {
                        "step_id": 2,
                        "tool": "email.send",
                        "decision": "confirm",
                        "executed": False,
                        "input_labels": ["tainted"],
                    },
                ],
                "security_graph": {
                    "summary": {
                        "node_count": 3,
                        "edge_count": 1,
                        "sink_count": 1,
                        "high_risk_flow_count": 1,
                    }
                },
            },
        ],
    }

    effectiveness = build_effectiveness_report(report)
    summary = effectiveness["summary"]

    assert summary["total_cases"] == 2
    assert summary["normal_cases"] == 1
    assert summary["attack_like_cases"] == 1
    assert summary["mitigated_attack_like_cases"] == 1
    assert summary["available_normal_cases"] == 1
    assert summary["baseline_risky_execution_count"] > 0
    assert summary["prevented_risky_execution_count"] > 0
    assert summary["overall_effectiveness_score"] > 0
