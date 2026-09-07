from backend.evidence.coverage_matrix import build_coverage_matrix


def test_coverage_matrix_summarizes_defense_layers():
    report = {
        "summary": {"total": 2},
        "integrity": {"root_hash": "abc"},
        "effectiveness": {"summary": {"overall_effectiveness_score": 90}},
        "cases": [
            {
                "id": "normal_public_read",
                "category": "normal",
                "passed": True,
                "final_decision": "allow",
                "steps": [
                    {
                        "step_id": 1,
                        "tool": "file.read",
                        "decision": "allow",
                        "executed": True,
                        "output_labels": ["public"],
                    }
                ],
                "security_graph": {
                    "summary": {
                        "node_count": 2,
                        "edge_count": 1,
                        "high_risk_flow_count": 0,
                    }
                },
            },
            {
                "id": "prompt_injection_attack",
                "category": "attack",
                "passed": True,
                "final_decision": "confirm",
                "steps": [
                    {
                        "step_id": 1,
                        "tool": "file.read",
                        "decision": "allow",
                        "executed": True,
                        "output_labels": ["prompt_injection", "tainted"],
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
                        "high_risk_flow_count": 1,
                    }
                },
            },
        ],
    }

    coverage = build_coverage_matrix(report)
    summary = coverage["summary"]

    assert summary["total_cases"] == 2
    assert summary["coverage_score"] > 0
    assert summary["layer_counts"]["data_flow_graph"] == 2
    assert summary["layer_counts"]["integrity_chain"] == 2
    assert summary["layer_counts"]["effectiveness_baseline"] == 2
    assert summary["high_risk_flow_cases"] == 1
    assert summary["surface_counts"]["email"] == 1
