from backend.evidence.graph_renderer import render_security_graph_html


def test_render_security_graph_html_contains_svg_and_flow_table():
    graph = {
        "case_id": "graph_case",
        "nodes": [
            {
                "id": "case:graph_case",
                "type": "case",
                "label": "graph_case",
                "risk": "medium",
            },
            {
                "id": "step:1",
                "type": "step",
                "step_id": 1,
                "tool": "file.read",
                "label": "Step 1: file.read",
                "decision": "allow",
                "risk": "low",
                "output_labels": ["tainted"],
            },
            {
                "id": "step:2",
                "type": "step",
                "step_id": 2,
                "tool": "email.send",
                "label": "Step 2: email.send",
                "decision": "confirm",
                "risk": "high",
                "input_labels": ["tainted"],
            },
        ],
        "edges": [
            {
                "source": "step:1",
                "target": "step:2",
                "labels": ["tainted"],
                "risk": "high",
            }
        ],
        "high_risk_flows": [
            {
                "source": "step:1",
                "target": "step:2",
                "tool": "email.send",
                "risky_labels": ["tainted"],
                "decision": "confirm",
                "risk": "high",
            }
        ],
        "summary": {
            "node_count": 3,
            "edge_count": 1,
            "sink_count": 1,
            "high_risk_flow_count": 1,
        },
    }

    html = render_security_graph_html(
        graph,
        report_file="Result_001.json",
        case_id="graph_case",
    )

    assert "Runtime Security Graph" in html
    assert "<svg" in html
    assert "email.send" in html
    assert "High-risk Flow Evidence" in html
    assert "tainted" in html
