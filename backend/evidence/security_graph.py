from __future__ import annotations

from typing import Any, Dict, List


SINK_TOOLS = {
    "email.send",
    "shell.run",
    "file.write",
    "file.delete",
    "db.query",
    "http.post",
    "code.exec",
    "run_code",
}

EXTERNAL_SINK_TOOLS = {
    "email.send",
    "http.post",
}

RISKY_LABELS = {
    "tainted",
    "prompt_injection",
    "unknown",
    "sensitive",
    "secret",
    "credential",
}

CRITICAL_LABELS = {
    "sensitive",
    "secret",
    "credential",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _unique(values: List[Any]) -> List[Any]:
    result: List[Any] = []
    seen = set()

    for value in values:
        marker = repr(value)

        if marker in seen:
            continue

        seen.add(marker)
        result.append(value)

    return result


def _step_labels(step: Dict[str, Any]) -> List[str]:
    labels: List[str] = []

    for label in _as_list(step.get("input_labels")):
        labels.append(str(label))

    for label in _as_list(step.get("output_labels")):
        labels.append(str(label))

    return _unique(labels)


def _node_risk(step: Dict[str, Any]) -> str:
    labels = set(_step_labels(step))
    tool = str(step.get("tool", ""))

    if step.get("decision") == "deny":
        return "critical"

    if set(labels) & CRITICAL_LABELS:
        return "critical"

    if step.get("decision") == "confirm":
        return "high"

    if tool in SINK_TOOLS and set(labels) & RISKY_LABELS:
        return "high"

    if set(labels) & RISKY_LABELS:
        return "medium"

    if tool in SINK_TOOLS:
        return "medium"

    return "low"


def _edge_risk(labels: List[str], target_tool: str) -> str:
    label_set = set(labels)

    if label_set & CRITICAL_LABELS and target_tool in SINK_TOOLS:
        return "critical"

    if label_set & RISKY_LABELS and target_tool in SINK_TOOLS:
        return "high"

    if label_set & RISKY_LABELS:
        return "medium"

    return "low"


def _extract_step_index(step: Dict[str, Any]) -> int:
    try:
        return int(step.get("step_id") or step.get("step_index") or 0)
    except (TypeError, ValueError):
        return 0


def build_case_security_graph(case_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    将单个 Benchmark case 转换为可展示的数据流安全图谱。
    """
    steps = case_result.get("steps", [])

    if not isinstance(steps, list):
        steps = []

    normalized_steps = [
        step
        for step in steps
        if isinstance(step, dict)
    ]

    step_by_id = {
        _extract_step_index(step): step
        for step in normalized_steps
    }

    nodes: List[Dict[str, Any]] = [
        {
            "id": f"case:{case_result.get('id')}",
            "type": "case",
            "label": str(case_result.get("id")),
            "category": case_result.get("category"),
            "passed": case_result.get("passed"),
            "final_decision": case_result.get("final_decision"),
            "risk": "critical" if case_result.get("final_decision") == "deny" else "medium",
        }
    ]

    edges: List[Dict[str, Any]] = []
    high_risk_flows: List[Dict[str, Any]] = []

    for step in normalized_steps:
        step_id = _extract_step_index(step)
        tool = str(step.get("tool", "unknown"))
        input_labels = [str(item) for item in _as_list(step.get("input_labels"))]
        output_labels = [str(item) for item in _as_list(step.get("output_labels"))]
        labels = _unique(input_labels + output_labels)

        nodes.append(
            {
                "id": f"step:{step_id}",
                "type": "step",
                "step_id": step_id,
                "tool": tool,
                "label": f"Step {step_id}: {tool}",
                "decision": step.get("decision"),
                "risk_score": step.get("risk_score"),
                "executed": step.get("executed"),
                "blocked": step.get("blocked"),
                "requires_confirmation": step.get("requires_confirmation"),
                "input_labels": input_labels,
                "output_labels": output_labels,
                "risk": _node_risk(step),
            }
        )

        input_from_steps = _as_list(
            (step.get("real_params") or {}).get("input_from_steps")
            or step.get("input_from_steps")
        )

        if not input_from_steps:
            edges.append(
                {
                    "source": f"case:{case_result.get('id')}",
                    "target": f"step:{step_id}",
                    "edge_type": "case_input_to_step",
                    "labels": input_labels,
                    "risk": _edge_risk(input_labels, tool),
                }
            )

        for source_step_id in input_from_steps:
            try:
                source_step_id = int(source_step_id)
            except (TypeError, ValueError):
                continue

            source_step = step_by_id.get(source_step_id, {})
            source_labels = [
                str(item)
                for item in _as_list(source_step.get("output_labels"))
            ]

            edge_labels = _unique(source_labels + input_labels)
            edge_risk = _edge_risk(edge_labels, tool)

            edge = {
                "source": f"step:{source_step_id}",
                "target": f"step:{step_id}",
                "source_step": source_step_id,
                "target_step": step_id,
                "edge_type": "step_output_to_step_input",
                "labels": edge_labels,
                "risk": edge_risk,
            }

            edges.append(edge)

            risky_labels = sorted(set(edge_labels) & RISKY_LABELS)
            critical_labels = sorted(set(edge_labels) & CRITICAL_LABELS)

            if tool in SINK_TOOLS and risky_labels:
                high_risk_flows.append(
                    {
                        "source": f"step:{source_step_id}",
                        "target": f"step:{step_id}",
                        "tool": tool,
                        "labels": edge_labels,
                        "risky_labels": risky_labels,
                        "critical_labels": critical_labels,
                        "decision": step.get("decision"),
                        "risk": edge_risk,
                        "reason": (
                            "Risky or sensitive data flows into a sink tool; "
                            "runtime decision should be confirm or deny."
                        ),
                    }
                )

        if tool in SINK_TOOLS and labels:
            risky_labels = sorted(set(labels) & RISKY_LABELS)
            critical_labels = sorted(set(labels) & CRITICAL_LABELS)

            if risky_labels:
                high_risk_flows.append(
                    {
                        "source": f"step:{step_id}",
                        "target": f"sink:{tool}",
                        "tool": tool,
                        "labels": labels,
                        "risky_labels": risky_labels,
                        "critical_labels": critical_labels,
                        "decision": step.get("decision"),
                        "risk": _edge_risk(labels, tool),
                        "reason": "Step carries risky labels while using a sink tool.",
                    }
                )

    sink_steps = [
        step
        for step in normalized_steps
        if str(step.get("tool")) in SINK_TOOLS
    ]

    external_sink_steps = [
        step
        for step in normalized_steps
        if str(step.get("tool")) in EXTERNAL_SINK_TOOLS
    ]

    blocked_or_confirmed_sinks = [
        step
        for step in sink_steps
        if step.get("decision") in {"deny", "confirm"}
    ]

    tainted_steps = [
        step
        for step in normalized_steps
        if set(_step_labels(step)) & {"tainted", "prompt_injection"}
    ]

    sensitive_steps = [
        step
        for step in normalized_steps
        if set(_step_labels(step)) & CRITICAL_LABELS
    ]

    return {
        "version": "1.0",
        "case_id": case_result.get("id"),
        "nodes": nodes,
        "edges": edges,
        "high_risk_flows": high_risk_flows,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "step_count": len(normalized_steps),
            "sink_count": len(sink_steps),
            "external_sink_count": len(external_sink_steps),
            "high_risk_flow_count": len(high_risk_flows),
            "blocked_or_confirmed_sink_count": len(blocked_or_confirmed_sinks),
            "tainted_step_count": len(tainted_steps),
            "sensitive_step_count": len(sensitive_steps),
        },
    }
