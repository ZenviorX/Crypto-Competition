from __future__ import annotations

import json
from typing import Any, Dict, List


DEFENSE_LAYERS = {
    "capability_contract": "Task-level least-privilege capability contract",
    "runtime_monitor": "Step-level runtime authorization and risk budget enforcement",
    "semantic_guard": "Semantic risk detection for intent-level attacks",
    "data_flow_graph": "Runtime data-flow graph and high-risk flow evidence",
    "integrity_chain": "SHA-256 integrity manifest and case hash chain",
    "effectiveness_baseline": "AgentGuard vs naive baseline effectiveness comparison",
    "sandbox_executor": "Sandboxed execution for allowed tools",
}


ATTACK_SURFACES = {
    "file": ["file.read", "file.write", "file.delete"],
    "email": ["email.send"],
    "shell": ["shell.run", "code.exec", "run_code"],
    "database": ["db.query"],
    "network": ["http.post", "http.get"],
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _text_blob(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, sort_keys=True, default=str).lower()
    except Exception:
        return str(data).lower()


def _steps(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps = case.get("steps", [])

    if not isinstance(steps, list):
        return []

    return [
        step
        for step in steps
        if isinstance(step, dict)
    ]


def _tools(case: Dict[str, Any]) -> List[str]:
    return [
        str(step.get("tool"))
        for step in _steps(case)
        if step.get("tool")
    ]


def _case_has_security_graph(case: Dict[str, Any]) -> bool:
    graph = case.get("security_graph")
    return isinstance(graph, dict) and isinstance(graph.get("summary"), dict)


def _case_has_high_risk_flow(case: Dict[str, Any]) -> bool:
    graph = case.get("security_graph", {})

    if not isinstance(graph, dict):
        return False

    summary = graph.get("summary", {})

    if not isinstance(summary, dict):
        return False

    try:
        return int(summary.get("high_risk_flow_count") or 0) > 0
    except (TypeError, ValueError):
        return False


def _infer_case_layers(case: Dict[str, Any], report: Dict[str, Any]) -> List[str]:
    text = _text_blob(case)
    steps = _steps(case)
    decisions = {
        str(step.get("decision"))
        for step in steps
        if step.get("decision")
    }
    final_decision = str(case.get("final_decision") or "")

    layers: List[str] = []

    if "capability" in text or "contract" in text or final_decision in {"confirm", "deny"}:
        layers.append("capability_contract")

    if steps:
        layers.append("runtime_monitor")

    semantic_markers = [
        "semantic",
        "prompt_injection",
        "policy_bypass",
        "credential",
        "data_exfiltration",
        "语义",
        "提示注入",
        "凭证",
        "外发",
    ]
    if any(marker in text for marker in semantic_markers):
        layers.append("semantic_guard")

    if _case_has_security_graph(case):
        layers.append("data_flow_graph")

    if isinstance(report.get("integrity"), dict):
        layers.append("integrity_chain")

    if isinstance(report.get("effectiveness"), dict):
        layers.append("effectiveness_baseline")

    if any(step.get("executed") is True for step in steps):
        layers.append("sandbox_executor")

    if not layers and decisions:
        layers.append("runtime_monitor")

    result: List[str] = []
    seen = set()

    for layer in layers:
        if layer in seen:
            continue
        seen.add(layer)
        result.append(layer)

    return result


def _infer_attack_surfaces(case: Dict[str, Any]) -> List[str]:
    tools = set(_tools(case))
    surfaces: List[str] = []

    for surface, surface_tools in ATTACK_SURFACES.items():
        if tools & set(surface_tools):
            surfaces.append(surface)

    if not surfaces:
        surfaces.append("general")

    return surfaces


def build_coverage_matrix(report: Dict[str, Any]) -> Dict[str, Any]:
    cases = report.get("cases", [])

    if not isinstance(cases, list):
        cases = []

    case_records: List[Dict[str, Any]] = []

    layer_counts = {
        layer: 0
        for layer in DEFENSE_LAYERS
    }
    surface_counts = {
        surface: 0
        for surface in list(ATTACK_SURFACES.keys()) + ["general"]
    }

    category_counts: Dict[str, int] = {}
    category_layer_counts: Dict[str, Dict[str, int]] = {}

    for case in cases:
        if not isinstance(case, dict):
            continue

        category = str(case.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1

        layers = _infer_case_layers(case, report)
        surfaces = _infer_attack_surfaces(case)

        for layer in layers:
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
            category_layer_counts.setdefault(category, {})
            category_layer_counts[category][layer] = (
                category_layer_counts[category].get(layer, 0) + 1
            )

        for surface in surfaces:
            surface_counts[surface] = surface_counts.get(surface, 0) + 1

        case_records.append(
            {
                "id": case.get("id"),
                "category": category,
                "passed": case.get("passed"),
                "final_decision": case.get("final_decision"),
                "tools": _tools(case),
                "attack_surfaces": surfaces,
                "covered_layers": layers,
                "layer_count": len(layers),
                "has_high_risk_flow": _case_has_high_risk_flow(case),
            }
        )

    total_cases = len(case_records)
    total_layers = len(DEFENSE_LAYERS)

    covered_layer_names = [
        layer
        for layer, count in layer_counts.items()
        if count > 0
    ]

    coverage_score = round(
        100 * len(covered_layer_names) / total_layers,
        2,
    ) if total_layers else 0.0

    average_layers_per_case = round(
        sum(item["layer_count"] for item in case_records) / total_cases,
        2,
    ) if total_cases else 0.0

    high_risk_flow_cases = sum(
        1
        for item in case_records
        if item["has_high_risk_flow"]
    )

    gaps: List[str] = []

    for layer in DEFENSE_LAYERS:
        if layer_counts.get(layer, 0) == 0:
            gaps.append(f"Layer not covered by current benchmark report: {layer}")

    if total_cases == 0:
        gaps.append("No benchmark cases found.")

    return {
        "version": "1.0",
        "layers": DEFENSE_LAYERS,
        "attack_surfaces": ATTACK_SURFACES,
        "summary": {
            "total_cases": total_cases,
            "covered_layer_count": len(covered_layer_names),
            "total_layer_count": total_layers,
            "coverage_score": coverage_score,
            "average_layers_per_case": average_layers_per_case,
            "high_risk_flow_cases": high_risk_flow_cases,
            "category_counts": category_counts,
            "layer_counts": layer_counts,
            "surface_counts": surface_counts,
            "category_layer_counts": category_layer_counts,
            "gaps": gaps,
        },
        "cases": case_records,
    }
