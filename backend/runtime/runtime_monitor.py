from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.attack_chain.attack_chain_detector import AttackChainDetector
from backend.capability.capability_contract import CapabilityCheckResult, CapabilityContract
from backend.capability.capability_enforcer import enforce_capability_contract
from backend.runtime.flow_label import analyze_output_labels
from backend.runtime.task_state import RuntimeStepRecord, RuntimeTaskState


def create_runtime_state(contract: CapabilityContract) -> RuntimeTaskState:
    """
    根据 Capability Contract v2 创建任务运行时状态。
    """

    return RuntimeTaskState(
        task_id=contract.task_id,
        user=contract.user,
        original_task=contract.original_task,
        contract=contract,
        current_step=0,
        used_risk=0,
    )


def _infer_output_labels(
    contract: CapabilityContract,
    tool: str,
    decision: str,
    output_content: Optional[str] = None,
    resource: Optional[str] = None,
) -> List[str]:
    """
    根据合约能力规则和实际输出内容推断输出标签。
    """

    if decision != "allow":
        return []

    base_labels: List[str] = []

    for capability in contract.capabilities:
        if capability.tool == tool:
            base_labels = list(capability.output_labels)
            break

    return analyze_output_labels(
        content=output_content,
        base_labels=base_labels,
        resource=resource,
    )


def _build_attack_chain_detector(state: RuntimeTaskState) -> AttackChainDetector:
    """
    根据当前 RuntimeTaskState 中已经执行过的步骤，
    重新构造攻击链检测器的历史状态。
    """

    detector = AttackChainDetector(session_id=state.task_id)

    for step in state.steps:
        chain_params = dict(step.params or {})
        labels = set(step.input_labels or []) | set(step.output_labels or [])

        # 如果历史步骤的标签里已经有 prompt_injection，
        # 就补一个内容标记，方便攻击链检测器恢复状态。
        if "prompt_injection" in labels and not chain_params.get("content"):
            chain_params["content"] = "ignore previous instructions"

        detector.add_event(
            tool=step.tool,
            params=chain_params,
            gateway_result={
                "decision": step.decision,
                "risk_score": step.risk_score,
            },
        )

    return detector


def _merge_task_decision(
    current_decision: str,
    new_decision: str,
) -> str:
    """
    合并任务级整体决策，保证任务状态不会被后续低风险步骤降级。

    优先级：
    deny > confirm > allow
    """

    priority = {
        "allow": 0,
        "confirm": 1,
        "deny": 2,
    }

    current_level = priority.get(current_decision, 0)
    new_level = priority.get(new_decision, 0)

    if new_level >= current_level:
        return new_decision

    return current_decision


def _has_tainted_or_sensitive_input(input_labels: Optional[List[str]]) -> bool:
    """
    判断当前步骤输入是否携带污染或敏感标签。
    """

    risky_labels = {
        "tainted",
        "prompt_injection",
        "sensitive",
        "secret",
        "credential",
    }

    return bool(set(input_labels or []) & risky_labels)


def _should_apply_chain_risk(
    tool: str,
    current_chain_stage: Optional[str],
    input_labels: Optional[List[str]],
    chain_risk_delta: int,
) -> bool:
    """
    判断攻击链检测器产生的风险是否应该真正叠加到本步骤最终风险分。
    """

    if chain_risk_delta <= 0:
        return False

    dangerous_tools = {
        "email.send",
        "file.write",
        "file.delete",
        "shell.run",
        "code.exec",
        "db.query",
        "http.post",
    }

    blocking_chain_stages = {
        "sensitive_resource_access",
        "prompt_to_sensitive_access_chain",
        "data_exfiltration_chain",
        "prompt_to_command_execution_chain",
        "high_risk_command",
    }

    if current_chain_stage in blocking_chain_stages:
        return True

    if tool in dangerous_tools and _has_tainted_or_sensitive_input(input_labels):
        return True

    return False



def _unique_values(values: List[Any]) -> List[Any]:
    """
    保持顺序去重。
    """
    result: List[Any] = []
    seen = set()

    for value in values:
        marker = repr(value)
        if marker in seen:
            continue
        result.append(value)
        seen.add(marker)

    return result


def _merge_input_labels_from_steps(
    state: RuntimeTaskState,
    input_labels: Optional[List[str]],
    input_from_steps: Optional[List[int]],
) -> List[str]:
    """
    将显式输入标签与历史步骤输出标签合并。
    """
    merged = list(input_labels or [])

    for step_index in input_from_steps or []:
        inherited_labels = state.data_labels_by_step.get(step_index, [])

        for label in inherited_labels:
            if label not in merged:
                merged.append(label)

    return merged


def _build_label_sources(
    state: RuntimeTaskState,
    input_labels: List[str],
    input_from_steps: Optional[List[int]],
) -> Dict[str, List[str]]:
    """
    为每个输入标签记录来源。

    示例：
    {
      "public": ["step:1"],
      "prompt_injection": ["step:1"],
      "unknown": ["direct_input"]
    }
    """
    sources: Dict[str, List[str]] = {}

    inherited_labels = set()

    for step_index in input_from_steps or []:
        for label in state.data_labels_by_step.get(step_index, []):
            inherited_labels.add(label)
            sources.setdefault(label, []).append(f"step:{step_index}")

    for label in input_labels:
        if label not in inherited_labels:
            sources.setdefault(label, []).append("direct_input")

    return {
        label: [str(item) for item in _unique_values(source_list)]
        for label, source_list in sources.items()
    }


def _record_data_lineage_edges(
    state: RuntimeTaskState,
    target_step: int,
    input_labels: List[str],
    input_from_steps: Optional[List[int]],
) -> None:
    """
    记录跨步骤数据流边。
    """
    inherited_labels = set()

    for source_step in input_from_steps or []:
        labels = state.data_labels_by_step.get(source_step, [])
        if not labels:
            continue

        inherited_labels.update(labels)

        state.data_lineage_edges.append(
            {
                "source": f"step:{source_step}",
                "source_step": source_step,
                "target": f"step:{target_step}",
                "target_step": target_step,
                "labels": labels,
                "edge_type": "step_output_to_step_input",
            }
        )

    direct_labels = [
        label
        for label in input_labels
        if label not in inherited_labels
    ]

    if direct_labels:
        state.data_lineage_edges.append(
            {
                "source": "direct_input",
                "source_step": None,
                "target": f"step:{target_step}",
                "target_step": target_step,
                "labels": direct_labels,
                "edge_type": "direct_input_to_step",
            }
        )


def run_runtime_step(
    state: RuntimeTaskState,
    tool: str,
    params: Dict[str, Any],
    input_labels: Optional[List[str]] = None,
    output_content: Optional[str] = None,
    input_from_steps: Optional[List[int]] = None,
) -> CapabilityCheckResult:
    """
    在运行时状态中执行一次工具调用检查，并记录结果。
    1. 根据当前状态调用 Capability Enforcer；
    2. 根据 allow / confirm / deny 更新任务状态；
    3. 记录 RuntimeStepRecord，形成任务执行链。
    """

    input_from_steps = input_from_steps or []
    input_labels = _merge_input_labels_from_steps(
        state=state,
        input_labels=input_labels,
        input_from_steps=input_from_steps,
    )

    if state.is_blocked:
        return CapabilityCheckResult(
            decision="deny",
            risk_score=0,
            reason=[
                "Runtime task is already blocked; no further tool calls are allowed."
            ],
        )

    next_step = state.current_step + 1

    result = enforce_capability_contract(
        contract=state.contract,
        tool=tool,
        params=params,
        input_labels=input_labels,
        current_step=next_step,
        used_risk=state.used_risk,
    )

    resource = None

    for key in ["path", "file_path", "resource", "filename"]:
        if params.get(key):
            resource = str(params.get(key))
            break

    output_labels = _infer_output_labels(
        contract=state.contract,
        tool=tool,
        decision=result.decision,
        output_content=output_content,
        resource=resource,
    )

    chain_detector = _build_attack_chain_detector(state)

    chain_params = dict(params or {})

    if output_content:
        chain_params["content"] = output_content

    chain_state = chain_detector.add_event(
        tool=tool,
        params=chain_params,
        gateway_result={
            "decision": result.decision,
            "risk_score": result.risk_score,
        },
    )

    state.attack_chain_state = chain_state

    chain_events = chain_state.get("events", [])
    current_chain_event = chain_events[-1] if chain_events else {}

    chain_decision = chain_state.get("final_decision", result.decision)
    chain_risk_delta = int(current_chain_event.get("risk_delta", 0) or 0)
    chain_reason = current_chain_event.get("reason", [])
    current_chain_stage = current_chain_event.get("stage")

    final_decision = result.decision
    final_risk_score = result.risk_score
    final_reason = list(result.reason or [])

    if chain_reason:
        final_reason.append("Attack chain detector:")
        final_reason.extend(chain_reason)

    should_apply_chain_risk = _should_apply_chain_risk(
        tool=tool,
        current_chain_stage=current_chain_stage,
        input_labels=input_labels,
        chain_risk_delta=chain_risk_delta,
    )

    if chain_decision == "deny":
        final_decision = "deny"

        if should_apply_chain_risk:
            final_risk_score += chain_risk_delta

    elif chain_decision == "confirm" and final_decision == "allow":
        if should_apply_chain_risk:
            final_decision = "confirm"
            final_risk_score += chain_risk_delta
        else:
            final_reason.append(
                "Attack chain risk observed, but current step does not carry "
                "tainted or sensitive data, so the base authorization decision is kept."
            )

    elif should_apply_chain_risk:
        final_risk_score += chain_risk_delta

    state.final_decision = _merge_task_decision(
        state.final_decision,
        final_decision,
    )

    if final_decision == "confirm" and next_step not in state.pending_confirm_steps:
        state.pending_confirm_steps.append(next_step)

    final_result = CapabilityCheckResult(
        decision=final_decision,
        risk_score=final_risk_score,
        reason=final_reason,
    )

    label_sources = _build_label_sources(
        state=state,
        input_labels=input_labels,
        input_from_steps=input_from_steps,
    )

    step_record = RuntimeStepRecord(
        step_index=next_step,
        tool=tool,
        params=params,
        input_from_steps=input_from_steps,
        input_labels=input_labels,
        output_labels=output_labels,
        label_sources=label_sources,
        decision=final_result.decision,
        risk_score=final_result.risk_score,
        reason=final_result.reason,
        executed=(final_result.decision == "allow"),
        blocked=(final_result.decision == "deny"),
        requires_confirmation=(final_result.decision == "confirm"),
        confirmed=False,
        confirmation_status=(
            "pending" if final_result.decision == "confirm" else "none"
        ),
    )

    state.steps.append(step_record)

    _record_data_lineage_edges(
        state=state,
        target_step=next_step,
        input_labels=input_labels,
        input_from_steps=input_from_steps,
    )

    if final_result.decision == "allow":
        state.current_step = next_step
        state.used_risk += final_result.risk_score
        state.data_labels_by_step[next_step] = output_labels

    elif final_result.decision == "confirm":
        state.current_step = next_step
        state.used_risk += final_result.risk_score
        state.violations.append(
            f"Step {next_step} requires human confirmation: {tool}"
        )

    elif final_result.decision == "deny":
        state.is_blocked = True
        state.violations.extend(final_result.reason)

    return final_result



def build_runtime_security_graph(state: RuntimeTaskState) -> Dict[str, Any]:
    """
    构建 Runtime Security Graph。

    把运行时状态转换成可展示、可审计的数据流安全图：
    - nodes：任务、步骤、直接输入；
    - edges：跨步骤数据流边；
    - high_risk_flows：污染/敏感数据流向危险工具的证据；
    - summary：图谱统计信息。

    这是 AgentGuard 从“记录标签”升级为“生成数据流安全证据图”的核心接口。
    """
    sink_tools = {
        "email.send",
        "shell.run",
        "file.write",
        "file.delete",
        "db.query",
        "http.post",
        "code.exec",
    }

    external_sink_tools = {
        "email.send",
        "http.post",
    }

    risky_labels = {
        "tainted",
        "prompt_injection",
        "unknown",
        "sensitive",
        "secret",
    }

    critical_labels = {
        "sensitive",
        "secret",
    }

    nodes: List[Dict[str, Any]] = [
        {
            "id": f"task:{state.task_id}",
            "type": "task",
            "label": state.original_task,
            "risk": state.used_risk,
            "decision": state.final_decision,
        }
    ]

    if any(edge.get("source") == "direct_input" for edge in state.data_lineage_edges):
        nodes.append(
            {
                "id": "direct_input",
                "type": "input",
                "label": "Direct User / Agent Input",
                "risk": 0,
                "decision": "allow",
            }
        )

    step_by_index = {}

    for step in state.steps:
        step_by_index[step.step_index] = step

        node_risk = "low"

        if step.decision == "deny":
            node_risk = "critical"
        elif step.decision == "confirm":
            node_risk = "high"
        elif set(step.input_labels or []) & risky_labels:
            node_risk = "medium"

        nodes.append(
            {
                "id": f"step:{step.step_index}",
                "type": "step",
                "step_index": step.step_index,
                "tool": step.tool,
                "label": f"Step {step.step_index}: {step.tool}",
                "decision": step.decision,
                "risk_score": step.risk_score,
                "risk": node_risk,
                "input_labels": step.input_labels,
                "output_labels": step.output_labels,
                "input_from_steps": step.input_from_steps,
                "label_sources": step.label_sources,
                "requires_confirmation": step.requires_confirmation,
                "blocked": step.blocked,
                "executed": step.executed,
            }
        )

    edges: List[Dict[str, Any]] = []
    high_risk_flows: List[Dict[str, Any]] = []

    for raw_edge in state.data_lineage_edges:
        labels = list(raw_edge.get("labels", []))
        target_step = raw_edge.get("target_step")
        target_step_record = step_by_index.get(target_step)

        edge_risky_labels = sorted(set(labels) & risky_labels)
        edge_critical_labels = sorted(set(labels) & critical_labels)

        edge_risk = "low"

        if edge_critical_labels:
            edge_risk = "critical"
        elif edge_risky_labels:
            edge_risk = "high"

        edge = {
            "source": raw_edge.get("source"),
            "target": raw_edge.get("target"),
            "source_step": raw_edge.get("source_step"),
            "target_step": target_step,
            "labels": labels,
            "edge_type": raw_edge.get("edge_type"),
            "risk": edge_risk,
            "risky_labels": edge_risky_labels,
        }

        edges.append(edge)

        if not target_step_record:
            continue

        target_tool = target_step_record.tool

        if target_tool not in sink_tools:
            continue

        if not edge_risky_labels:
            continue

        severity = "high"
        reason = "Tainted or unknown data reaches a high-risk tool."

        if edge_critical_labels and target_tool in external_sink_tools:
            severity = "critical"
            reason = "Sensitive or secret data reaches an external output tool."
        elif edge_critical_labels:
            severity = "critical"
            reason = "Sensitive or secret data reaches a high-risk tool."
        elif "prompt_injection" in edge_risky_labels and target_tool in external_sink_tools:
            severity = "high"
            reason = "Prompt-injection-tainted data reaches an external output tool."

        high_risk_flows.append(
            {
                "source": edge["source"],
                "target": edge["target"],
                "source_step": edge["source_step"],
                "target_step": edge["target_step"],
                "target_tool": target_tool,
                "labels": labels,
                "risky_labels": edge_risky_labels,
                "severity": severity,
                "reason": reason,
                "target_decision": target_step_record.decision,
                "target_risk_score": target_step_record.risk_score,
            }
        )

    severity_order = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    graph_risk_level = "low"

    for item in high_risk_flows:
        severity = item.get("severity", "low")
        if severity_order.get(severity, 0) > severity_order.get(graph_risk_level, 0):
            graph_risk_level = severity

    return {
        "task_id": state.task_id,
        "final_decision": state.final_decision,
        "is_blocked": state.is_blocked,
        "used_risk": state.used_risk,
        "risk_budget": state.contract.risk_budget,
        "graph_risk_level": graph_risk_level,
        "nodes": nodes,
        "edges": edges,
        "high_risk_flows": high_risk_flows,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "step_count": len(state.steps),
            "high_risk_flow_count": len(high_risk_flows),
            "blocked_step_count": sum(1 for step in state.steps if step.blocked),
            "confirm_step_count": sum(1 for step in state.steps if step.requires_confirmation),
        },
    }


def get_step_output_labels(
    state: RuntimeTaskState,
    step_index: int,
) -> List[str]:
    """
    获取某一步产生的输出标签。

    后续多步任务中，如果 step2 使用 step1 的输出，
    就可以通过这个函数把 step1 的 output_labels 传给 step2。
    """

    return state.data_labels_by_step.get(step_index, [])


def approve_runtime_step(
    state: RuntimeTaskState,
    step_index: int,
) -> bool:
    """
    批准一个等待人工确认的运行时步骤。

    返回 True 表示批准成功；
    返回 False 表示没有找到对应的待确认步骤。
    """

    for step in state.steps:
        if step.step_index != step_index:
            continue

        if not step.requires_confirmation:
            return False

        step.confirmed = True
        step.confirmation_status = "approved"
        step.executed = True
        step.blocked = False

        state.data_labels_by_step[step_index] = step.output_labels

        if step_index in state.pending_confirm_steps:
            state.pending_confirm_steps.remove(step_index)

        if (
            not state.pending_confirm_steps
            and state.final_decision == "confirm"
            and not state.is_blocked
        ):
            state.final_decision = "allow"

        return True

    return False


def reject_runtime_step(
    state: RuntimeTaskState,
    step_index: int,
) -> bool:
    """
    拒绝一个等待人工确认的运行时步骤。

    返回 True 表示拒绝成功；
    返回 False 表示没有找到对应的待确认步骤。
    """

    for step in state.steps:
        if step.step_index != step_index:
            continue

        if not step.requires_confirmation:
            return False

        step.confirmed = False
        step.confirmation_status = "rejected"
        step.executed = False
        step.blocked = True
        step.decision = "deny"

        if step_index in state.pending_confirm_steps:
            state.pending_confirm_steps.remove(step_index)

        state.is_blocked = True
        state.final_decision = "deny"
        state.violations.append(
            f"Step {step_index} was rejected by human reviewer."
        )

        return True

    return False