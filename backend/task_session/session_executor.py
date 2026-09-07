from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.capability.capability_compiler import compile_capability_contract
from backend.runtime.flow_label import analyze_output_labels, is_sensitive, is_tainted
from backend.runtime.runtime_monitor import (
    create_runtime_state,
    run_runtime_step,
)
from backend.task_session.context_analyzer import analyze_text_security
from backend.task_session.session_models import TaskSession, TaskStep
from backend.tools.tool_executor import execute_tool


def model_to_dict(model: Any) -> Dict[str, Any]:
    """
    兼容 Pydantic v1 / v2 的模型转 dict 工具函数。
    """

    if model is None:
        return {}

    if hasattr(model, "model_dump"):
        return model.model_dump()

    if hasattr(model, "dict"):
        return model.dict()

    if isinstance(model, dict):
        return model

    return {
        "value": str(model),
    }


def unique_labels(labels: List[str]) -> List[str]:
    """
    去重并保持标签顺序。
    """

    result: List[str] = []
    seen = set()

    for label in labels:
        if not label:
            continue

        if label not in seen:
            result.append(label)
            seen.add(label)

    return result


def extract_tool_result_text(tool_result: Dict[str, Any]) -> str:
    """
    从工具执行结果中提取文本内容。

    file.read 的返回结果一般是：
    {
        "success": True,
        "result": "文件内容..."
    }

    email.send / db.query / shell.run 的 result 可能是 dict。
    这里统一转成字符串，方便后续步骤引用和标签分析。
    """

    if not tool_result:
        return ""

    result = tool_result.get("result", "")

    if isinstance(result, str):
        return result

    return str(result)


def build_output_excerpt(text: str, limit: int = 240) -> str:
    """
    构造前端展示用的输出摘要。
    """

    text = text or ""
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()

    if len(text) <= limit:
        return text

    return text[:limit] + "...[truncated]"


def extract_resource_from_params(params: Dict[str, Any]) -> Optional[str]:
    """
    从工具参数中提取资源路径。
    """

    for key in ["path", "file_path", "resource", "filename"]:
        value = params.get(key)

        if value:
            return str(value)

    return None


def find_step_by_id(session: TaskSession, step_id: int) -> Optional[TaskStep]:
    """
    根据 step_id 查找前面的步骤。
    """

    for step in session.steps:
        if step.step_id == step_id:
            return step

    return None


def build_step_params(session: TaskSession, step: TaskStep) -> Dict[str, Any]:
    """
    构造当前步骤真正要传给 Runtime Monitor / ToolExecutor 的参数。
    """

    params = dict(step.params)

    if "content_from_step" in params:
        source_step_id = int(params.get("content_from_step"))
        source_step = find_step_by_id(session, source_step_id)

        if source_step and source_step.tool_result:
            params["content"] = extract_tool_result_text(source_step.tool_result)
        else:
            params["content"] = ""

        if source_step_id not in step.input_from_steps:
            step.input_from_steps.append(source_step_id)

    return params


def collect_input_labels(session: TaskSession, step: TaskStep) -> List[str]:
    """
    汇总当前步骤的输入标签。

    1. step.input_labels 手动指定的标签；
    2. input_from_steps 指向的历史步骤输出标签；
    3. content_from_step 隐含引用的历史步骤输出标签。
    """

    labels = list(step.input_labels or [])

    input_from_steps = list(step.input_from_steps or [])

    if "content_from_step" in step.params:
        try:
            source_step_id = int(step.params.get("content_from_step"))
            if source_step_id not in input_from_steps:
                input_from_steps.append(source_step_id)
        except (TypeError, ValueError):
            pass

    normalized_input_from_steps: List[int] = []

    for source_step_id in input_from_steps:
        try:
            source_step_id = int(source_step_id)
        except (TypeError, ValueError):
            continue

        if source_step_id not in normalized_input_from_steps:
            normalized_input_from_steps.append(source_step_id)

        source_labels = session.get_step_output_labels(source_step_id)

        for label in source_labels:
            if label not in labels:
                labels.append(label)

    step.input_from_steps = normalized_input_from_steps
    return unique_labels(labels)


def infer_labels_from_executed_output(
    step: TaskStep,
    output_text: str,
) -> List[str]:

    resource = extract_resource_from_params(step.real_params or step.params)

    output_labels = analyze_output_labels(
        content=output_text,
        base_labels=step.output_labels,
        resource=resource,
    )

    return unique_labels(output_labels)


def update_context_from_labels(
    session: TaskSession,
    step: TaskStep,
) -> None:
    """
    根据 step.output_labels 更新 TaskSession 的上下文安全状态。
    """

    labels = step.output_labels or []

    if is_sensitive(labels):
        step.sensitive = True
        session.sensitive_context = True

        if "当前 Step 输出被标记为敏感数据" not in step.reason:
            step.reason.append("当前 Step 输出被标记为敏感数据")

    if is_tainted(labels):
        step.tainted = True
        session.tainted_context = True

        if "当前 Step 输出被标记为提示注入污染数据" not in step.reason:
            step.reason.append("当前 Step 输出被标记为提示注入污染数据")


def update_context_from_tool_output(session: TaskSession, step: TaskStep) -> None:
    """
    兼容旧逻辑的上下文更新函数。
    """

    if not step.tool_result:
        return

    output_text = extract_tool_result_text(step.tool_result)
    analysis = analyze_text_security(output_text)

    analysis_reasons = analysis.get("reasons", [])

    for reason in analysis_reasons:
        if reason not in step.reason:
            step.reason.append(reason)

    if analysis.get("sensitive"):
        step.sensitive = True
        session.sensitive_context = True
        session.context_risk_score += 50

        if "当前 Step 输出被标记为敏感数据" not in step.reason:
            step.reason.append("当前 Step 输出被标记为敏感数据")

    if analysis.get("tainted"):
        step.tainted = True
        session.tainted_context = True
        session.context_risk_score += 30

        if "当前 Step 输出被标记为提示注入污染数据" not in step.reason:
            step.reason.append("当前 Step 输出被标记为提示注入污染数据")


def apply_context_security_rules(
    session: TaskSession,
    step: TaskStep,
    real_params: Dict[str, Any],
    gateway_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    兼容旧版本的上下文安全规则函数。
    """

    decision = gateway_result.get("decision")
    risk_score = gateway_result.get("risk_score", 0)
    reason = list(gateway_result.get("reason", []))

    if session.tainted_context:
        risk_score += 30
        reason.append("任务链上下文已被提示注入内容污染，当前步骤风险分 +30")

    if session.sensitive_context and step.tool == "email.send":
        decision = "deny"
        risk_score += 100
        reason.append("检测到敏感数据可能流向外部工具，拒绝执行")

    return {
        "decision": decision,
        "risk_score": risk_score,
        "reason": reason,
    }


def sync_runtime_output_after_execution(
    runtime_state: Any,
    step: TaskStep,
) -> None:
    """
    工具 allow 并真实执行后，把真实 output_labels 回填到 RuntimeTaskState。

    原因：
    run_runtime_step() 发生在工具执行之前，它只能根据路径等信息推断基础标签；
    file.read 的真实内容需要执行后才能知道是否包含 prompt injection / secret。
    """

    if not runtime_state.steps:
        return

    runtime_record = runtime_state.steps[-1]

    if runtime_record.step_index != step.step_id:
        return

    runtime_record.output_labels = list(step.output_labels)
    runtime_record.executed = step.executed
    runtime_record.blocked = step.blocked
    runtime_record.requires_confirmation = step.requires_confirmation
    runtime_record.confirmed = step.confirmed
    runtime_record.confirmation_status = step.confirmation_status

    runtime_state.data_labels_by_step[step.step_id] = list(step.output_labels)


def update_step_from_runtime_result(
    step: TaskStep,
    runtime_result: Any,
    runtime_state: Any,
) -> None:
    """
    将 Runtime Monitor 的判断结果写回 TaskStep。
    """

    result_dict = model_to_dict(runtime_result)

    step.runtime_result = result_dict
    step.gateway_result = {
        "decision": result_dict.get("decision"),
        "risk_score": result_dict.get("risk_score", 0),
        "reason": result_dict.get("reason", []),
    }

    step.attack_chain_state = runtime_state.attack_chain_state

    step.decision = result_dict.get("decision")
    step.risk_score = int(result_dict.get("risk_score", 0) or 0)
    step.reason = list(result_dict.get("reason", []))

    step.executed = step.decision == "allow"
    step.blocked = step.decision == "deny"
    step.requires_confirmation = step.decision == "confirm"
    step.confirmation_status = "pending" if step.requires_confirmation else "none"

    if runtime_state.steps:
        runtime_record = runtime_state.steps[-1]

        if runtime_record.step_index == step.step_id:
            step.output_labels = list(runtime_record.output_labels or [])

    step.mark_updated()


def execute_allowed_tool_and_update_labels(
    session: TaskSession,
    step: TaskStep,
    runtime_state: Any,
) -> None:
    """
    对 allow 的步骤进行真实沙箱执行，并根据真实输出回填标签。
    """

    tool_result = execute_tool(step.tool, step.real_params)

    step.tool_result = tool_result
    step.executed = bool(tool_result.get("success") is True)

    output_text = extract_tool_result_text(tool_result)
    step.output_excerpt = build_output_excerpt(output_text)

    if step.executed:
        step.output_labels = infer_labels_from_executed_output(
            step=step,
            output_text=output_text,
        )

        session.record_step_labels(step.step_id, step.output_labels)
        sync_runtime_output_after_execution(runtime_state, step)
        update_context_from_labels(session, step)
        update_context_from_tool_output(session, step)

    else:
        step.reason.append("工具虽然通过授权检查，但沙箱执行失败。")
        step.reason.append(str(tool_result.get("result", "")))

    step.mark_updated()


def execute_task_session(session: TaskSession) -> TaskSession:
    """
    执行一个多步任务链。

    新执行主线：

    1. 根据用户原始任务编译 Capability Contract；
    2. 创建 RuntimeTaskState；
    3. 对每一步工具调用执行 run_runtime_step()；
    4. 根据 input_from_steps 自动继承历史步骤 output_labels；
    5. decision == allow 才进入沙箱 execute_tool()；
    6. 工具执行后分析真实输出，回填 output_labels；
    7. confirm / deny 会停止任务链；
    8. 每一步留下 runtime_result、tool_result、input_labels、output_labels 等证据。
    """

    session.mark_running()

    max_steps = max(5, len(session.steps))

    contract = compile_capability_contract(
        user=session.user,
        original_task=session.original_input,
        max_steps=max_steps,
        risk_budget=80,
    )

    runtime_state = create_runtime_state(contract)

    session.task_id = runtime_state.task_id
    session.contract = model_to_dict(contract)
    session.runtime_state = model_to_dict(runtime_state)

    if not session.steps:
        session.mark_finished()
        session.final_decision = "allow"
        return session

    for step in session.steps:
        # 1. 处理 content_from_step，得到真实参数
        real_params = build_step_params(session, step)
        step.real_params = real_params

        # 2. 继承历史步骤输出标签
        input_labels = collect_input_labels(session, step)
        step.input_labels = input_labels

        # 3. 进入 Runtime Monitor 检查
        runtime_result = run_runtime_step(
            state=runtime_state,
            tool=step.tool,
            params=real_params,
            input_labels=input_labels,
            output_content=None,
        )

        # 4. 把 Runtime 判断结果写回当前步骤
        update_step_from_runtime_result(
            step=step,
            runtime_result=runtime_result,
            runtime_state=runtime_state,
        )

        session.update_final_decision(step.decision or "allow")
        session.runtime_state = model_to_dict(runtime_state)

        # 5. confirm / deny 不执行工具，直接停止任务链
        if step.decision == "confirm":
            step.executed = False
            step.requires_confirmation = True
            step.confirmation_status = "pending"
            step.mark_updated()

            session.mark_confirm_required(step.step_id)
            session.runtime_state = model_to_dict(runtime_state)
            return session

        if step.decision == "deny":
            step.executed = False
            step.blocked = True
            step.mark_updated()

            session.mark_blocked()
            session.violations.extend(step.reason)
            session.runtime_state = model_to_dict(runtime_state)
            return session

        # 6. allow 才真正进入沙箱执行
        execute_allowed_tool_and_update_labels(
            session=session,
            step=step,
            runtime_state=runtime_state,
        )

        session.runtime_state = model_to_dict(runtime_state)

        # 7. 如果沙箱执行失败，任务不一定是安全违规，但当前任务无法继续稳定执行
        if step.tool_result and step.tool_result.get("success") is False:
            session.status = "execution_failed"
            session.update_final_decision("confirm")
            session.violations.append(
                f"Step {step.step_id} sandbox execution failed: {step.tool_result.get('result')}"
            )
            return session

    session.runtime_state = model_to_dict(runtime_state)
    session.final_decision = runtime_state.final_decision
    session.mark_finished()

    return session