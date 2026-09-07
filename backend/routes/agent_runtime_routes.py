from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.agents.multistep_llm_agent import MultiStepLLMAgent
from backend.capability.capability_compiler import compile_capability_contract
from backend.runtime.runtime_monitor import (
    create_runtime_state,
    run_runtime_step,
)
from backend.task_session.session_executor import (
    build_step_params,
    collect_input_labels,
    execute_allowed_tool_and_update_labels,
    extract_tool_result_text,
    model_to_dict,
    update_step_from_runtime_result,
)
from backend.task_session.session_models import TaskSession, TaskStep


router = APIRouter(
    prefix="/agent-runtime",
    tags=["Real Agent Runtime"],
)


AGENT_RUNTIME_SESSIONS: Dict[str, TaskSession] = {}


class AgentRuntimeRequest(BaseModel):
    """
    真实 Agent 运行请求。

    """

    user: str = Field(default="user", description="当前用户身份")
    user_input: str = Field(..., description="用户自然语言任务")
    max_steps: int = Field(default=5, ge=1, le=10, description="最大规划/执行步数")
    risk_budget: int = Field(default=80, ge=1, le=200, description="任务风险预算")


class AgentStepwiseRunRequest(BaseModel):
    """
    真实 Agent 逐步规划运行请求。
    """

    user: str = Field(default="user", description="当前用户身份")
    user_input: str = Field(..., description="用户自然语言任务")
    max_steps: int = Field(default=5, ge=1, le=10, description="最大逐步规划次数")
    risk_budget: int = Field(default=80, ge=1, le=200, description="任务风险预算")


def save_agent_runtime_session(session: TaskSession) -> None:
    """
    将真实 Agent 运行会话保存到内存中。
    """
    AGENT_RUNTIME_SESSIONS[session.session_id] = session


def get_agent_runtime_session(session_id: str) -> Optional[TaskSession]:
    """
    根据 session_id 获取真实 Agent 运行会话。
    """
    return AGENT_RUNTIME_SESSIONS.get(session_id)


def build_executed_steps_for_llm(session: TaskSession) -> List[Dict[str, Any]]:
    """
    构造传给 plan_next() 的历史步骤摘要。

    """

    executed_steps: List[Dict[str, Any]] = []

    for step in session.steps:
        item = {
            "step_id": step.step_id,
            "tool": step.tool,
            "params": step.real_params or step.params,
            "description": step.description,
            "decision": step.decision,
            "risk_score": step.risk_score,
            "reason": step.reason,
            "executed": step.executed,
            "input_from_steps": step.input_from_steps,
            "input_labels": step.input_labels,
            "output_labels": step.output_labels,
            "output_excerpt": step.output_excerpt,
        }

        executed_steps.append(item)

    return executed_steps


def build_task_step_from_plan(
    step_id: int,
    plan_result: Dict[str, Any],
) -> TaskStep:
    """
    将 MultiStepLLMAgent.plan_next() 的 next_step 转成 TaskStep。
    """

    next_step = plan_result.get("next_step")

    if not isinstance(next_step, dict):
        raise ValueError("plan_result does not contain a valid next_step")

    tool = str(next_step.get("tool", "")).strip()
    params = next_step.get("params", {})
    description = str(next_step.get("description", "") or "").strip()

    if not isinstance(params, dict):
        params = {}

    input_from_steps = next_step.get("input_from_steps", [])

    if not isinstance(input_from_steps, list):
        input_from_steps = []

    normalized_input_from_steps: List[int] = []

    for item in input_from_steps:
        try:
            normalized_input_from_steps.append(int(item))
        except (TypeError, ValueError):
            continue

    return TaskStep(
        step_id=step_id,
        tool=tool,
        params=params,
        description=description,
        input_from_steps=normalized_input_from_steps,
        raw_llm_output=plan_result.get("raw_output"),
        agent_confidence=float(plan_result.get("confidence", 0.0) or 0.0),
        agent_reason=str(plan_result.get("reason", "") or ""),
    )


def execute_one_runtime_step(
    session: TaskSession,
    step: TaskStep,
    runtime_state: Any,
) -> None:
    """
    对单个 TaskStep 执行 Runtime Monitor 检查和沙箱执行。
    """

    real_params = build_step_params(session, step)
    step.real_params = real_params

    input_labels = collect_input_labels(session, step)
    step.input_labels = input_labels

    runtime_result = run_runtime_step(
        state=runtime_state,
        tool=step.tool,
        params=real_params,
        input_labels=input_labels,
        output_content=None,
    )

    update_step_from_runtime_result(
        step=step,
        runtime_result=runtime_result,
        runtime_state=runtime_state,
    )

    session.update_final_decision(step.decision or "allow")
    session.runtime_state = model_to_dict(runtime_state)

    if step.decision == "allow":
        execute_allowed_tool_and_update_labels(
            session=session,
            step=step,
            runtime_state=runtime_state,
        )
        session.runtime_state = model_to_dict(runtime_state)
        return

    if step.decision == "confirm":
        step.executed = False
        step.requires_confirmation = True
        step.confirmation_status = "pending"
        step.mark_updated()

        session.mark_confirm_required(step.step_id)
        session.runtime_state = model_to_dict(runtime_state)
        return

    if step.decision == "deny":
        step.executed = False
        step.blocked = True
        step.mark_updated()

        session.mark_blocked()
        session.violations.extend(step.reason)
        session.runtime_state = model_to_dict(runtime_state)
        return


@router.post("/multistep-llm/plan")
def plan_with_multistep_llm(request: AgentRuntimeRequest):
    """
    使用真实 MultiStepLLMAgent 一次性生成多步工具调用计划。
    """

    try:
        agent = MultiStepLLMAgent()
        session = agent.plan(
            user=request.user,
            user_input=request.user_input,
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    save_agent_runtime_session(session)

    return {
        "message": "MultiStepLLMAgent plan generated successfully.",
        "mode": "plan_only",
        "session": session.model_dump(),
    }


@router.post("/multistep-llm/run")
def run_with_multistep_llm(request: AgentRuntimeRequest):
    """
    使用真实 MultiStepLLMAgent 一次性规划并执行完整任务链。
    """

    try:
        from backend.task_session.session_executor import execute_task_session

        agent = MultiStepLLMAgent()
        session = agent.plan(
            user=request.user,
            user_input=request.user_input,
        )
        session.agent_type = "multistep_llm"

        executed_session = execute_task_session(session)

    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    save_agent_runtime_session(executed_session)

    return {
        "message": "MultiStepLLMAgent task executed successfully.",
        "mode": "plan_all_then_run",
        "session": executed_session.model_dump(),
    }


@router.post("/stepwise-llm/run")
def run_with_stepwise_llm(request: AgentStepwiseRunRequest):
    """
    使用真实 MultiStepLLMAgent 逐步规划并执行。
    """

    try:
        agent = MultiStepLLMAgent()

    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    session = TaskSession(
        user=request.user,
        original_input=request.user_input,
        agent_type="stepwise_llm",
    )

    contract = compile_capability_contract(
        user=request.user,
        original_task=request.user_input,
        max_steps=request.max_steps,
        risk_budget=request.risk_budget,
    )

    runtime_state = create_runtime_state(contract)

    session.task_id = runtime_state.task_id
    session.contract = model_to_dict(contract)
    session.runtime_state = model_to_dict(runtime_state)
    session.mark_running()

    last_tool_output = ""

    for step_index in range(1, request.max_steps + 1):
        executed_steps = build_executed_steps_for_llm(session)

        plan_result = agent.plan_next(
            user=request.user,
            original_task=request.user_input,
            executed_steps=executed_steps,
            last_tool_output=last_tool_output,
        )

        raw_output = plan_result.get("raw_output")

        if raw_output:
            session.raw_agent_outputs.append(raw_output)

        status = plan_result.get("status")

        if status == "finished":
            session.evidence["finish_reason"] = plan_result.get("reason", "")
            session.runtime_state = model_to_dict(runtime_state)
            session.final_decision = runtime_state.final_decision
            session.mark_finished()
            save_agent_runtime_session(session)

            return {
                "message": "Stepwise LLM task finished.",
                "mode": "stepwise_llm",
                "finish_status": "finished",
                "session": session.model_dump(),
            }

        if status != "planned":
            session.status = "agent_planning_stopped"
            session.evidence["stop_status"] = status
            session.evidence["stop_reason"] = plan_result.get("reason", "")
            session.runtime_state = model_to_dict(runtime_state)
            save_agent_runtime_session(session)

            return {
                "message": "Stepwise LLM planning stopped before producing a valid next step.",
                "mode": "stepwise_llm",
                "finish_status": status,
                "plan_result": plan_result,
                "session": session.model_dump(),
            }

        try:
            step = build_task_step_from_plan(
                step_id=step_index,
                plan_result=plan_result,
            )

        except ValueError as exc:
            session.status = "agent_planning_error"
            session.evidence["error"] = str(exc)
            session.runtime_state = model_to_dict(runtime_state)
            save_agent_runtime_session(session)

            return {
                "message": "LLM produced an invalid next step.",
                "mode": "stepwise_llm",
                "finish_status": "invalid_step",
                "plan_result": plan_result,
                "session": session.model_dump(),
            }

        session.add_step(step)

        execute_one_runtime_step(
            session=session,
            step=step,
            runtime_state=runtime_state,
        )

        session.runtime_state = model_to_dict(runtime_state)

        if step.decision in {"confirm", "deny"}:
            save_agent_runtime_session(session)

            return {
                "message": "Stepwise LLM task stopped by Runtime Monitor.",
                "mode": "stepwise_llm",
                "finish_status": step.decision,
                "blocked_step": step.step_id,
                "session": session.model_dump(),
            }

        if step.tool_result and step.tool_result.get("success") is False:
            session.status = "execution_failed"
            session.evidence["failed_step"] = step.step_id
            session.evidence["failed_result"] = step.tool_result
            session.runtime_state = model_to_dict(runtime_state)
            save_agent_runtime_session(session)

            return {
                "message": "Stepwise LLM task stopped because sandbox execution failed.",
                "mode": "stepwise_llm",
                "finish_status": "execution_failed",
                "failed_step": step.step_id,
                "session": session.model_dump(),
            }

        last_tool_output = ""

        if step.tool_result:
            last_tool_output = extract_tool_result_text(step.tool_result)

    session.status = "max_steps_reached"
    session.evidence["finish_reason"] = "Reached max_steps before LLM returned finished."
    session.runtime_state = model_to_dict(runtime_state)
    session.final_decision = runtime_state.final_decision

    save_agent_runtime_session(session)

    return {
        "message": "Stepwise LLM task reached max_steps.",
        "mode": "stepwise_llm",
        "finish_status": "max_steps_reached",
        "session": session.model_dump(),
    }


@router.get("/sessions")
def list_agent_runtime_sessions():
    """
    查看真实 Agent Runtime 会话列表。
    """

    sessions = []

    for session in AGENT_RUNTIME_SESSIONS.values():
        sessions.append(
            {
                "session_id": session.session_id,
                "task_id": session.task_id,
                "user": session.user,
                "agent_type": session.agent_type,
                "original_input": session.original_input,
                "status": session.status,
                "final_decision": session.final_decision,
                "step_count": len(session.steps),
                "created_at": session.created_at,
                "updated_at": session.updated_at,
            }
        )

    return {
        "message": "Agent runtime sessions loaded successfully.",
        "count": len(sessions),
        "sessions": sessions,
    }


@router.get("/sessions/{session_id}")
def read_agent_runtime_session(session_id: str):
    """
    查看某个真实 Agent Runtime 会话详情。
    """

    session = get_agent_runtime_session(session_id)

    if session is None:
        raise HTTPException(
            status_code=404,
            detail=f"Agent runtime session {session_id} not found.",
        )

    return {
        "message": "Agent runtime session loaded successfully.",
        "session": session.model_dump(),
    }