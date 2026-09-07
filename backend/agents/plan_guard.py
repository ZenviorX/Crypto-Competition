from typing import Dict, Any, List, Optional

from backend.schemas import AgentPlanResult, ToolCallRequest
from backend.utils import normalize_tool_name, normalize_params
from backend.gateway.policy_loader import (
    get_supported_tools,
    get_required_params,
    get_agent_plan_policy,
    get_risk_score,
)


def _is_empty_value(value: Any) -> bool:
    return value is None or str(value).strip() in {
        "",
        "unknown",
        "未提取到邮件正文",
    }


def find_missing_params(tool: str, params: Dict[str, Any]) -> List[str]:
    required_params = get_required_params()
    required = required_params.get(tool, [])
    missing = []

    for name in required:
        if _is_empty_value(params.get(name)):
            missing.append(name)

    return missing


def inspect_agent_plan(plan: AgentPlanResult) -> Dict[str, Any]:
    """
    检查 Agent 生成的计划是否可以进入 Gateway。
    """
    plan_policy = get_agent_plan_policy()
    min_auto_confidence = plan_policy["min_auto_confidence"]
    min_confirm_confidence = plan_policy["min_confirm_confidence"]
    supported_tools = set(get_supported_tools())

    if plan.status == "error":
        return {
            "pass_to_gateway": False,
            "force_confirm": False,
            "decision": "deny",
            "risk_score": get_risk_score("unknown_tool", 100),
            "reason": [
                "Agent 规划阶段发生错误，系统无法确认用户真实意图，拒绝自动执行。",
                plan.message or "未知错误",
            ],
            "tool": "unknown",
            "params": {},
        }

    if plan.status == "need_clarification":
        return {
            "pass_to_gateway": False,
            "force_confirm": False,
            "decision": "confirm",
            "risk_score": get_risk_score("missing_params", 60),
            "reason": [
                "Agent 能识别部分用户意图，但缺少必要参数。",
                "该请求不能自动执行，需要用户补充信息或人工确认。",
            ],
            "tool": "unknown",
            "params": {},
            "missing_params": plan.missing_params,
            "clarification_question": plan.clarification_question,
        }

    if plan.status == "unsupported" or plan.tool_call is None:
        return {
            "pass_to_gateway": False,
            "force_confirm": False,
            "decision": "deny",
            "risk_score": get_risk_score("unknown_tool", 100),
            "reason": [
                "Agent 未能将用户输入转换为受支持的工具调用。",
                plan.unsupported_reason or plan.message or "当前系统不支持该任务类型。",
            ],
            "tool": "unknown",
            "params": {},
            "clarification_question": plan.clarification_question,
        }

    tool = normalize_tool_name(plan.tool_call.tool_name)
    params = normalize_params(tool, plan.tool_call.arguments)

    if tool not in supported_tools:
        return {
            "pass_to_gateway": False,
            "force_confirm": False,
            "decision": "deny",
            "risk_score": get_risk_score("unknown_tool", 100),
            "reason": [
                f"工具 {tool} 不在系统支持列表中，未知工具不能自动执行。"
            ],
            "tool": tool,
            "params": params,
        }

    missing_params = find_missing_params(tool, params)

    if missing_params:
        return {
            "pass_to_gateway": False,
            "force_confirm": False,
            "decision": "confirm",
            "risk_score": get_risk_score("missing_params", 60),
            "reason": [
                f"Agent 已识别出工具 {tool}，但缺少必要参数：{', '.join(missing_params)}。",
                "该请求不能自动执行，需要用户补充信息或人工确认。",
            ],
            "tool": tool,
            "params": params,
            "missing_params": missing_params,
            "clarification_question": plan.clarification_question,
        }

    confidence = float(plan.confidence or 0.0)

    if confidence < min_confirm_confidence:
        return {
            "pass_to_gateway": False,
            "force_confirm": False,
            "decision": "deny",
            "risk_score": get_risk_score("low_confidence_deny", 100),
            "reason": [
                f"Agent 对当前计划的置信度过低：{confidence}。",
                "低置信度工具调用不能自动执行。",
            ],
            "tool": tool,
            "params": params,
        }

    if confidence < min_auto_confidence:
        return {
            "pass_to_gateway": True,
            "force_confirm": True,
            "decision": "confirm",
            "risk_score": get_risk_score("low_confidence_confirm", 45),
            "reason": [
                f"Agent 计划置信度为 {confidence}，低于自动执行阈值。",
                "该请求可以进入 Gateway，但最终应至少要求人工确认。",
            ],
            "tool": tool,
            "params": params,
        }

    return {
        "pass_to_gateway": True,
        "force_confirm": False,
        "decision": "allow",
        "risk_score": 0,
        "reason": [
            f"Agent 计划置信度为 {confidence}，工具和参数通过计划校验。"
        ],
        "tool": tool,
        "params": params,
    }


def build_tool_request_after_guard(
    user: str,
    plan: AgentPlanResult,
    guard_result: Dict[str, Any],
) -> Optional[ToolCallRequest]:
    if not guard_result.get("pass_to_gateway"):
        return None

    return ToolCallRequest(
        user=user,
        tool=guard_result["tool"],
        params=guard_result["params"],
        agent_confidence=plan.confidence,
        plan_status=plan.status,
        plan_warnings=guard_result.get("reason", []),
    )
