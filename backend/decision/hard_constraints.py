from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Dict, List, Optional

from backend.schemas import ToolCallRequest
from backend.capability.capability_contract import (
    CapabilityContract,
    CapabilityRule,
)
from backend.gateway.policy_loader import (
    get_supported_tools,
    get_required_params,
)
from backend.gateway.security_detectors import (
    analyze_resource_path,
)
from backend.utils import (
    normalize_tool_name,
    normalize_params,
    get_path,
)


INVALID_PLAN_STATES = {
    "failed",
    "error",
    "invalid",
    "cancelled",
}


@dataclass
class HardConstraintResult:
    """
    硬约束检查结果。

    passed=True:
        没发现确定性的授权违规，
        可以继续进入概率风险模型。

    passed=False:
        已发现明确违规，
        直接 deny。
    """

    passed: bool
    decision: str
    reasons: List[str] = field(
        default_factory=list
    )

    violation_type: Optional[str] = None


def _deny(
    violation_type: str,
    *reasons: str,
) -> HardConstraintResult:
    return HardConstraintResult(
        passed=False,
        decision="deny",
        violation_type=violation_type,
        reasons=list(reasons),
    )


def _normalize_contract_resource(
    path: str,
) -> str:
    """
    与现有 Capability Contract 的资源格式保持兼容。
    """

    value = str(path).strip()
    value = value.replace("\\", "/")
    value = value.strip(
        "'\"，。；;,. "
    )

    if value.startswith("../"):
        return value

    if value.startswith("data/"):
        return value

    if value.startswith(
        (
            "public/",
            "course/",
            "secret/",
            "private/",
        )
    ):
        return f"data/{value}"

    return value


def _match_any(
    value: str,
    patterns: List[str],
) -> bool:

    if not patterns:
        return True

    return any(
        fnmatch(
            value,
            pattern,
        )
        for pattern in patterns
    )


def _get_recipient(
    params: Dict[str, Any],
) -> Optional[str]:

    for key in [
        "to",
        "recipient",
        "email",
        "to_email",
    ]:
        value = params.get(key)

        if value:
            return str(value).strip()

    return None


def _rule_matches(
    rule: CapabilityRule,
    tool: str,
    resource: Optional[str],
    recipient: Optional[str],
) -> bool:
    """
    这里只判断是否属于被授权能力。

    不处理：
    risk_cost
    risk_budget
    require_approval

    这些不属于确定性授权边界。
    """

    if rule.tool != tool:
        return False

    if rule.mode in {
        "read",
        "write",
        "delete",
    }:
        if not resource:
            return False

        if not _match_any(
            resource,
            rule.resource_patterns,
        ):
            return False

    elif rule.mode == "query":
        if (
            resource
            and rule.resource_patterns
            and not _match_any(
                resource,
                rule.resource_patterns,
            )
        ):
            return False

    elif rule.mode == "external_write":
        if not recipient:
            return False

        if not rule.recipients:
            return False

        if recipient not in rule.recipients:
            return False

    return True


def _check_capability_contract(
    request: ToolCallRequest,
    tool: str,
    params: Dict[str, Any],
) -> Optional[HardConstraintResult]:
    """
    只执行 Capability Contract 中确定性的授权检查。
    """

    if not request.task_contract:
        return None

    try:
        contract = CapabilityContract(
            **request.task_contract
        )

    except Exception as exc:
        return _deny(
            "invalid_contract",
            "Capability Contract 格式无效。",
            f"解析错误：{exc}",
        )

    # ---------------------------------------------------------
    # 1. 编译器已经拒绝的任务不能继续
    # ---------------------------------------------------------
    if contract.compilation_status == "rejected":
        return _deny(
            "contract_rejected",
            "任务 Capability Contract 已被编译器拒绝。",
            "被拒绝的任务不能继续获得工具权限。",
        )

    # ---------------------------------------------------------
    # 2. 最大步骤数
    # ---------------------------------------------------------
    if request.current_step > contract.max_steps:
        return _deny(
            "max_steps_exceeded",
            (
                f"当前步骤 {request.current_step} "
                f"超过合约允许的最大步骤数 "
                f"{contract.max_steps}。"
            ),
        )

    # ---------------------------------------------------------
    # 3. 明确禁止的工具
    # ---------------------------------------------------------
    if tool in set(
        contract.forbidden_tools
    ):
        return _deny(
            "forbidden_tool",
            (
                f"工具 {tool} 被当前任务合约明确禁止。"
            ),
        )

    path = get_path(params)

    resource = (
        _normalize_contract_resource(path)
        if path
        else None
    )

    # ---------------------------------------------------------
    # 4. 明确禁止的资源
    # ---------------------------------------------------------
    if (
        resource
        and contract.forbidden_resources
        and _match_any(
            resource,
            contract.forbidden_resources,
        )
    ):
        return _deny(
            "forbidden_resource",
            (
                f"资源 {resource} "
                "命中任务合约的禁止资源范围。"
            ),
        )

    recipient = _get_recipient(
        params
    )

    # ---------------------------------------------------------
    # 5. 必须存在真正匹配本次调用的能力
    #
    # 这是最关键的一条：
    # OAuth 有 file 权限
    # 不等于
    # 当前这个任务允许读任何文件
    # ---------------------------------------------------------
    matched_rule = None

    for rule in contract.capabilities:
        if _rule_matches(
            rule=rule,
            tool=tool,
            resource=resource,
            recipient=recipient,
        ):
            matched_rule = rule
            break

    if matched_rule is None:
        return _deny(
            "contract_violation",
            "当前工具调用没有匹配到任务合约授予的任何能力。",
            f"tool={tool}",
            f"resource={resource}",
            f"recipient={recipient}",
        )

    return None


def check_hard_constraints(
    request: ToolCallRequest,
) -> HardConstraintResult:
    """
    新授权架构第一阶段：

        Deterministic Hard Authorization Constraints

    只有不存在确定性违规时，
    才允许进入后面的概率风险模型。
    """

    tool = normalize_tool_name(
        request.tool
    )

    params = normalize_params(
        tool,
        request.params,
    )

    # =========================================================
    # 1. 未登记工具
    # =========================================================
    supported_tools = set(
        get_supported_tools()
    )

    if tool not in supported_tools:
        return _deny(
            "unknown_tool",
            f"工具 {tool} 未登记。",
            "未知工具不进入概率模型，直接拒绝。",
        )

    # =========================================================
    # 2. Agent 计划状态异常
    # =========================================================
    plan_status = str(
        request.plan_status or ""
    ).strip().lower()

    if plan_status in INVALID_PLAN_STATES:
        return _deny(
            "invalid_plan_state",
            (
                f"Agent 计划状态异常："
                f"{plan_status}"
            ),
            "无效计划不能继续获得工具权限。",
        )

    # =========================================================
    # 3. 必要参数缺失
    # =========================================================
    required_params = (
        get_required_params()
    )

    missing_params: List[str] = []

    for name in required_params.get(
        tool,
        [],
    ):
        value = params.get(name)

        if value is None:
            missing_params.append(name)
            continue

        if (
            isinstance(value, str)
            and (
                not value.strip()
                or value.strip().lower()
                == "unknown"
            )
        ):
            missing_params.append(name)

    if missing_params:
        return _deny(
            "missing_required_parameter",
            (
                "工具调用缺少必要参数："
                + ", ".join(
                    missing_params
                )
            ),
            "参数不完整，无法确定实际授权对象。",
        )

    # =========================================================
    # 4. 路径安全边界
    # =========================================================
    path = get_path(params)

    if path:
        analysis = (
            analyze_resource_path(path)
        )

        if analysis.has_traversal:
            return _deny(
                "path_traversal",
                "检测到目录穿越路径。",
                "资源已经越出授权边界。",
            )

        if analysis.has_encoded_bypass:
            return _deny(
                "encoded_path_bypass",
                "检测到 URL 编码路径绕过。",
                "编码不能用于绕过资源授权边界。",
            )

        if analysis.is_absolute:
            return _deny(
                "absolute_path_escape",
                "检测到绝对路径或 UNC 网络路径。",
                "当前资源必须位于受控工作区。",
            )

    # =========================================================
    # 5. Capability Contract
    # =========================================================
    contract_result = (
        _check_capability_contract(
            request=request,
            tool=tool,
            params=params,
        )
    )

    if contract_result is not None:
        return contract_result

    # =========================================================
    # 通过硬约束并不代表 allow
    # =========================================================
    return HardConstraintResult(
        passed=True,
        decision="continue",
        violation_type=None,
        reasons=[
            "未发现确定性的授权边界违规，可以进入概率风险评估阶段。"
        ],
    )
