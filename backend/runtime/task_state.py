from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from backend.capability.capability_contract import CapabilityContract


Decision = Literal["allow", "confirm", "deny"]


class RuntimeStepRecord(BaseModel):
    """
    任务运行时的单步记录。
    """

    step_index: int = Field(..., description="当前步骤编号")
    tool: str = Field(..., description="调用的工具名称")
    params: Dict[str, Any] = Field(default_factory=dict, description="工具调用参数")

    input_from_steps: List[int] = Field(
        default_factory=list,
        description="当前步骤输入数据继承自哪些历史步骤"
    )

    input_labels: List[str] = Field(default_factory=list, description="输入数据标签")
    output_labels: List[str] = Field(default_factory=list, description="输出数据标签")

    label_sources: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="每个输入标签的来源，例如 direct_input 或 step:1"
    )

    decision: Decision = Field(..., description="allow / confirm / deny")
    risk_score: int = Field(default=0, description="本步骤风险分")
    reason: List[str] = Field(default_factory=list, description="决策原因")

    executed: bool = Field(default=False, description="该步骤是否被执行")
    blocked: bool = Field(default=False, description="该步骤是否被阻断")
    requires_confirmation: bool = Field(
        default=False,
        description="该步骤是否需要人工确认"
    )

    confirmed: bool = Field(
        default=False,
        description="该步骤是否已经被人工确认"
    )

    confirmation_status: Literal["none", "pending", "approved", "rejected"] = Field(
        default="none",
        description="人工确认状态"
    )


class RuntimeTaskState(BaseModel):
    """
    任务级运行时状态。
    记录整个任务执行过程。
    后续 Taint Graph、Audit Graph、风险预算、步骤限制都会基于它实现。
    """

    task_id: str = Field(..., description="任务编号")
    user: str = Field(..., description="任务发起用户")
    original_task: str = Field(..., description="用户原始任务")

    contract: CapabilityContract = Field(..., description="该任务绑定的 Capability Contract v2")

    current_step: int = Field(default=0, description="当前已经执行到第几步")
    used_risk: int = Field(default=0, description="当前已经消耗的风险预算")

    steps: List[RuntimeStepRecord] = Field(default_factory=list, description="任务步骤记录")

    data_labels_by_step: Dict[int, List[str]] = Field(
        default_factory=dict,
        description="每一步输出的数据标签"
    )

    data_lineage_edges: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="跨步骤数据流边，用于记录标签从哪个步骤流向哪个步骤"
    )

    violations: List[str] = Field(default_factory=list, description="任务中发生的违规原因")
    is_blocked: bool = Field(default=False, description="任务是否已经被阻断")
    final_decision: Decision = Field(
    default="allow",
    description="当前任务的整体最终决策：allow / confirm / deny")

    attack_chain_state: Optional[Dict[str, Any]] = Field(
    default=None,
    description="攻击链检测器的状态快照"
)

    pending_confirm_steps: List[int] = Field(
    default_factory=list,
    description="需要人工确认的步骤编号"
)