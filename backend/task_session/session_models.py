from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def now_iso() -> str:
    """
    返回当前 UTC 时间，用于记录任务链和步骤创建时间。
    """
    return datetime.now(timezone.utc).isoformat()


class TaskStep(BaseModel):
    """
    表示多步任务链中的一个步骤。

    例如：
    Step 1: file.read public/notice.txt
    Step 2: email.send admin@sdu.edu.cn

    后续真实 Agent 演示中，每个 TaskStep 不只记录工具调用，
    还要记录：
    1. 大模型原始输出；
    2. 参数解析结果；
    3. 数据标签传播；
    4. Gateway / Runtime Monitor 判断；
    5. 沙箱执行结果。
    """

    step_id: int
    tool: str
    params: Dict[str, Any] = Field(default_factory=dict)

    description: str = ""

    # ------------------------------------------------------------
    # LLM 规划相关字段
    # ------------------------------------------------------------

    raw_llm_output: Optional[str] = None
    agent_confidence: float = 0.0
    agent_reason: str = ""

    # ------------------------------------------------------------
    # 参数与数据流字段
    # ------------------------------------------------------------

    input_from_steps: List[int] = Field(default_factory=list)
    input_labels: List[str] = Field(default_factory=list)
    output_labels: List[str] = Field(default_factory=list)

    # real_params 是处理 content_from_step 之后真正送入 Gateway / Runtime 的参数
    real_params: Dict[str, Any] = Field(default_factory=dict)

    # output_excerpt 用于前端展示，避免把完整敏感内容直接显示出来
    output_excerpt: str = ""

    # ------------------------------------------------------------
    # 安全判断字段
    # ------------------------------------------------------------

    decision: Optional[str] = None
    risk_score: int = 0
    reason: List[str] = Field(default_factory=list)

    gateway_result: Optional[Dict[str, Any]] = None
    runtime_result: Optional[Dict[str, Any]] = None
    attack_chain_state: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------
    # 执行状态字段
    # ------------------------------------------------------------

    executed: bool = False
    blocked: bool = False
    requires_confirmation: bool = False
    confirmed: bool = False
    confirmation_status: str = "none"

    tool_result: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------
    # 兼容旧任务链逻辑的布尔字段
    # ------------------------------------------------------------

    sensitive: bool = False
    tainted: bool = False

    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    def mark_updated(self) -> None:
        """
        更新步骤修改时间。
        """
        self.updated_at = now_iso()


class TaskSession(BaseModel):
    """
    表示一次完整的 Agent 任务链。

    一个 TaskSession 里可以包含多个 TaskStep。

    它用于支撑：
    1. 多步任务执行；
    2. Capability Contract 任务级授权；
    3. Runtime Monitor 状态追踪；
    4. input_labels / output_labels 数据标签传播；
    5. 提示注入攻击链检测；
    6. 前端证据链展示。
    """

    session_id: str = Field(default_factory=lambda: str(uuid4()))

    # ??????????????
    # Agent ??????????????????????
    task_handle: Optional[str] = None

    # SQLite ?????????????????????
    version: int = 0

    user: str
    original_input: str
    agent_type: str = "fake"

    # OAuth 任务授权上下文。
    #
    # 任务不仅绑定用户 sub，也绑定创建任务时的
    # issuer、client、audience 和 scope 权限上限。
    oauth_authorization_binding: Dict[
        str,
        Any,
    ] = Field(
        default_factory=dict
    )

    oauth_authorization_fingerprint: str = ""

    steps: List[TaskStep] = Field(default_factory=list)

    # ------------------------------------------------------------
    # 任务级运行状态
    # ------------------------------------------------------------

    status: str = "created"
    final_decision: str = "allow"

    # ------------------------------------------------------------
    # Runtime / Capability 关联字段
    # ------------------------------------------------------------

    task_id: Optional[str] = None
    contract: Optional[Dict[str, Any]] = None
    runtime_state: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------
    # 上下文安全状态
    # ------------------------------------------------------------

    context_risk_score: int = 0
    sensitive_context: bool = False
    tainted_context: bool = False

    data_labels_by_step: Dict[int, List[str]] = Field(default_factory=dict)
    pending_confirm_steps: List[int] = Field(default_factory=list)
    violations: List[str] = Field(default_factory=list)

    # ------------------------------------------------------------
    # Agent 原始输出与证据展示
    # ------------------------------------------------------------

    raw_agent_outputs: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    def add_step(self, step: TaskStep) -> None:
        """
        向任务链中添加一个步骤。
        """
        self.steps.append(step)
        self.updated_at = now_iso()

    def mark_running(self) -> None:
        """
        标记任务链正在执行。
        """
        self.status = "running"
        self.updated_at = now_iso()

    def mark_finished(self) -> None:
        """
        标记任务链执行完成。
        """
        self.status = "finished"
        self.updated_at = now_iso()

    def mark_blocked(self) -> None:
        """
        标记任务链被安全网关或运行时阻断。
        """
        self.status = "blocked"
        self.final_decision = "deny"
        self.updated_at = now_iso()

    def mark_confirm_required(self, step_id: int) -> None:
        """
        标记任务链进入人工确认状态。
        """
        self.status = "confirm_required"
        self.final_decision = "confirm"

        if step_id not in self.pending_confirm_steps:
            self.pending_confirm_steps.append(step_id)

        self.updated_at = now_iso()

    def update_final_decision(self, decision: str) -> None:
        """
        更新任务级最终决策。

        优先级：
        deny > confirm > allow
        """
        priority = {
            "allow": 0,
            "confirm": 1,
            "deny": 2,
        }

        current_level = priority.get(self.final_decision, 0)
        new_level = priority.get(decision, 0)

        if new_level >= current_level:
            self.final_decision = decision

        self.updated_at = now_iso()

    def record_step_labels(self, step_id: int, labels: List[str]) -> None:
        """
        记录某一步产生的输出标签。
        后续步骤可以通过 input_from_steps 继承这些标签。
        """
        self.data_labels_by_step[step_id] = labels
        self.updated_at = now_iso()

    def get_step_output_labels(self, step_id: int) -> List[str]:
        """
        获取某一步的输出标签。
        """
        return self.data_labels_by_step.get(step_id, [])