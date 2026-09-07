from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


SecurityEventType = Literal[
    "safe",
    "unauthorized",
    "data_exfiltration",
    "credential_access",
    "prompt_injection",
    "destructive_action",
    "privilege_escalation",
    "network_abuse",
    "other",
]


Severity = Literal[
    "none",
    "low",
    "medium",
    "high",
    "critical",
]


class AuthorizationSample(BaseModel):
    """
    Agent 工具调用授权数据集的一条正式样本。

    Ground Truth 描述安全事实，
    不直接使用 allow / confirm / deny 作为标签。
    """

    sample_id: str

    # ---------------------------------------------------------
    # A. 数据来源元信息
    # ---------------------------------------------------------
    source: Optional[str] = None
    scenario_family: Optional[str] = None
    source_candidate_id: Optional[str] = None
    original_case_id: Optional[str] = None
    description: Optional[str] = None

    # ---------------------------------------------------------
    # B. 原始任务上下文
    # ---------------------------------------------------------
    user: str = "user"
    original_task: str
    tool: str

    params: Dict[str, Any] = Field(
        default_factory=dict
    )

    # ---------------------------------------------------------
    # C. 授权上下文
    # ---------------------------------------------------------
    oauth_scopes: List[str] = Field(
        default_factory=list
    )

    task_contract: Optional[
        Dict[str, Any]
    ] = None

    input_labels: List[str] = Field(
        default_factory=list
    )

    current_step: int = 1

    history: List[
        Dict[str, Any]
    ] = Field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # D. 硬约束 Ground Truth
    # ---------------------------------------------------------
    hard_constraint_violation: bool = False

    hard_constraint_type: Optional[str] = None

    # ---------------------------------------------------------
    # E. 安全 Ground Truth
    # ---------------------------------------------------------
    is_unsafe: bool

    security_event_type: SecurityEventType

    severity: Severity

    human_reviewable: bool

    annotation_reason: str

    annotator: Optional[str] = None

    annotation_version: str = "v1"
