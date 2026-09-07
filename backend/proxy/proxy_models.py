from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolProxyAuthorizeRequest(BaseModel):
    """
    外部 Agent / 前端调试台发来的工具调用授权请求。
    """

    user: str = Field(default="user", description="Current user identity.")
    original_task: str = Field(default="", description="Original natural language task.")

    task_handle: str = Field(
        default="",
        description="Opaque task handle issued and controlled by AgentGuard.",
    )

    tool: str = Field(..., description="Requested tool name.")
    params: Dict[str, Any] = Field(default_factory=dict, description="Tool parameters.")

    input_labels: List[str] = Field(
        default_factory=list,
        description="Data labels carried by current tool input.",
    )
    input_from_steps: List[int] = Field(
        default_factory=list,
        description="Runtime step ids that provide input data for this call.",
    )

    agent_confidence: float = Field(
        default=1.0,
        description="Confidence score reported by the external Agent.",
    )

    execute: bool = Field(
        default=False,
        description="Whether to execute the real tool after allow. Demo default is False.",
    )

    agent_platform: str = Field(
        default="custom",
        description="External Agent platform, such as openclaw / workbuddy / custom.",
    )
    auth_mode: str = Field(
        default="none",
        description="Authorization mode, such as oauth_scope.",
    )
    requested_scopes: List[str] = Field(
        default_factory=list,
        description="Scopes declared by external Agent request.",
    )
    oauth_token_claims: Dict[str, Any] = Field(
        default_factory=dict,
        description="OAuth-like token claims from external Agent.",
    )

    capability_token: str = Field(
        default="",
        description="Optional task-scoped capability token issued by AgentGuard.",
    )

    capability_token_validation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Capability token validation result.",
    )

    authorization_trace: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered authorization decision trace.",
    )

    task_boundary_evaluation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Task boundary guard evaluation result.",
    )

    sandbox_profile: str = Field(
        default="default",
        description="Sandbox profile name.",
    )
    external_agent_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata from external Agent adapter.",
    )

    approval_ticket: str = Field(
        default="",
        description=(
            "Server-issued human approval ticket for this exact call."
        ),
    )


class ToolProxyAuthorizeResponse(BaseModel):
    success: bool = True
    mode: str = "tool_proxy_authorize"

    task_handle: str = Field(
        default="",
        description="Opaque task handle used for this authorization decision.",
    )
    task_version: int = Field(
        default=0,
        description="Current persisted task session version.",
    )

    decision: str
    risk_score: int
    reason: List[str] = Field(default_factory=list)

    executed: bool = False
    tool_result: Optional[Dict[str, Any]] = None
    sandbox_evidence: Optional[Dict[str, Any]] = None

    contract: Dict[str, Any] = Field(default_factory=dict)
    runtime_state: Dict[str, Any] = Field(default_factory=dict)
    security_graph: Dict[str, Any] = Field(default_factory=dict)

    agent_auth_profile: Dict[str, Any] = Field(
        default_factory=dict,
        description="OAuth-style Agent authorization profile.",
    )
    capability_token: Dict[str, Any] = Field(
        default_factory=dict,
        description="Task-scoped signed capability token issued by AgentGuard.",
    )

    capability_token_validation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Capability token validation result.",
    )

    authorization_trace: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered authorization decision trace.",
    )

    task_boundary_evaluation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Task boundary guard evaluation result.",
    )

    sandbox_profile: str = Field(
        default="default",
        description="Sandbox profile name.",
    )
    sandbox_evaluation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed sandbox policy evaluation result.",
    )

    data_ref: str = Field(
        default="",
        description=(
            "Opaque server-issued reference to the trusted output data."
        ),
    )

    approval_ticket: str = Field(
        default="",
        description=(
            "Opaque server-issued human approval ticket."
        ),
    )

    approval_status: str = Field(
        default="",
        description=(
            "Current approval state: pending, approved, denied or consumed."
        ),
    )
