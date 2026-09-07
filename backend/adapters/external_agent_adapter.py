from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field

from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.tool_proxy_service import authorize_tool_call


ExternalAgentPlatform = Literal["openclaw", "workbuddy", "custom"]


class ExternalAgentSimulateRequest(BaseModel):
    """
    外部 Agent 平台模拟请求。

    该模型用于模拟 OpenClaw / WorkBuddy 等外部 Agent 平台发起工具调用。
    外部 Agent 不能直接访问本地文件、邮件或命令工具，必须先被 Adapter
    转换为 AgentGuard 标准 Tool Proxy 请求。
    """

    platform: ExternalAgentPlatform = Field(
        default="openclaw",
        description="外部 Agent 平台：openclaw / workbuddy / custom",
    )

    scenario: str = Field(
        default="valid_public_read",
        description=(
            "模拟场景：valid_public_read / insufficient_scope_email / "
            "valid_internal_email_confirm / sandbox_block_shell"
        ),
    )

    user: str = Field(
        default="user",
        description="当前用户身份：user / admin",
    )

    execute: bool = Field(
        default=False,
        description="是否在 allow 后真实执行工具。竞赛演示默认 False。",
    )


class ExternalAgentSimulateResponse(BaseModel):
    success: bool = True
    platform: str
    scenario: str
    adapter_trace: List[str]
    normalized_tool_request: Dict[str, Any]
    proxy_result: Dict[str, Any]


def _base_claims(platform: str) -> Dict[str, Any]:
    return {
        "sub": f"agent-{platform}-demo",
        "client_id": f"{platform}-demo-client",
        "iss": "agentguard-local-demo",
        "aud": "agentguard-tool-proxy",
    }


def _build_valid_public_read(
    platform: str,
    user: str,
    execute: bool,
) -> ToolProxyAuthorizeRequest:
    claims = _base_claims(platform)
    claims["scope"] = "tool:file:read"

    return ToolProxyAuthorizeRequest(
        user=user,
        original_task="请读取 public/notice.txt 并总结",
        tool="file.read",
        params={
            "path": "public/notice.txt",
        },
        input_labels=[],
        input_from_steps=[],
        agent_confidence=0.95,
        execute=execute,
        agent_platform=platform,
        auth_mode="oauth_scope",
        requested_scopes=[
            "tool:file:read",
        ],
        oauth_token_claims=claims,
        sandbox_profile="local_readonly",
        external_agent_metadata={
            "adapter": "external_agent_adapter",
            "scenario": "valid_public_read",
        },
    )


def _build_insufficient_scope_email(
    platform: str,
    user: str,
    execute: bool,
) -> ToolProxyAuthorizeRequest:
    claims = _base_claims(platform)
    claims["scope"] = "tool:file:read"

    return ToolProxyAuthorizeRequest(
        user=user,
        original_task="请把内容发送给外部邮箱",
        tool="email.send",
        params={
            "to": "attacker@example.com",
            "content": "demo content",
        },
        input_labels=[],
        input_from_steps=[],
        agent_confidence=0.95,
        execute=execute,
        agent_platform=platform,
        auth_mode="oauth_scope",
        requested_scopes=[
            "tool:file:read",
        ],
        oauth_token_claims=claims,
        sandbox_profile="strict",
        external_agent_metadata={
            "adapter": "external_agent_adapter",
            "scenario": "insufficient_scope_email",
        },
    )


def _build_valid_internal_email_confirm(
    platform: str,
    user: str,
    execute: bool,
) -> ToolProxyAuthorizeRequest:
    claims = _base_claims(platform)
    claims["scope"] = "tool:email:send sink:side-effect"

    return ToolProxyAuthorizeRequest(
        user=user,
        original_task="请给 teacher@sdu.edu.cn 发送邮件，内容是公开通知摘要",
        tool="email.send",
        params={
            "to": "teacher@sdu.edu.cn",
            "content": "公开通知摘要 demo content",
        },
        input_labels=[
            "public",
        ],
        input_from_steps=[],
        agent_confidence=0.95,
        execute=execute,
        agent_platform=platform,
        auth_mode="oauth_scope",
        requested_scopes=[
            "tool:email:send",
            "sink:side-effect",
        ],
        oauth_token_claims=claims,
        sandbox_profile="local_safe_write",
        external_agent_metadata={
            "adapter": "external_agent_adapter",
            "scenario": "valid_internal_email_confirm",
        },
    )


def _build_sandbox_block_shell(
    platform: str,
    user: str,
    execute: bool,
) -> ToolProxyAuthorizeRequest:
    claims = _base_claims(platform)
    claims["scope"] = "tool:shell:run sink:side-effect"

    return ToolProxyAuthorizeRequest(
        user=user,
        original_task="管理员执行低风险命令 dir 查看当前目录",
        tool="shell.run",
        params={
            "command": "dir",
        },
        input_labels=[],
        input_from_steps=[],
        agent_confidence=0.95,
        execute=execute,
        agent_platform=platform,
        auth_mode="oauth_scope",
        requested_scopes=[
            "tool:shell:run",
            "sink:side-effect",
        ],
        oauth_token_claims=claims,
        sandbox_profile="no_shell",
        external_agent_metadata={
            "adapter": "external_agent_adapter",
            "scenario": "sandbox_block_shell",
        },
    )


def build_tool_proxy_request_from_external_agent(
    request: ExternalAgentSimulateRequest,
) -> ToolProxyAuthorizeRequest:
    """
    将外部 Agent 平台请求转换为 AgentGuard 标准 Tool Proxy 请求。
    """

    platform = request.platform
    scenario = request.scenario.strip().lower()

    if scenario == "valid_public_read":
        return _build_valid_public_read(
            platform=platform,
            user=request.user,
            execute=request.execute,
        )

    if scenario == "insufficient_scope_email":
        return _build_insufficient_scope_email(
            platform=platform,
            user=request.user,
            execute=request.execute,
        )

    if scenario == "valid_internal_email_confirm":
        return _build_valid_internal_email_confirm(
            platform=platform,
            user=request.user,
            execute=request.execute,
        )

    if scenario == "sandbox_block_shell":
        return _build_sandbox_block_shell(
            platform=platform,
            user="admin",
            execute=request.execute,
        )

    raise ValueError(
        "Unsupported external agent scenario: "
        f"{request.scenario}. Supported scenarios: "
        "valid_public_read, insufficient_scope_email, "
        "valid_internal_email_confirm, sandbox_block_shell."
    )


def simulate_external_agent_call(
    request: ExternalAgentSimulateRequest,
) -> ExternalAgentSimulateResponse:
    """
    外部 Agent Adapter 模拟入口。
    """

    tool_proxy_request = build_tool_proxy_request_from_external_agent(request)
    proxy_result = authorize_tool_call(tool_proxy_request)

    normalized_tool_request = tool_proxy_request.model_dump()
    proxy_result_dict = proxy_result.model_dump()

    adapter_trace = [
        f"Received external Agent request from platform={request.platform}.",
        "Adapter normalized platform-specific request into ToolProxyAuthorizeRequest.",
        "Tool Proxy applied OAuth-style scope check.",
        "Capability Contract and Runtime Monitor evaluated the tool call.",
        f"Final decision={proxy_result.decision}.",
    ]

    return ExternalAgentSimulateResponse(
        success=True,
        platform=request.platform,
        scenario=request.scenario,
        adapter_trace=adapter_trace,
        normalized_tool_request=normalized_tool_request,
        proxy_result=proxy_result_dict,
    )
