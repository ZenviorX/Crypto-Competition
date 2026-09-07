from __future__ import annotations

from fastapi import APIRouter

from backend.real_agent.tool_call_adapter import (
    LLMToolCallRunRequest,
    run_llm_tool_call_through_agentguard,
)

router = APIRouter(
    prefix="/real-agent",
    tags=["Real Agent Tool Calling"],
)


@router.post("/tool-call/run")
def run_real_agent_tool_call(request: LLMToolCallRunRequest):
    """
    Run an OpenAI-compatible LLM tool call through AgentGuard.

    This route is designed for competition demo and report evidence:

    Real LLM tool_call
        -> OpenAI-compatible adapter
        -> Tool Proxy prepare phase
        -> Capability Token
        -> execute phase
        -> Hybrid Sandbox
        -> Audit / Evidence

    The route proves that AgentGuard is not limited to FakeAgent demos.
    It can accept real LLM tool-calling outputs and enforce the same security
    boundary before any tool enters execution.
    """

    return run_llm_tool_call_through_agentguard(request)
