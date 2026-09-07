import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from backend.gateway.gateway import check_tool_call
from backend.runtime.tool_executor import SafeToolExecutor
from backend.schemas import ToolCallRequest


@dataclass
class RuntimeExecutionRecord:
    """
    一次 Agent 工具调用的完整运行时记录。
    """
    user: str
    tool: str
    params: Dict[str, Any]
    gateway_decision: str
    risk_score: Any
    risk_level: str
    gateway_reason: Any
    execution_status: str
    execution_result: Optional[Dict[str, Any]]
    message: str
    elapsed_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecureAgentRuntime:
    """
    Agent 工具调用安全运行时。

    Gateway 返回 allow 时才进入受控工具执行器；
    返回 confirm 时进入人工确认等待；
    返回 deny 时直接拒绝执行。
    """

    def __init__(self) -> None:
        self.executor = SafeToolExecutor()

    def run_tool_call(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()

        request = ToolCallRequest(**request_data)
        gateway_result = check_tool_call(request)

        decision = gateway_result.get("decision")
        risk_score = gateway_result.get("risk_score")
        risk_level = gateway_result.get("risk_level", "")
        reason = gateway_result.get("reason", [])


        if decision == "allow":
            execution_result = self.executor.execute(
                tool=request.tool,
                params=request.params,
            ).to_dict()

            elapsed_ms = (time.perf_counter() - start) * 1000

            return RuntimeExecutionRecord(
                user=request.user,
                tool=request.tool,
                params=request.params,
                gateway_decision=decision,
                risk_score=risk_score,
                risk_level=risk_level,
                gateway_reason=reason,
                execution_status=execution_result.get("status", "unknown"),
                execution_result=execution_result,
                message="Gateway allowed the tool call and the tool was executed by SafeToolExecutor.",
                elapsed_ms=elapsed_ms,
            ).to_dict()

        if decision == "confirm":
            elapsed_ms = (time.perf_counter() - start) * 1000

            return RuntimeExecutionRecord(
                user=request.user,
                tool=request.tool,
                params=request.params,
                gateway_decision=decision,
                risk_score=risk_score,
                risk_level=risk_level,
                gateway_reason=reason,
                execution_status="waiting_for_human_confirmation",
                execution_result=None,
                message="Gateway requires human confirmation before executing this tool call.",
                elapsed_ms=elapsed_ms,
            ).to_dict()

        elapsed_ms = (time.perf_counter() - start) * 1000

        return RuntimeExecutionRecord(
            user=request.user,
            tool=request.tool,
            params=request.params,
            gateway_decision=decision,
            risk_score=risk_score,
            risk_level=risk_level,
            gateway_reason=reason,
            execution_status="blocked_by_gateway",
            execution_result=None,
            message="Gateway denied the tool call. The tool was not executed.",
            elapsed_ms=elapsed_ms,
        ).to_dict()


def run_secure_tool_call(request_data: Dict[str, Any]) -> Dict[str, Any]:
    runtime = SecureAgentRuntime()
    return runtime.run_tool_call(request_data)
