from typing import Dict

from fastapi import APIRouter
from pydantic import Field

from backend.attack_chain import AttackChainDetector
from backend.gateway.gateway import check_tool_call
from backend.schemas import ToolCallRequest


router = APIRouter()

# 简单内存态会话表。
# 后续可以替换成 Redis、SQLite 或 task_sessions.jsonl。
_DETECTORS: Dict[str, AttackChainDetector] = {}


class AttackChainGatewayRequest(ToolCallRequest):
    """
    带攻击链会话 ID 的网关检查请求。
    继承 ToolCallRequest，兼容原有 user / tool / params / task_contract 等字段。
    """

    chain_session_id: str = Field(default="default")


def get_detector(session_id: str) -> AttackChainDetector:
    if session_id not in _DETECTORS:
        _DETECTORS[session_id] = AttackChainDetector(session_id=session_id)

    return _DETECTORS[session_id]


def reset_detector(session_id: str) -> AttackChainDetector:
    detector = AttackChainDetector(session_id=session_id)
    _DETECTORS[session_id] = detector
    return detector


def merge_decision(gateway_decision: str, chain_decision: str) -> str:
    """
    合并单次网关决策与攻击链决策。
    规则：更严格的决策优先。
    deny > confirm > allow
    """
    severity = {
        "allow": 0,
        "confirm": 1,
        "deny": 2,
    }

    gateway_level = severity.get(gateway_decision, 2)
    chain_level = severity.get(chain_decision, 2)

    if max(gateway_level, chain_level) == 2:
        return "deny"

    if max(gateway_level, chain_level) == 1:
        return "confirm"

    return "allow"


@router.post("/attack-chain/check")
def attack_chain_check(request: AttackChainGatewayRequest):
    """
    运行时攻击链增强检查接口。
    """
    gateway_result = check_tool_call(request)

    detector = get_detector(request.chain_session_id)

    chain_result = detector.add_event(
        tool=gateway_result.get("normalized_tool", request.tool),
        params=gateway_result.get("normalized_params", request.params),
        gateway_result=gateway_result,
    )

    gateway_decision = gateway_result.get("decision", "deny")
    chain_decision = chain_result.get("final_decision", "deny")
    effective_decision = merge_decision(gateway_decision, chain_decision)

    return {
        "session_id": request.chain_session_id,
        "gateway_decision": gateway_decision,
        "chain_decision": chain_decision,
        "effective_decision": effective_decision,
        "gateway_result": gateway_result,
        "chain_result": chain_result,
    }


@router.get("/attack-chain/session/{session_id}")
def get_attack_chain_session(session_id: str):
    """
    查看某个攻击链会话的当前状态。
    """
    detector = get_detector(session_id)

    return detector.to_dict()


@router.post("/attack-chain/reset/{session_id}")
def reset_attack_chain_session(session_id: str):
    """
    重置某个攻击链会话，便于重新演示。
    """
    detector = reset_detector(session_id)

    return {
        "message": "attack chain session reset",
        "session_id": session_id,
        "state": detector.to_dict(),
    }
