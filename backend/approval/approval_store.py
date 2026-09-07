from datetime import datetime
from uuid import uuid4
from typing import Dict, Any, Optional


PENDING_REQUESTS: Dict[str, Dict[str, Any]] = {}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _model_to_dict(model):
    """
    兼容 Pydantic v1 和 v2。
    """
    if hasattr(model, "model_dump"):
        return model.model_dump()

    return model.dict()


def create_pending_request(
    tool_request,
    gateway_result: Dict[str, Any],
    original_input: Optional[str] = None,
    agent_result: Optional[Dict[str, Any]] = None,
):
    pending_id = str(uuid4())

    PENDING_REQUESTS[pending_id] = {
        "pending_id": pending_id,
        "status": "pending",
        "created_at": _now(),
        "tool_request": _model_to_dict(tool_request),
        "gateway_result": gateway_result,
        "original_input": original_input,
        "agent_result": agent_result,
    }

    return pending_id


def list_pending_requests(limit: int = 50):
    items = list(PENDING_REQUESTS.values())
    items = items[-limit:]
    return items[::-1]


def get_pending_request(pending_id: str):
    return PENDING_REQUESTS.get(pending_id)


def pop_pending_request(pending_id: str):
    return PENDING_REQUESTS.pop(pending_id, None)