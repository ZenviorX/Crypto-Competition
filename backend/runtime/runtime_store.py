from __future__ import annotations

from typing import Dict, Optional

from backend.runtime.task_state import RuntimeTaskState


_RUNTIME_STATES: Dict[str, RuntimeTaskState] = {}


def save_runtime_state(state: RuntimeTaskState) -> RuntimeTaskState:
    """
    保存任务运行时状态。

    当前先使用内存字典，后续可以升级为 jsonl / sqlite / redis。
    """
    _RUNTIME_STATES[state.task_id] = state
    return state


def get_runtime_state(task_id: str) -> Optional[RuntimeTaskState]:
    """
    根据 task_id 获取任务运行时状态。
    """
    return _RUNTIME_STATES.get(task_id)


def delete_runtime_state(task_id: str) -> bool:
    """
    删除任务运行时状态。
    """
    if task_id in _RUNTIME_STATES:
        del _RUNTIME_STATES[task_id]
        return True

    return False


def list_runtime_states() -> Dict[str, RuntimeTaskState]:
    """
    返回所有运行时状态。
    """
    return _RUNTIME_STATES