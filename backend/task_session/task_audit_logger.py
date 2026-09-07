import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from backend.task_session.session_models import TaskSession


BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"
TASK_AUDIT_LOG = LOG_DIR / "task_sessions.jsonl"


def now_iso() -> str:
    """
    返回当前 UTC 时间。
    """
    return datetime.now(timezone.utc).isoformat()


def task_session_to_log_record(session: TaskSession) -> Dict[str, Any]:
    """
    将 TaskSession 转换成适合写入日志的 dict。

    这里不直接手写每个字段，而是使用 Pydantic 的 model_dump / dict，
    兼容不同版本的 pydantic。
    """
    if hasattr(session, "model_dump"):
        data = session.model_dump()
    else:
        data = session.dict()

    return {
        "log_type": "task_session",
        "logged_at": now_iso(),
        "session": data,
    }


def write_task_session_log(session: TaskSession) -> None:
    """
    将一次多步任务链执行结果写入 JSONL 日志文件。

    每一行是一条完整任务链记录。
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    record = task_session_to_log_record(session)

    with TASK_AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_task_session_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """
    读取最近的多步任务链日志。

    默认返回最近 50 条。
    """
    if not TASK_AUDIT_LOG.exists():
        return []

    lines = TASK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()

    records: List[Dict[str, Any]] = []

    for line in lines[-limit:]:
        if not line.strip():
            continue

        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records