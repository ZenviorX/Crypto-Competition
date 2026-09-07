import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import uuid4


BASE_DIR = Path(__file__).resolve().parents[2]
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "audit.log"

SENSITIVE_WORDS = [
    "password",
    "token",
    "secret",
    "key",
    "credential",
    "密钥",
    "密码",
]

MAX_LOG_VALUE_LENGTH = 500
GENESIS_HASH = "0" * 64


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _mask_sensitive_value(key: str, value: Any):
    """
    简单脱敏，避免日志里直接保存 password、token、key 等敏感值。
    """
    key_lower = str(key).lower()

    if any(word in key_lower for word in SENSITIVE_WORDS):
        return "***MASKED***"

    if isinstance(value, dict):
        return {k: _mask_sensitive_value(k, v) for k, v in value.items()}

    if isinstance(value, list):
        return [_mask_sensitive_value(key, item) for item in value]

    if isinstance(value, str):
        value_lower = value.lower()

        if any(word in value_lower for word in SENSITIVE_WORDS):
            return "***MASKED***"

        if len(value) > MAX_LOG_VALUE_LENGTH:
            return value[:MAX_LOG_VALUE_LENGTH] + "...[TRUNCATED]"

    return value


def _mask_log_value(value: Any):
    return _mask_sensitive_value("", value)


def _canonical_json(data: Dict[str, Any]) -> str:
    """
    生成稳定JSON字符串，用于计算哈希。
    sort_keys=True 可以保证字段顺序不影响哈希结果。
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _calculate_record_hash(record: Dict[str, Any]) -> str:
    """
    计算单条审计日志的哈希。
    注意：计算时排除 record_hash 字段自身。
    """
    data = dict(record)
    data.pop("record_hash", None)

    raw = _canonical_json(data).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _read_jsonl_records() -> list[Dict[str, Any]]:
    """
    读取 audit.log 中的 JSONL 记录。
    遇到损坏行时跳过，避免整个接口崩溃。
    """
    if not LOG_FILE.exists():
        return []

    records = []

    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records


def _get_last_hash() -> str:
    """
    获取上一条带 record_hash 的日志哈希。
    如果没有历史日志，则返回创世哈希。
    这样兼容旧版本没有哈希字段的日志。
    """
    records = _read_jsonl_records()

    for record in reversed(records):
        record_hash = record.get("record_hash")
        if record_hash:
            return str(record_hash)

    return GENESIS_HASH


def write_log(
    user: str,
    tool: str,
    params: Dict[str, Any],
    gateway_result: Dict[str, Any],
    executed: bool,
    original_input: Optional[str] = None,
    message: Optional[str] = None,
    pending_id: Optional[str] = None,
    tool_result: Optional[Dict[str, Any]] = None,
):
    """
    写入一条审计日志。

    1. 对敏感字段进行脱敏；
    2. 每条日志保存 prev_hash；
    3. 每条日志保存 record_hash；
    4. 多条日志形成哈希链，可用于检测篡改。
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    prev_hash = _get_last_hash()

    record = {
        "request_id": str(uuid4()),
        "time": _now(),
        "user": user,
        "original_input": _mask_log_value(original_input),
        "tool": tool,
        "params": _mask_log_value(params),
        "decision": gateway_result.get("decision"),
        "risk_score": gateway_result.get("risk_score"),
        "risk_level": gateway_result.get("risk_level"),
        "reason": gateway_result.get("reason"),
        "explanations": gateway_result.get("explanations"),
        "executed": executed,
        "pending_id": pending_id,
        "message": _mask_log_value(message),
        "tool_result": _mask_log_value(tool_result),
        "prev_hash": prev_hash,
    }

    record["record_hash"] = _calculate_record_hash(record)

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def get_logs(limit: int = 50):
    """
    读取最近 limit 条审计日志。
    """
    records = _read_jsonl_records()
    records = records[-limit:]
    return records[::-1]


def verify_audit_chain() -> Dict[str, Any]:
    """
    校验审计日志哈希链是否完整。

    返回：
    - valid: True / False
    - total_records: 日志总数
    - checked_records: 实际参与哈希链校验的日志数
    - broken_index: 第一条异常日志的位置
    - reason: 校验结果说明
    """
    records = _read_jsonl_records()

    if not records:
        return {
            "valid": True,
            "total_records": 0,
            "checked_records": 0,
            "broken_index": None,
            "reason": "审计日志为空，无需校验。",
        }

    previous_hash = GENESIS_HASH
    checked_records = 0
    chain_started = False

    for index, record in enumerate(records):
        record_hash = record.get("record_hash")
        prev_hash = record.get("prev_hash")

        # 兼容旧日志：如果一条日志没有哈希字段，则跳过。
        # 一旦发现第一条带哈希的日志，就开始严格校验后续链条。
        if not record_hash or not prev_hash:
            if chain_started:
                return {
                    "valid": False,
                    "total_records": len(records),
                    "checked_records": checked_records,
                    "broken_index": index,
                    "reason": "哈希链开始后出现缺少哈希字段的日志。",
                }
            continue

        if not chain_started:
            chain_started = True
            previous_hash = prev_hash

        if prev_hash != previous_hash:
            return {
                "valid": False,
                "total_records": len(records),
                "checked_records": checked_records,
                "broken_index": index,
                "reason": "prev_hash 与上一条日志 record_hash 不一致，日志可能被删除、插入或重排。",
            }

        recalculated_hash = _calculate_record_hash(record)

        if recalculated_hash != record_hash:
            return {
                "valid": False,
                "total_records": len(records),
                "checked_records": checked_records,
                "broken_index": index,
                "reason": "record_hash 校验失败，日志内容可能被篡改。",
            }

        previous_hash = record_hash
        checked_records += 1

    return {
        "valid": True,
        "total_records": len(records),
        "checked_records": checked_records,
        "broken_index": None,
        "reason": "审计日志哈希链校验通过。",
    }
