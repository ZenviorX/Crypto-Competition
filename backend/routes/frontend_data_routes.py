from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from fastapi import APIRouter

from backend.audit import get_logs


router = APIRouter(prefix="/api", tags=["Frontend Runtime Data"])

BASE_DIR = Path(__file__).resolve().parents[2]
RUNTIME_WORKSPACE = BASE_DIR / "runtime_workspace"
NATIVE_RUNS_DIR = RUNTIME_WORKSPACE / "native_sandbox_runs"
DOCKER_RUNS_DIR = RUNTIME_WORKSPACE / "sandbox_runs"
TEST_SUMMARY = BASE_DIR / "test" / "results" / "latest_summary.json"
CONFIG_POLICY = BASE_DIR / "config" / "policy.yaml"


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _safe_str(value: Any, fallback: str = "-") -> str:
    if value is None or value == "":
        return fallback
    return str(value)


def _parse_dt(value: Any) -> datetime:
    if not value:
        return datetime.min

    raw = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(value), fmt)
        except Exception:
            continue

    return datetime.min


def _target_from_params(params: Any) -> str:
    if isinstance(params, dict):
        for key in ("path", "file_path", "resource", "filename", "to", "command", "query", "url"):
            if params.get(key):
                return str(params[key])
        if params:
            return json.dumps(params, ensure_ascii=False)[:160]
    return "-"


def _risk_from_score(score: Any) -> str:
    try:
        value = int(float(score))
    except Exception:
        return "low"

    if value >= 90:
        return "critical"
    if value >= 70:
        return "high"
    if value >= 40:
        return "medium"
    return "low"


def _status_from_decision(decision: Any, executed: Any = False) -> str:
    if decision == "deny":
        return "blocked"
    if decision == "confirm":
        return "pending"
    if decision == "allow":
        return "approved" if executed else "approved"
    return "pending"


def _decision_from_tool_result(tool_result: Any) -> str:
    if isinstance(tool_result, dict) and tool_result.get("success") is False:
        return "deny"
    return "allow"


def _iter_evidence_files() -> Iterable[Path]:
    for base in (NATIVE_RUNS_DIR, DOCKER_RUNS_DIR):
        if not base.exists():
            continue
        yield from base.glob("*/evidence.json")


def _relative_to_runtime(path: Path) -> str:
    try:
        return str(path.relative_to(RUNTIME_WORKSPACE))
    except Exception:
        return str(path)


def _load_evidence_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []

    for evidence_path in _iter_evidence_files():
        evidence = _read_json(evidence_path)
        if not evidence:
            continue
        tool_result = evidence.get("tool_result") or {}
        started_at = evidence.get("started_at") or evidence.get("created_at") or evidence.get("finished_at")
        records.append({
            "kind": "sandbox_evidence",
            "id": _safe_str(evidence.get("run_id"), evidence_path.parent.name),
            "time": _safe_str(started_at),
            "sort_time": _parse_dt(started_at),
            "user": "local",
            "agent": _safe_str(evidence.get("engine"), _safe_str(evidence.get("sandbox_type"), "sandbox")),
            "tool": _safe_str(evidence.get("tool")),
            "params": evidence.get("params") or {},
            "decision": _decision_from_tool_result(tool_result),
            "risk_score": 10 if tool_result.get("success") is not False else 90,
            "reason": tool_result.get("result") if isinstance(tool_result, dict) else "Sandbox execution finished.",
            "executed": True,
            "sandbox_type": evidence.get("sandbox_type"),
            "sandbox_profile": evidence.get("sandbox_profile"),
            "evidence_hash": evidence.get("evidence_hash"),
            "evidence_path": _relative_to_runtime(evidence_path),
        })

    return records


def _load_audit_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []

    for item in get_logs(500):
        timestamp = item.get("time") or item.get("timestamp")
        records.append({
            "kind": "audit_log",
            "id": _safe_str(item.get("request_id"), _safe_str(item.get("id"))),
            "time": _safe_str(timestamp),
            "sort_time": _parse_dt(timestamp),
            "user": _safe_str(item.get("user")),
            "agent": _safe_str(item.get("agent"), "gateway"),
            "tool": _safe_str(item.get("tool")),
            "params": item.get("params") or {},
            "decision": _safe_str(item.get("decision"), "review"),
            "risk_score": item.get("risk_score") or 0,
            "reason": item.get("reason") or item.get("message") or "Gateway decision recorded.",
            "executed": bool(item.get("executed")),
            "pending_id": item.get("pending_id"),
            "record_hash": item.get("record_hash"),
        })

    return records


def _all_local_records() -> List[Dict[str, Any]]:
    records = _load_audit_records() + _load_evidence_records()
    return sorted(records, key=lambda item: item.get("sort_time") or datetime.min, reverse=True)


def _load_test_summary() -> Dict[str, Any]:
    return _read_json(TEST_SUMMARY) if TEST_SUMMARY.exists() else {}


def _count_policy_rules() -> int:
    if not CONFIG_POLICY.exists():
        return 0
    text = CONFIG_POLICY.read_text(encoding="utf-8", errors="ignore")
    return sum(1 for line in text.splitlines() if line.strip().startswith("-") or line.strip().startswith("id:"))


def _as_gateway_request(record: Dict[str, Any]) -> Dict[str, Any]:
    decision = str(record.get("decision") or "review")
    risk_score = record.get("risk_score") or 0
    return {
        "id": _safe_str(record.get("id")),
        "agent": _safe_str(record.get("agent")),
        "user": _safe_str(record.get("user")),
        "tool": _safe_str(record.get("tool")),
        "target": _target_from_params(record.get("params")),
        "intent": _safe_str(record.get("kind"), "local_runtime"),
        "risk": _risk_from_score(risk_score),
        "decision": decision if decision in {"allow", "deny", "confirm", "review"} else "review",
        "status": _status_from_decision(decision, record.get("executed")),
        "createdAt": _safe_str(record.get("time")),
        "reason": _safe_str(record.get("reason")),
        "policy": _safe_str(record.get("sandbox_profile") or record.get("record_hash") or record.get("evidence_hash"), "local-runtime"),
    }


def _as_audit_log(record: Dict[str, Any]) -> Dict[str, Any]:
    decision = str(record.get("decision") or "review")
    result = decision if decision in {"allow", "deny", "confirm", "review"} else "review"
    if record.get("kind") == "sandbox_evidence":
        action = f"Sandbox execution: {_safe_str(record.get('tool'))}"
        resource = _safe_str(record.get("evidence_path"))
        detail = (
            f"{_safe_str(record.get('sandbox_type'))} / "
            f"{_safe_str(record.get('sandbox_profile'))} / "
            f"hash={_safe_str(record.get('evidence_hash'))}"
        )
    else:
        action = f"Gateway decision: {_safe_str(record.get('tool'))}"
        resource = _target_from_params(record.get("params"))
        detail = _safe_str(record.get("reason"))

    return {
        "id": _safe_str(record.get("id")),
        "timestamp": _safe_str(record.get("time")),
        "actor": _safe_str(record.get("user")),
        "action": action,
        "resource": resource,
        "result": result,
        "detail": detail,
    }


@router.get("/overview")
def frontend_overview() -> Dict[str, Any]:
    # Authorization statistics use Gateway audit records only.
    # Sandbox Evidence is counted separately by localEvidenceRuns.
    records = _load_audit_records()
    test_summary = _load_test_summary()

    total = len(records)
    denied = sum(1 for item in records if item.get("decision") == "deny")
    confirmed = sum(1 for item in records if item.get("decision") == "confirm")
    allowed = sum(1 for item in records if item.get("decision") == "allow")

    risk_unsafe_allow_rate = float(test_summary.get("risk_unsafe_allow_rate") or 0)
    normal_false_deny_rate = float(test_summary.get("normal_false_deny_rate") or 0)
    security_score = max(0, min(100, round(100 - risk_unsafe_allow_rate * 100 - normal_false_deny_rate * 50)))

    if total and not test_summary:
        security_score = max(0, min(100, round(100 - (denied / total) * 10)))

    return {
        "totalRequests": total,
        "blockedRequests": denied,
        "confirmRequests": confirmed,
        "averageLatencyMs": round(float(test_summary.get("avg_latency_ms") or 0), 2),
        "policyHitRate": round(((allowed + denied + confirmed) / total) * 100, 2) if total else 0,
        "securityScore": security_score,
        "activePolicies": _count_policy_rules(),
        "agentsOnline": 1,
        "source": "local_runtime_files",
        "localEvidenceRuns": len(_load_evidence_records()),
        "localAuditLogs": len(_load_audit_records()),
    }


@router.get("/requests")
def frontend_requests(limit: int = 50) -> List[Dict[str, Any]]:
    return [
        _as_gateway_request(record)
        for record in _load_audit_records()[:limit]
    ]


@router.get("/audit-logs")
def frontend_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    return [
        _as_audit_log(record)
        for record in _load_audit_records()[:limit]
    ]


@router.get("/evaluations")
def frontend_evaluations() -> List[Dict[str, Any]]:
    records = _all_local_records()
    evidence_records = [item for item in records if item.get("kind") == "sandbox_evidence"]
    test_summary = _load_test_summary()

    return [
        {
            "name": "Gateway 准确率",
            "value": round(float(test_summary.get("accuracy") or 0) * 100, 2),
            "unit": "%",
            "trend": "up",
            "description": "来自 test/results/latest_summary.json。",
        },
        {
            "name": "风险阻断率",
            "value": round(float(test_summary.get("risk_block_or_confirm_rate") or 0) * 100, 2),
            "unit": "%",
            "trend": "up",
            "description": "风险样例被 confirm 或 deny 的比例。",
        },
        {
            "name": "本地沙箱运行",
            "value": len(evidence_records),
            "unit": "runs",
            "trend": "up",
            "description": "读取 runtime_workspace/native_sandbox_runs 与 sandbox_runs。",
        },
        {
            "name": "本地审计记录",
            "value": len(_load_audit_records()),
            "unit": "logs",
            "trend": "flat",
            "description": "读取 logs/audit.log。",
        },
    ]


@router.get("/policies")
def frontend_policies() -> List[Dict[str, Any]]:
    return []


@router.get("/settings")
def frontend_settings() -> List[Dict[str, Any]]:
    return [
        {
            "key": "data_source",
            "name": "前端数据源",
            "value": "local_runtime_files",
            "description": "运行证据页读取本地 audit log、sandbox evidence 和 test results。",
        }
    ]
