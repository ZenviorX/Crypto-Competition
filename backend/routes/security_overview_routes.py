import ast
import json
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter
from collections import Counter

from fastapi import HTTPException, Request

from backend.audit.decision_snapshot import (
    verify_decision_snapshot,
)
from backend.audit.trusted_audit_store import (
    get_trusted_audit_events,
    verify_trusted_audit_chain,
)
from backend.evidence.evidence_bundle import (
    build_task_evidence_bundle,
    verify_task_evidence_bundle,
)
from backend.revocation.revocation_store import (
    get_revocation,
    list_revocations,
)
from backend.routes.trusted_audit_routes import (
    _authenticate,
    _authorize_task_audit_read,
    _no_store_json,
)
from backend.task_session.task_store import (
    connect as task_store_connect,
    load_session,
)


router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[2]
TESTS_DIR = BASE_DIR / "tests"
SECURITY_CASES_DIR = BASE_DIR / "security_cases"
EXPERIMENTS_DIR = BASE_DIR / "experiments"
WORKFLOW_FILE = BASE_DIR / ".github" / "workflows" / "ci.yml"


def count_json_array(path: Path) -> int:
    if not path.exists():
        return 0

    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return 0

    if isinstance(data, list):
        return len(data)

    return 0


def count_unittest_cases() -> int:
    """
    静态统计 tests 目录下 test_*.py 文件中的 test_ 方法数量。
    这个数字用于展示项目测试规模，不替代真实 unittest 执行结果。
    """
    if not TESTS_DIR.exists():
        return 0

    total = 0

    for file_path in TESTS_DIR.glob("test_*.py"):
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                total += 1

    return total


def file_status(path: Path) -> Dict[str, Any]:
    return {
        "exists": path.exists(),
        "path": str(path.relative_to(BASE_DIR)) if path.exists() else str(path),
    }


@router.get("/security/overview")
def security_overview():
    """
    返回当前系统安全能力概览。
    """
    gateway_cases_file = SECURITY_CASES_DIR / "gateway_cases.json"
    attack_chain_cases_file = SECURITY_CASES_DIR / "attack_chain_cases.json"

    gateway_report_file = EXPERIMENTS_DIR / "gateway_benchmark_report.md"
    gateway_csv_file = EXPERIMENTS_DIR / "gateway_benchmark_results.csv"

    attack_chain_demo_report_file = EXPERIMENTS_DIR / "attack_chain_demo_report.md"
    attack_chain_demo_json_file = EXPERIMENTS_DIR / "attack_chain_demo_result.json"

    attack_chain_benchmark_report_file = EXPERIMENTS_DIR / "attack_chain_benchmark_report.md"
    attack_chain_benchmark_csv_file = EXPERIMENTS_DIR / "attack_chain_benchmark_results.csv"
    comparison_report_file = EXPERIMENTS_DIR / "comparison_benchmark_report.md"
    comparison_csv_file = EXPERIMENTS_DIR / "comparison_benchmark_results.csv"

    gateway_case_count = count_json_array(gateway_cases_file)
    attack_chain_case_count = count_json_array(attack_chain_cases_file)
    unit_test_count = count_unittest_cases()

    features = [
        {
            "key": "explainable_risk",
            "name": "可解释风险评估",
            "enabled": True,
            "description": "Gateway 返回 risk_level 与 explanations，支持结构化说明风险来源。",
        },
        {
            "key": "task_contract",
            "name": "任务授权合约",
            "enabled": True,
            "description": "限制 Agent 在当前任务中的工具、资源和目标对象访问范围。",
        },
        {
            "key": "capability_contract",
            "name": "Capability Contract 能力约束",
            "enabled": True,
            "description": "支持更细粒度的工具能力、步骤边界和风险预算约束。",
        },
        {
            "key": "audit_hash_chain",
            "name": "审计日志哈希链",
            "enabled": True,
            "description": "审计日志包含 prev_hash 与 record_hash，可检测篡改、删除、插入或重排。",
        },
        {
            "key": "attack_chain_detector",
            "name": "多步攻击链检测",
            "enabled": True,
            "description": "识别外部内容读取、提示注入、敏感资源访问、外部发送和高危命令执行等链式风险。",
        },
        {
            "key": "attack_chain_runtime",
            "name": "运行时攻击链检测",
            "enabled": True,
            "description": "攻击链检测已接入 /attack-chain/check 接口，可参与真实调用流程的最终决策。",
        },
        {
            "key": "gateway_benchmark",
            "name": "网关安全评测",
            "enabled": gateway_case_count > 0,
            "description": "基于 security_cases/gateway_cases.json 自动评测网关安全策略。",
        },
        {
            "key": "attack_chain_benchmark",
            "name": "攻击链批量评测",
            "enabled": attack_chain_case_count > 0,
            "description": "基于 security_cases/attack_chain_cases.json 自动评测攻击链检测能力。",
        },
        {
            "key": "comparison_benchmark",
            "name": "安全对比实验",
            "enabled": comparison_report_file.exists(),
            "description": "对比无防护、单步网关、网关+攻击链检测三种模式的安全效果。",
        },
        {
            "key": "ci",
            "name": "GitHub Actions 自动测试",
            "enabled": WORKFLOW_FILE.exists(),
            "description": "推送后自动运行单元测试、安全评测和攻击链演示。",
        },
    ]

    return {
        "project": "Agent-Authorization",
        "title": "面向 AI Agent 工具调用的授权与安全防护系统",
        "summary": "系统提供工具调用前置授权、动态风险评分、可解释决策、审计防篡改、多步攻击链检测和可复现安全评测能力。",
        "metrics": {
            "unit_test_cases": unit_test_count,
            "gateway_security_cases": gateway_case_count,
            "attack_chain_cases": attack_chain_case_count,
            "total_security_cases": gateway_case_count + attack_chain_case_count,
        },
        "reports": {
            "gateway_benchmark_report": file_status(gateway_report_file),
            "gateway_benchmark_results": file_status(gateway_csv_file),
            "attack_chain_demo_report": file_status(attack_chain_demo_report_file),
            "attack_chain_demo_result": file_status(attack_chain_demo_json_file),
            "attack_chain_benchmark_report": file_status(attack_chain_benchmark_report_file),
            "attack_chain_benchmark_results": file_status(attack_chain_benchmark_csv_file),
            "comparison_benchmark_report": file_status(comparison_report_file),
            "comparison_benchmark_results": file_status(comparison_csv_file),
        },
        "automation": {
            "github_actions_configured": WORKFLOW_FILE.exists(),
            "workflow_file": str(WORKFLOW_FILE.relative_to(BASE_DIR)) if WORKFLOW_FILE.exists() else None,
        },
        "features": features,
    }


def _approval_status_counts(
    *,
    task_handle: str,
) -> Dict[str, int]:
    connection = task_store_connect()

    try:
        rows = connection.execute(
            """
            SELECT
                status,
                COUNT(*) AS status_count
            FROM trusted_approval_tickets
            WHERE task_handle = ?
            GROUP BY status
            ORDER BY status
            """,
            (task_handle,),
        ).fetchall()

    finally:
        connection.close()

    counts = {
        "pending": 0,
        "approved": 0,
        "denied": 0,
        "consumed": 0,
    }

    for row in rows:
        status = str(
            row["status"]
        )

        counts[status] = int(
            row["status_count"]
        )

    counts["total"] = sum(
        value
        for key, value in counts.items()
        if key != "total"
    )

    return counts


def _runtime_security_summary(
    runtime_state: Any,
) -> Dict[str, Any]:
    if not isinstance(
        runtime_state,
        dict,
    ):
        return {
            "available": False,
            "current_step": 0,
            "used_risk": 0,
            "final_decision": "",
            "step_count": 0,
            "executed_step_count": 0,
            "blocked_step_count": 0,
            "pending_confirmation_count": 0,
            "decision_counts": {},
        }

    steps = [
        dict(step)
        for step in (
            runtime_state.get("steps")
            or []
        )
        if isinstance(
            step,
            dict,
        )
    ]

    decision_counts = Counter(
        str(
            step.get("decision")
            or ""
        )
        for step in steps
        if str(
            step.get("decision")
            or ""
        )
    )

    pending_steps = (
        runtime_state.get(
            "pending_confirm_steps"
        )
        or []
    )

    return {
        "available": True,
        "current_step": int(
            runtime_state.get(
                "current_step",
                0,
            )
            or 0
        ),
        "used_risk": int(
            runtime_state.get(
                "used_risk",
                0,
            )
            or 0
        ),
        "final_decision": str(
            runtime_state.get(
                "final_decision"
            )
            or ""
        ),
        "step_count": len(steps),
        "executed_step_count": sum(
            1
            for step in steps
            if bool(
                step.get("executed")
            )
        ),
        "blocked_step_count": sum(
            1
            for step in steps
            if bool(
                step.get("blocked")
            )
            or str(
                step.get("decision")
                or ""
            )
            == "deny"
        ),
        "pending_confirmation_count": len(
            pending_steps
        ),
        "decision_counts": dict(
            sorted(
                decision_counts.items()
            )
        ),
    }


def _audit_event_summary(
    events: List[
        Dict[str, Any]
    ],
) -> Dict[str, Any]:
    event_type_counts = Counter(
        str(
            event.get("event_type")
            or ""
        )
        for event in events
        if str(
            event.get("event_type")
            or ""
        )
    )

    decision_counts: Counter = (
        Counter()
    )

    for event in events:
        payload = event.get(
            "payload"
        )

        if not isinstance(
            payload,
            dict,
        ):
            continue

        decision = str(
            payload.get("decision")
            or ""
        )

        if decision:
            decision_counts[
                decision
            ] += 1

    return {
        "event_count": len(events),
        "event_type_counts": dict(
            sorted(
                event_type_counts.items()
            )
        ),
        "decision_counts": dict(
            sorted(
                decision_counts.items()
            )
        ),
        "first_sequence": (
            int(
                events[0]["sequence"]
            )
            if events
            else None
        ),
        "last_sequence": (
            int(
                events[-1]["sequence"]
            )
            if events
            else None
        ),
    }


def _decision_snapshot_summary(
    events: List[
        Dict[str, Any]
    ],
) -> Dict[str, Any]:
    results = []

    for event in events:
        payload = event.get(
            "payload"
        )

        if not isinstance(
            payload,
            dict,
        ):
            continue

        snapshot = payload.get(
            "decision_snapshot"
        )

        if not isinstance(
            snapshot,
            dict,
        ):
            continue

        verification = (
            verify_decision_snapshot(
                snapshot,
                compare_current_policy=True,
            )
        )

        results.append(
            {
                "sequence": int(
                    event["sequence"]
                ),
                "valid": bool(
                    verification.get(
                        "valid"
                    )
                ),
                "current_policy_matches": (
                    verification.get(
                        "current_policy_matches"
                    )
                ),
                "snapshot_hash_valid": bool(
                    verification.get(
                        "snapshot_hash_valid"
                    )
                ),
                "contract_hash_valid": bool(
                    verification.get(
                        "contract_hash_valid"
                    )
                ),
                "decision_hash_valid": bool(
                    verification.get(
                        "decision_hash_valid"
                    )
                ),
            }
        )

    valid_count = sum(
        1
        for result in results
        if result["valid"]
    )

    policy_changed_count = sum(
        1
        for result in results
        if (
            result[
                "current_policy_matches"
            ]
            is False
        )
    )

    return {
        "snapshot_count": len(
            results
        ),
        "valid_snapshot_count": (
            valid_count
        ),
        "invalid_snapshot_count": (
            len(results)
            - valid_count
        ),
        "policy_changed_count": (
            policy_changed_count
        ),
        "all_snapshots_valid": all(
            result["valid"]
            for result in results
        ),
        "results": results,
    }


def _revocation_summary(
    *,
    task_handle: str,
    task_owner: str,
) -> Dict[str, Any]:
    records = list_revocations(
        task_handle=task_handle,
        limit=1000,
    )

    type_counts = Counter(
        str(
            record.get(
                "subject_type"
            )
            or ""
        )
        for record in records
        if str(
            record.get(
                "subject_type"
            )
            or ""
        )
    )

    task_revocation = get_revocation(
        subject_type="task",
        subject_value=task_handle,
        expected_task_handle=(
            task_handle
        ),
        expected_user=(
            task_owner
        ),
    )

    return {
        "task_revoked": (
            task_revocation
            is not None
        ),
        "revocation_count": len(
            records
        ),
        "type_counts": dict(
            sorted(
                type_counts.items()
            )
        ),
        "latest_revocation": (
            {
                "revocation_id": int(
                    records[-1][
                        "revocation_id"
                    ]
                ),
                "subject_type": str(
                    records[-1][
                        "subject_type"
                    ]
                ),
                "reason": str(
                    records[-1][
                        "reason"
                    ]
                ),
                "revoked_by": str(
                    records[-1][
                        "revoked_by"
                    ]
                ),
                "revoked_at": str(
                    records[-1][
                        "revoked_at"
                    ]
                ),
            }
            if records
            else None
        ),
    }


def _evidence_security_summary(
    *,
    task_handle: str,
    task_owner: str,
    task_exists: bool,
) -> Dict[str, Any]:
    if not task_exists:
        return {
            "available": False,
            "valid": None,
            "reason": (
                "Live trusted task session "
                "is unavailable."
            ),
        }

    try:
        bundle = (
            build_task_evidence_bundle(
                task_handle=task_handle,
                expected_user=task_owner,
            )
        )

        verification = (
            verify_task_evidence_bundle(
                bundle
            )
        )

        return {
            "available": True,
            "valid": bool(
                verification.get(
                    "valid"
                )
            ),
            "bundle_version": int(
                bundle.get(
                    "bundle_version",
                    0,
                )
                or 0
            ),
            "bundle_hash": str(
                bundle.get(
                    "bundle_hash"
                )
                or ""
            ),
            "task_event_count": int(
                bundle.get(
                    "task_event_count",
                    0,
                )
                or 0
            ),
            "decision_snapshot_count": int(
                bundle.get(
                    "decision_snapshot_count",
                    0,
                )
                or 0
            ),
            "revocation_count": int(
                bundle.get(
                    "revocation_count",
                    0,
                )
                or 0
            ),
            "verification": (
                verification
            ),
        }

    except Exception as exc:
        return {
            "available": False,
            "valid": False,
            "reason": (
                "Evidence package generation "
                "failed."
            ),
            "error_type": (
                type(exc).__name__
            ),
        }


def _overall_security_status(
    *,
    task_revoked: bool,
    chain_valid: bool,
    snapshots_valid: bool,
    evidence_valid: Any,
    pending_approvals: int,
) -> Dict[str, Any]:
    score = 100
    findings = []

    if not chain_valid:
        score -= 45
        findings.append(
            "Trusted audit chain "
            "verification failed."
        )

    if not snapshots_valid:
        score -= 30
        findings.append(
            "One or more authorization "
            "decision snapshots are invalid."
        )

    if evidence_valid is False:
        score -= 30
        findings.append(
            "Task evidence package "
            "verification failed."
        )

    if task_revoked:
        score -= 20
        findings.append(
            "The trusted task has "
            "been revoked."
        )

    if pending_approvals > 0:
        score -= min(
            10,
            pending_approvals * 2,
        )
        findings.append(
            (
                f"{pending_approvals} approval "
                "request(s) are pending."
            )
        )

    score = max(
        0,
        min(100, score),
    )

    if (
        not chain_valid
        or not snapshots_valid
        or evidence_valid is False
    ):
        status = "critical"

    elif task_revoked:
        status = "revoked"

    elif pending_approvals > 0:
        status = "attention"

    else:
        status = "healthy"

    return {
        "status": status,
        "score": score,
        "findings": findings,
    }


@router.get(
    "/security/overview/"
    "tasks/{task_handle}"
)
def task_security_overview(
    task_handle: str,
    request: Request,
):
    """
    Return a consolidated trusted-security view for
    one task.

    The response contains no raw approval ticket,
    capability token or external secret.
    """
    normalized_handle = str(
        task_handle
    ).strip()

    if not normalized_handle:
        raise HTTPException(
            status_code=400,
            detail=(
                "task_handle is required."
            ),
            headers={
                "Cache-Control": (
                    "no-store"
                ),
            },
        )

    principal = _authenticate(
        request
    )

    access = (
        _authorize_task_audit_read(
            principal=principal,
            task_handle=(
                normalized_handle
            ),
        )
    )

    task_exists = bool(
        access.get(
            "task_exists"
        )
    )

    task_owner = str(
        access.get(
            "task_owner"
        )
        or ""
    )

    session = None

    if task_exists:
        session, version = load_session(
            task_handle=(
                normalized_handle
            ),
            expected_user=(
                task_owner
            ),
        )

        task_version = int(
            version
        )

        runtime_summary = (
            _runtime_security_summary(
                getattr(
                    session,
                    "runtime_state",
                    None,
                )
            )
        )

        contract = dict(
            getattr(
                session,
                "contract",
                {},
            )
            or {}
        )

    else:
        task_version = None
        runtime_summary = (
            _runtime_security_summary(
                None
            )
        )
        contract = {}

    events = (
        get_trusted_audit_events(
            task_handle=(
                normalized_handle
            ),
            limit=1000,
        )
    )

    audit_summary = (
        _audit_event_summary(
            events
        )
    )

    chain_integrity = (
        verify_trusted_audit_chain()
    )

    snapshot_summary = (
        _decision_snapshot_summary(
            events
        )
    )

    approval_counts = (
        _approval_status_counts(
            task_handle=(
                normalized_handle
            )
        )
    )

    revocation_summary = (
        _revocation_summary(
            task_handle=(
                normalized_handle
            ),
            task_owner=task_owner,
        )
    )

    evidence_summary = (
        _evidence_security_summary(
            task_handle=(
                normalized_handle
            ),
            task_owner=task_owner,
            task_exists=task_exists,
        )
    )

    overall = (
        _overall_security_status(
            task_revoked=bool(
                revocation_summary[
                    "task_revoked"
                ]
            ),
            chain_valid=bool(
                chain_integrity.get(
                    "valid"
                )
            ),
            snapshots_valid=bool(
                snapshot_summary[
                    "all_snapshots_valid"
                ]
            ),
            evidence_valid=(
                evidence_summary.get(
                    "valid"
                )
            ),
            pending_approvals=int(
                approval_counts.get(
                    "pending",
                    0,
                )
            ),
        )
    )

    return _no_store_json(
        {
            "message": (
                "Trusted task security "
                "overview loaded."
            ),
            "task_handle": (
                normalized_handle
            ),
            "requested_by": str(
                principal.get("sub")
                or ""
            ),
            "access": access,
            "overall": overall,
            "task": {
                "exists": (
                    task_exists
                ),
                "owner": task_owner,
                "version": (
                    task_version
                ),
                "contract_present": bool(
                    contract
                ),
                "contract_version": (
                    contract.get(
                        "version"
                    )
                ),
            },
            "runtime": (
                runtime_summary
            ),
            "approvals": (
                approval_counts
            ),
            "revocations": (
                revocation_summary
            ),
            "audit": {
                **audit_summary,
                "chain_integrity": (
                    chain_integrity
                ),
            },
            "decision_snapshots": (
                snapshot_summary
            ),
            "evidence": (
                evidence_summary
            ),
            "acceptance_checks": {
                "trusted_session": (
                    task_exists
                ),
                "audit_chain_valid": bool(
                    chain_integrity.get(
                        "valid"
                    )
                ),
                "decision_snapshots_valid": bool(
                    snapshot_summary[
                        "all_snapshots_valid"
                    ]
                ),
                "evidence_valid": (
                    evidence_summary.get(
                        "valid"
                    )
                ),
                "revocation_registry_available": (
                    True
                ),
            },
        }
    )
