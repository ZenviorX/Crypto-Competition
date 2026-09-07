from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from backend.runtime.runtime_monitor import build_runtime_security_graph
from backend.runtime.task_state import RuntimeTaskState


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE_DIR = PROJECT_ROOT / "runtime_workspace" / "evidence"


def _canonical_json(data: Dict[str, Any]) -> str:
    """
    生成稳定 JSON 文本，用于计算证据包完整性哈希。
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_runtime_evidence_package(state: RuntimeTaskState) -> Dict[str, Any]:
    """
    构建 Runtime Evidence Package。

    用于把一次 Agent 多步工具调用过程固化为可审计材料：
    - Capability Contract；
    - 每一步工具调用记录；
    - 跨步骤数据流边；
    - Runtime Security Graph；
    - 高风险数据流；
    - 最终决策与风险预算；
    - integrity_hash 完整性校验。

    注意：
    integrity_hash 计算时不包含自身字段，避免循环依赖。
    """
    security_graph = build_runtime_security_graph(state)

    steps = [
        step.model_dump()
        for step in state.steps
    ]

    payload: Dict[str, Any] = {
        "evidence_version": "1.0",
        "evidence_type": "runtime_security_evidence_package",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "task": {
            "task_id": state.task_id,
            "user": state.user,
            "original_task": state.original_task,
            "final_decision": state.final_decision,
            "is_blocked": state.is_blocked,
            "used_risk": state.used_risk,
            "risk_budget": state.contract.risk_budget,
        },
        "contract": state.contract.model_dump(),
        "runtime": {
            "current_step": state.current_step,
            "step_count": len(state.steps),
            "pending_confirm_steps": state.pending_confirm_steps,
            "violations": state.violations,
        },
        "steps": steps,
        "data_lineage_edges": state.data_lineage_edges,
        "security_graph": security_graph,
        "attack_chain_state": state.attack_chain_state,
        "summary": {
            "step_count": len(state.steps),
            "data_lineage_edge_count": len(state.data_lineage_edges),
            "high_risk_flow_count": security_graph.get("summary", {}).get(
                "high_risk_flow_count",
                0,
            ),
            "graph_risk_level": security_graph.get("graph_risk_level"),
            "blocked_step_count": security_graph.get("summary", {}).get(
                "blocked_step_count",
                0,
            ),
            "confirm_step_count": security_graph.get("summary", {}).get(
                "confirm_step_count",
                0,
            ),
        },
    }

    integrity_payload = dict(payload)
    canonical_text = _canonical_json(integrity_payload)

    payload["integrity"] = {
        "hash_algorithm": "sha256",
        "hash_scope": "runtime_evidence_package_without_integrity_field",
        "sha256": _sha256_text(canonical_text),
    }

    payload["evidence_id"] = (
        f"runtime-evidence-{state.task_id}-"
        f"{payload['integrity']['sha256'][:12]}"
    )

    return payload


def verify_runtime_evidence_package(package: Dict[str, Any]) -> bool:
    """
    校验证据包完整性哈希。

    如果证据包核心内容被修改，校验会失败。
    """
    integrity = package.get("integrity", {})
    expected_hash = integrity.get("sha256")

    if not expected_hash:
        return False

    copied = dict(package)
    copied.pop("integrity", None)
    copied.pop("evidence_id", None)

    actual_hash = _sha256_text(_canonical_json(copied))

    return actual_hash == expected_hash


def save_runtime_evidence_package(
    state: RuntimeTaskState,
    evidence_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    生成并保存 Runtime Evidence Package。

    默认保存到：
        runtime_workspace/evidence/
    """
    evidence_dir = evidence_dir or DEFAULT_EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)

    package = build_runtime_evidence_package(state)
    evidence_id = package["evidence_id"]

    output_path = evidence_dir / f"{evidence_id}.json"

    output_path.write_text(
        json.dumps(package, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return {
        "saved": True,
        "path": str(output_path),
        "evidence_id": evidence_id,
        "package": package,
    }
