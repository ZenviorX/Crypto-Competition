from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, List


ZERO_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """
    生成稳定 JSON 字符串。

    规则：
    - key 排序；
    - 去掉多余空格；
    - 保留中文；
    - default=str 避免不可序列化对象导致失败。
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(data: Any) -> str:
    return sha256_text(canonical_json(data))


def strip_integrity(report: Dict[str, Any]) -> Dict[str, Any]:
    clean = copy.deepcopy(report)
    clean.pop("integrity", None)
    return clean


def _step_integrity_record(step: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "step_id": step.get("step_id"),
        "tool": step.get("tool"),
        "decision": step.get("decision"),
        "risk_score": step.get("risk_score"),
        "executed": step.get("executed"),
        "blocked": step.get("blocked"),
        "requires_confirmation": step.get("requires_confirmation"),
        "input_labels": step.get("input_labels", []),
        "output_labels": step.get("output_labels", []),
        "hash": sha256_json(step),
    }


def build_integrity_manifest(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    为 Benchmark 报告构造完整性清单。

    哈希链规则：
    chain_hash_i = SHA256(previous_hash + case_id + case_hash)
    root_hash = 最后一个 case 的 chain_hash
    """
    clean_report = strip_integrity(report)
    summary = clean_report.get("summary", {})
    cases = clean_report.get("cases", [])

    if not isinstance(summary, dict):
        summary = {}

    if not isinstance(cases, list):
        cases = []

    previous_hash = ZERO_HASH
    case_chain: List[Dict[str, Any]] = []

    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            case = {"value": str(case)}

        steps = case.get("steps", [])
        if not isinstance(steps, list):
            steps = []

        step_hashes = [
            _step_integrity_record(step)
            for step in steps
            if isinstance(step, dict)
        ]

        case_hash = sha256_json(case)
        chain_input = {
            "index": index,
            "case_id": case.get("id"),
            "previous_hash": previous_hash,
            "case_hash": case_hash,
        }
        chain_hash = sha256_json(chain_input)

        case_chain.append(
            {
                "index": index,
                "case_id": case.get("id"),
                "category": case.get("category"),
                "passed": case.get("passed"),
                "final_decision": case.get("final_decision"),
                "previous_hash": previous_hash,
                "case_hash": case_hash,
                "chain_hash": chain_hash,
                "step_hashes": step_hashes,
            }
        )

        previous_hash = chain_hash

    return {
        "version": "1.0",
        "algorithm": "sha256",
        "scope": "llm_runtime_benchmark_report",
        "generated_at": summary.get("generated_at"),
        "total_cases": len(cases),
        "report_hash_without_integrity": sha256_json(clean_report),
        "root_hash": previous_hash,
        "case_chain": case_chain,
    }


def attach_integrity_manifest(report: Dict[str, Any]) -> Dict[str, Any]:
    sealed = strip_integrity(report)
    sealed["integrity"] = build_integrity_manifest(sealed)
    return sealed


def verify_report_integrity(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    验证 Benchmark 报告是否被篡改。
    """
    if not isinstance(report, dict):
        return {
            "valid": False,
            "reason": ["report is not a dict"],
        }

    manifest = report.get("integrity")

    if not isinstance(manifest, dict):
        return {
            "valid": False,
            "reason": ["missing integrity manifest"],
        }

    expected = build_integrity_manifest(report)

    checks = [
        (
            "algorithm",
            manifest.get("algorithm"),
            expected.get("algorithm"),
        ),
        (
            "total_cases",
            manifest.get("total_cases"),
            expected.get("total_cases"),
        ),
        (
            "report_hash_without_integrity",
            manifest.get("report_hash_without_integrity"),
            expected.get("report_hash_without_integrity"),
        ),
        (
            "root_hash",
            manifest.get("root_hash"),
            expected.get("root_hash"),
        ),
    ]

    reasons: List[str] = []
    valid = True

    for name, actual, recomputed in checks:
        if actual != recomputed:
            valid = False
            reasons.append(
                f"{name} mismatch: stored={actual}, recomputed={recomputed}"
            )

    stored_chain = manifest.get("case_chain", [])
    expected_chain = expected.get("case_chain", [])

    if not isinstance(stored_chain, list):
        valid = False
        reasons.append("case_chain is not a list")
        stored_chain = []

    if len(stored_chain) != len(expected_chain):
        valid = False
        reasons.append(
            f"case_chain length mismatch: stored={len(stored_chain)}, recomputed={len(expected_chain)}"
        )

    for index, expected_case in enumerate(expected_chain):
        if index >= len(stored_chain):
            break

        stored_case = stored_chain[index]

        for key in ["case_id", "case_hash", "previous_hash", "chain_hash"]:
            if stored_case.get(key) != expected_case.get(key):
                valid = False
                reasons.append(
                    f"case[{index + 1}] {key} mismatch: "
                    f"stored={stored_case.get(key)}, recomputed={expected_case.get(key)}"
                )

    if valid:
        reasons.append("integrity manifest verified successfully")

    return {
        "valid": valid,
        "reason": reasons,
        "algorithm": expected.get("algorithm"),
        "root_hash": expected.get("root_hash"),
        "report_hash_without_integrity": expected.get("report_hash_without_integrity"),
        "total_cases": expected.get("total_cases"),
    }
