from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from backend.tools.tool_executor import SANDBOX_DIR, ensure_sandbox_ready


router = APIRouter(
    prefix="/showcase-report",
    tags=["Showcase Report"],
)


EVIDENCE_DIR = SANDBOX_DIR / "evidence"
REPORT_DIR = SANDBOX_DIR / "reports"


@router.get("/generate")
def generate_showcase_report():
    """
    生成展示报告。

    报告会统计：
    1. 已生成的证据包数量；
    2. 授权证据包数量；
    3. SHA256 校验通过数量；
    4. 工具调用总步数；
    5. 实际执行步数；
    6. 成功执行步数；
    7. 阻断步数；
    8. 最新证据包信息。

    系统会同时保存：
    1. Markdown 报告；
    2. JSON 摘要。
    """

    ensure_sandbox_ready()
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    evidence_files = _load_evidence_files()
    summary = _build_report_summary(evidence_files)

    created_at = datetime.now().isoformat(timespec="seconds")
    report_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    markdown = _build_markdown_report(
        created_at=created_at,
        summary=summary,
        evidence_files=evidence_files,
    )

    report_payload = {
        "project": "AgentGuard",
        "report_type": "competition_showcase_report",
        "created_at": created_at,
        "summary": summary,
        "evidence_files": evidence_files,
    }

    markdown_path = REPORT_DIR / f"showcase_report_{report_id}.md"
    json_path = REPORT_DIR / f"showcase_report_{report_id}.json"

    markdown_path.write_text(markdown, encoding="utf-8")

    json_path.write_text(
        json.dumps(report_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return {
        "message": "Showcase report generated successfully.",
        "markdown_file": str(markdown_path.relative_to(SANDBOX_DIR)),
        "json_file": str(json_path.relative_to(SANDBOX_DIR)),
        "summary": summary,
        "markdown_preview": markdown,
    }


@router.get("/latest")
def read_latest_showcase_report():
    """
    读取最新生成的 Markdown 展示报告。
    """

    ensure_sandbox_ready()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    reports = sorted(REPORT_DIR.glob("showcase_report_*.md"), reverse=True)

    if not reports:
        raise HTTPException(
            status_code=404,
            detail="No showcase report found. Please call /showcase-report/generate first.",
        )

    latest_report = reports[0]

    return {
        "message": "Latest showcase report loaded successfully.",
        "file": str(latest_report.relative_to(SANDBOX_DIR)),
        "content": latest_report.read_text(encoding="utf-8"),
    }


@router.get("/list")
def list_showcase_reports():
    """
    查看已经生成的展示报告列表。
    """

    ensure_sandbox_ready()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    reports = []

    for file_path in sorted(REPORT_DIR.glob("showcase_report_*.*"), reverse=True):
        reports.append(
            {
                "name": file_path.name,
                "relative_path": str(file_path.relative_to(SANDBOX_DIR)),
                "size": file_path.stat().st_size,
                "created_at": datetime.fromtimestamp(
                    file_path.stat().st_mtime
                ).isoformat(timespec="seconds"),
            }
        )

    return {
        "message": "Showcase reports loaded successfully.",
        "count": len(reports),
        "reports": reports,
    }


def _load_evidence_files() -> list[dict[str, Any]]:
    evidence_files = []

    for file_path in sorted(EVIDENCE_DIR.glob("*.json"), reverse=True):
        data = _read_json_safely(file_path)

        expected_hash = data.get("sha256")
        actual_hash = _recompute_evidence_hash(data)
        hash_verified = expected_hash == actual_hash

        summary = data.get("summary", {})

        evidence_files.append(
            {
                "name": file_path.name,
                "relative_path": str(file_path.relative_to(SANDBOX_DIR)),
                "size": file_path.stat().st_size,
                "created_at": data.get("created_at"),
                "finished_at": data.get("finished_at"),
                "evidence_type": data.get("evidence_type", "unknown"),
                "sha256": expected_hash,
                "sha256_recomputed": actual_hash,
                "hash_verified": hash_verified,
                "summary": {
                    "total_steps": int(summary.get("total_steps", 0) or 0),
                    "executed_steps": int(summary.get("executed_steps", 0) or 0),
                    "success_steps": int(summary.get("success_steps", 0) or 0),
                    "blocked_steps": int(summary.get("blocked_steps", 0) or 0),
                    "note": summary.get("note", ""),
                },
            }
        )

    return evidence_files


def _build_report_summary(evidence_files: list[dict[str, Any]]) -> dict[str, Any]:
    total_evidence_files = len(evidence_files)

    authorized_evidence_files = sum(
        1
        for item in evidence_files
        if item.get("evidence_type") == "gateway_authorized_execution"
    )

    runtime_evidence_files = sum(
        1
        for item in evidence_files
        if item.get("evidence_type") == "sandbox_runtime_execution"
    )

    verified_files = sum(
        1
        for item in evidence_files
        if item.get("hash_verified") is True
    )

    total_steps = sum(
        item["summary"].get("total_steps", 0)
        for item in evidence_files
    )

    executed_steps = sum(
        item["summary"].get("executed_steps", 0)
        for item in evidence_files
    )

    success_steps = sum(
        item["summary"].get("success_steps", 0)
        for item in evidence_files
    )

    blocked_steps = sum(
        item["summary"].get("blocked_steps", 0)
        for item in evidence_files
    )

    latest = evidence_files[0] if evidence_files else None

    hash_verified_rate = 0.0

    if total_evidence_files > 0:
        hash_verified_rate = round(verified_files / total_evidence_files, 4)

    block_rate = 0.0

    if total_steps > 0:
        block_rate = round(blocked_steps / total_steps, 4)

    return {
        "total_evidence_files": total_evidence_files,
        "authorized_evidence_files": authorized_evidence_files,
        "runtime_evidence_files": runtime_evidence_files,
        "hash_verified_files": verified_files,
        "hash_verified_rate": hash_verified_rate,
        "total_steps": total_steps,
        "executed_steps": executed_steps,
        "success_steps": success_steps,
        "blocked_steps": blocked_steps,
        "block_rate": block_rate,
        "latest_evidence": latest,
    }


def _build_markdown_report(
    created_at: str,
    summary: dict[str, Any],
    evidence_files: list[dict[str, Any]],
) -> str:
    latest = summary.get("latest_evidence") or {}

    lines = [
        "# AgentGuard 展示报告",
        "",
        f"生成时间：{created_at}",
        "",
        "## 1. 报告说明",
        "",
        (
            "本报告由系统自动生成，用于汇总 AgentGuard 在演示过程中产生的沙箱执行证据包、"
            "Gateway 授权证据包和 SHA256 校验结果。报告内容来自 runtime_workspace 目录下的真实运行文件，"
            "用于证明系统具备可执行、可审计、可复查的安全闭环。"
        ),
        "",
        "## 2. 总体统计",
        "",
        f"- 证据包总数：{summary['total_evidence_files']}",
        f"- Gateway 授权证据包数量：{summary['authorized_evidence_files']}",
        f"- 沙箱运行证据包数量：{summary['runtime_evidence_files']}",
        f"- SHA256 校验通过数量：{summary['hash_verified_files']}",
        f"- SHA256 校验通过率：{summary['hash_verified_rate']}",
        f"- 工具调用总步数：{summary['total_steps']}",
        f"- 实际执行步数：{summary['executed_steps']}",
        f"- 成功执行步数：{summary['success_steps']}",
        f"- 阻断步数：{summary['blocked_steps']}",
        f"- 阻断比例：{summary['block_rate']}",
        "",
        "## 3. 最新证据包",
        "",
    ]

    if latest:
        lines.extend(
            [
                f"- 文件名：{latest.get('name')}",
                f"- 证据类型：{latest.get('evidence_type')}",
                f"- 相对路径：{latest.get('relative_path')}",
                f"- SHA256：`{latest.get('sha256')}`",
                f"- 哈希校验：{'通过' if latest.get('hash_verified') else '失败'}",
                "",
            ]
        )

    else:
        lines.extend(
            [
                "当前还没有生成任何证据包。",
                "",
            ]
        )

    lines.extend(
        [
            "## 4. 证据包明细",
            "",
            "| 序号 | 文件名 | 类型 | 总步数 | 执行步数 | 成功步数 | 阻断步数 | 哈希校验 |",
            "|---:|---|---|---:|---:|---:|---:|---|",
        ]
    )

    for index, item in enumerate(evidence_files, start=1):
        item_summary = item.get("summary", {})

        lines.append(
            "| "
            f"{index} | "
            f"{item.get('name')} | "
            f"{item.get('evidence_type')} | "
            f"{item_summary.get('total_steps', 0)} | "
            f"{item_summary.get('executed_steps', 0)} | "
            f"{item_summary.get('success_steps', 0)} | "
            f"{item_summary.get('blocked_steps', 0)} | "
            f"{'通过' if item.get('hash_verified') else '失败'} |"
        )

    lines.extend(
        [
            "",
            "## 5. 展示结论",
            "",
            (
                "从当前证据包统计可以看出，系统已经形成了“工具请求—Gateway 授权—沙箱执行—证据固化”的闭环。"
                "其中授权证据包用于证明工具调用并非绕过网关直接执行，沙箱运行证据包用于证明文件、邮件、数据库和命令"
                "操作确实在受控环境中产生了可复查痕迹，SHA256 校验用于证明证据包内容可被后续复核。"
            ),
            "",
        ]
    )

    return "\n".join(lines)


def _recompute_evidence_hash(data: dict[str, Any]) -> str:
    data_without_hash = dict(data)
    data_without_hash.pop("sha256", None)

    return _hash_json(data_without_hash)


def _hash_json(data: dict[str, Any]) -> str:
    raw = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _read_json_safely(file_path: Path) -> dict[str, Any]:
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))

    except json.JSONDecodeError:
        return {
            "error": "Invalid JSON evidence file.",
        }