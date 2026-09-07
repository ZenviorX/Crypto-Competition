from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse


router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[2]
EXPERIMENTS_DIR = BASE_DIR / "experiments"


def read_report_file(filename: str) -> PlainTextResponse:
    report_path = EXPERIMENTS_DIR / filename

    if not report_path.exists():
        return PlainTextResponse(
            content=f"Report file not found: {report_path}",
            status_code=404,
        )

    return PlainTextResponse(
        content=report_path.read_text(encoding="utf-8"),
        media_type="text/markdown; charset=utf-8",
    )


@router.get("/reports/gateway-benchmark")
def gateway_benchmark_report():
    """
    返回网关安全评测 Markdown 报告。
    """
    return read_report_file("gateway_benchmark_report.md")


@router.get("/reports/attack-chain")
def attack_chain_report():
    """
    返回多步攻击链演示 Markdown 报告。
    """
    return read_report_file("attack_chain_demo_report.md")

@router.get("/reports/attack-chain-benchmark")
def attack_chain_benchmark_report():
    """
    返回多步攻击链批量评测 Markdown 报告。
    """
    return read_report_file("attack_chain_benchmark_report.md")

@router.get("/reports/comparison-benchmark")
def comparison_benchmark_report():
    """
    返回安全对比实验 Markdown 报告。
    """
    return read_report_file("comparison_benchmark_report.md")

