from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "tests"

MINIMUM_TEST_FILE_COUNT = 20


def discover_test_files() -> list[Path]:
    if not TEST_ROOT.exists():
        raise RuntimeError(
            "tests directory does not exist."
        )

    return sorted(
        path
        for path in TEST_ROOT.rglob(
            "test_*.py"
        )
        if "__pycache__"
        not in path.parts
    )


def build_test_environment(
) -> dict[str, str]:
    environment = dict(os.environ)

    environment["PYTHONUTF8"] = "1"
    environment["PYTHONHASHSEED"] = "0"

    # 自动化回归统一在 Demo 暴露模式下运行。
    # competition 安全就绪逻辑由专门单元测试覆盖，
    # 避免开发机器遗留环境变量干扰全部测试。
    environment["AGENTGUARD_MODE"] = (
        "demo"
    )

    environment.pop(
        "AGENTGUARD_ENFORCE_STARTUP_SECURITY",
        None,
    )

    environment.pop(
        "AGENTGUARD_REQUIRE_EVIDENCE_BUNDLE_SIGNATURE",
        None,
    )

    return environment



def main() -> int:
    test_files = discover_test_files()

    if (
        len(test_files)
        < MINIMUM_TEST_FILE_COUNT
    ):
        print(
            "ERROR: discovered too few "
            "backend test files."
        )

        print(
            "discovered:",
            len(test_files),
        )

        return 2

    print(
        "=== AgentGuard Complete "
        "Backend Regression ==="
    )

    print(
        "test_files:",
        len(test_files),
    )

    for path in test_files:
        print(
            "-",
            path.relative_to(ROOT),
        )

    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests",
        "-q",
        "--strict-markers",
        "--maxfail=1",
        "--durations=10",
    ]

    return subprocess.call(
        command,
        cwd=ROOT,
        env=build_test_environment(),
    )


if __name__ == "__main__":
    raise SystemExit(main())