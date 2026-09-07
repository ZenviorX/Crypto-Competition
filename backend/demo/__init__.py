"""
Demo-only components.

This package contains FakeAgent and demonstration orchestration code.
It is intentionally separated from the core gateway implementation.

Core project modules should not depend on this package.
Only demo routes should import from backend.demo.
"""

from backend.demo.fake_agent import FakeAgent
from backend.demo.demo_service import (
    list_demo_cases,
    run_fake_agent_plan,
    run_fake_agent_demo,
    run_demo_case,
)

__all__ = [
    "FakeAgent",
    "list_demo_cases",
    "run_fake_agent_plan",
    "run_fake_agent_demo",
    "run_demo_case",
]
