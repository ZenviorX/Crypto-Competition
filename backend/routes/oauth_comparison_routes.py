from __future__ import annotations

from fastapi import APIRouter

from backend.research.oauth_comparison import (
    OAuthComparisonRequest,
    OAuthComparisonResponse,
    run_oauth_comparison,
)

router = APIRouter(
    prefix="/research",
    tags=["Research Comparison"],
)


@router.get("/oauth-comparison/health")
def oauth_comparison_health():
    return {
        "success": True,
        "message": "OAuth-only vs AgentGuard comparison is ready.",
        "default_scenario": "scope_enough_but_sandbox_denies",
    }


@router.post(
    "/oauth-comparison/run",
    response_model=OAuthComparisonResponse,
)
def run_oauth_comparison_api(
    request: OAuthComparisonRequest,
) -> OAuthComparisonResponse:
    return run_oauth_comparison(request)
