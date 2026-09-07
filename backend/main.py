from pathlib import Path
import hmac
import os
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from backend.routes.approval_routes import router as approval_router
from backend.routes.audit_routes import router as audit_router
from backend.routes.gateway_routes import router as gateway_router
from backend.routes.task_contract_routes import router as task_contract_router
from backend.routes.report_routes import router as report_router
from backend.routes.capability_routes import router as capability_router
from backend.routes.runtime_routes import router as runtime_router
from backend.routes.attack_chain_routes import router as attack_chain_router
from backend.routes.security_overview_routes import router as security_overview_router
from backend.routes.demo_routes import router as demo_router
from backend.routes.sandbox_evidence_routes import router as sandbox_evidence_router
from backend.routes.showcase_report_routes import router as showcase_report_router
from backend.routes.agent_runtime_routes import router as agent_runtime_router
from backend.routes.tool_proxy_routes import router as tool_proxy_router
from backend.routes.external_agent_routes import router as external_agent_router
from backend.routes.oauth_comparison_routes import router as oauth_comparison_router
from backend.routes.research_eval_routes import router as research_eval_router
from backend.routes.research_strategy_routes import router as research_strategy_router
from backend.routes.test_results_routes import router as test_results_router
from backend.routes.docker_sandbox_routes import router as docker_sandbox_router
from backend.routes.native_sandbox_routes import router as native_sandbox_router
from backend.routes.frontend_data_routes import router as frontend_data_router
from backend.routes.two_phase_tool_proxy_routes import router as two_phase_tool_proxy_router
from backend.routes.capability_token_routes import router as capability_token_router
from backend.routes.llm_tool_call_routes import router as llm_tool_call_router
from backend.routes.mcp_routes import router as mcp_router
from backend.routes.trusted_audit_routes import router as trusted_audit_router
from backend.routes.evidence_bundle_routes import router as evidence_bundle_router

from backend.mcp.tool_registry import (
    tool_manifest_digest,
)


SUPPORTED_AGENTGUARD_MODES = {
    "demo",
    "competition",
}


def _resolve_agentguard_mode() -> str:
    """
    Resolve the current AgentGuard exposure mode.

    demo:
        Keep legacy development and demonstration APIs.

    competition:
        Expose the OAuth-protected MCP execution path and
        read-only evidence/reporting APIs. Legacy direct
        execution routes are not registered.

    Invalid values fail closed to competition mode.
    """

    configured = str(
        os.getenv(
            "AGENTGUARD_MODE",
            "demo",
        )
        or "demo"
    ).strip().lower()

    if configured in SUPPORTED_AGENTGUARD_MODES:
        return configured

    return "competition"


AGENTGUARD_MODE = _resolve_agentguard_mode()
COMPETITION_MODE = (
    AGENTGUARD_MODE == "competition"
)

COMPETITION_DISABLED_ROUTE_PREFIXES = (
    "/gateway",
    "/agent/call",
    "/approval",
    "/tool-proxy",
    "/external-agent",
    "/sandbox-native",
    "/sandbox-docker",
    "/demo",
    "/llm",
)


STARTUP_SECURITY_ENFORCEMENT_ENV = (
    "AGENTGUARD_ENFORCE_STARTUP_SECURITY"
)


def _environment_enabled(
    environment: Mapping[str, str],
    name: str,
) -> bool:
    return str(
        environment.get(name, "")
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _is_https_url(
    value: str,
) -> bool:
    try:
        parsed = urlparse(
            str(value or "").strip()
        )

    except ValueError:
        return False

    return bool(
        parsed.scheme.lower() == "https"
        and parsed.netloc
    )


def _normalize_oauth_mode(
    value: str,
) -> str:
    aliases = {
        "jwks": "jwks_rs256",
        "rs256": "jwks_rs256",
        "jwks_rs256": "jwks_rs256",
        "demo": "demo_hs256",
        "hs256": "demo_hs256",
        "demo_hs256": "demo_hs256",
    }

    normalized = str(
        value or ""
    ).strip().lower()

    return aliases.get(
        normalized,
        normalized,
    )


def _valid_sha256_digest(
    value: str,
) -> bool:
    normalized = str(
        value or ""
    ).strip().lower()

    if len(normalized) != 64:
        return False

    try:
        int(normalized, 16)

    except ValueError:
        return False

    return True


def _audit_key_pair_status(
    environment: Mapping[str, str],
) -> Dict[str, Any]:
    private_pem = str(
        environment.get(
            "AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_PEM",
            "",
        )
    ).strip()

    public_pem = str(
        environment.get(
            "AGENTGUARD_AUDIT_SIGNING_PUBLIC_KEY_PEM",
            "",
        )
    ).strip()

    if not private_pem or not public_pem:
        return {
            "valid": False,
            "detail": (
                "必须同时配置 Ed25519 "
                "审计签名公钥和私钥。"
            ),
        }

    try:
        private_key = (
            serialization
            .load_pem_private_key(
                private_pem.encode("utf-8"),
                password=None,
            )
        )

        public_key = (
            serialization
            .load_pem_public_key(
                public_pem.encode("utf-8")
            )
        )

    except Exception:
        return {
            "valid": False,
            "detail": (
                "审计签名公钥或私钥 "
                "不是有效的 PEM。"
            ),
        }

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        return {
            "valid": False,
            "detail": (
                "审计签名私钥必须是 "
                "Ed25519 私钥。"
            ),
        }

    if not isinstance(
        public_key,
        Ed25519PublicKey,
    ):
        return {
            "valid": False,
            "detail": (
                "审计签名公钥必须是 "
                "Ed25519 公钥。"
            ),
        }

    derived_public = (
        private_key
        .public_key()
        .public_bytes(
            encoding=(
                serialization.Encoding.Raw
            ),
            format=(
                serialization
                .PublicFormat
                .Raw
            ),
        )
    )

    configured_public = (
        public_key.public_bytes(
            encoding=(
                serialization.Encoding.Raw
            ),
            format=(
                serialization
                .PublicFormat
                .Raw
            ),
        )
    )

    matched = hmac.compare_digest(
        derived_public,
        configured_public,
    )

    return {
        "valid": matched,
        "detail": (
            "Ed25519 审计签名公私钥匹配。"
            if matched
            else (
                "Ed25519 审计签名公私钥 "
                "不属于同一密钥对。"
            )
        ),
    }


def build_security_readiness_report(
    environment: Optional[
        Mapping[str, str]
    ] = None,
    *,
    mode: Optional[str] = None,
) -> Dict[str, Any]:
    env: Mapping[str, str] = (
        os.environ
        if environment is None
        else environment
    )

    resolved_mode = str(
        mode
        if mode is not None
        else env.get(
            "AGENTGUARD_MODE",
            AGENTGUARD_MODE,
        )
    ).strip().lower()

    competition_mode = (
        resolved_mode == "competition"
    )

    enforcement_requested = (
        _environment_enabled(
            env,
            STARTUP_SECURITY_ENFORCEMENT_ENV,
        )
    )

    if not competition_mode:
        return {
            "schema": (
                "agentguard."
                "security_readiness.v1"
            ),
            "ready": True,
            "status": "development",
            "agentguard_mode": (
                resolved_mode
            ),
            "competition_mode": False,
            "enforcement_requested": (
                enforcement_requested
            ),
            "passed_checks": 0,
            "failed_checks": 0,
            "checks": [],
            "reason": (
                "Demo mode does not require "
                "production security settings."
            ),
        }

    checks: list[
        Dict[str, Any]
    ] = []

    def add_check(
        check_id: str,
        passed: bool,
        detail: str,
        remediation: str,
    ) -> None:
        checks.append(
            {
                "id": check_id,
                "required": True,
                "passed": bool(passed),
                "detail": detail,
                "remediation": remediation,
            }
        )

    add_check(
        "startup_enforcement",
        enforcement_requested,
        (
            "生产安全强制启动已开启。"
            if enforcement_requested
            else (
                "生产安全强制启动尚未开启。"
            )
        ),
        (
            "设置 "
            "AGENTGUARD_ENFORCE_STARTUP_SECURITY=1"
        ),
    )

    oauth_mode_value = (
        _normalize_oauth_mode(
            str(
                env.get(
                    "AGENTGUARD_OAUTH_MODE",
                    "",
                )
            )
        )
    )

    add_check(
        "oauth_jwks_rs256",
        oauth_mode_value
        == "jwks_rs256",
        (
            "OAuth 使用 JWKS/RS256。"
            if oauth_mode_value
            == "jwks_rs256"
            else (
                "OAuth 仍在使用本地 "
                "HS256 演示模式。"
            )
        ),
        (
            "设置 "
            "AGENTGUARD_OAUTH_MODE="
            "jwks_rs256"
        ),
    )

    jwks_url = str(
        env.get(
            "AGENTGUARD_OAUTH_JWKS_URL",
            "",
        )
    ).strip()

    add_check(
        "oauth_jwks_https",
        _is_https_url(jwks_url),
        (
            "JWKS 地址使用 HTTPS。"
            if _is_https_url(jwks_url)
            else (
                "JWKS 地址缺失或未使用 HTTPS。"
            )
        ),
        (
            "配置 HTTPS 的 "
            "AGENTGUARD_OAUTH_JWKS_URL"
        ),
    )

    issuer = str(
        env.get(
            "AGENTGUARD_OAUTH_ISSUER",
            "",
        )
    ).strip()

    add_check(
        "oauth_issuer_https",
        _is_https_url(issuer),
        (
            "OAuth issuer 使用 HTTPS。"
            if _is_https_url(issuer)
            else (
                "OAuth issuer 缺失或 "
                "未使用 HTTPS。"
            )
        ),
        (
            "配置 HTTPS 的 "
            "AGENTGUARD_OAUTH_ISSUER"
        ),
    )

    resource = str(
        env.get(
            "AGENTGUARD_MCP_RESOURCE",
            "",
        )
    ).strip()

    add_check(
        "mcp_resource_https",
        _is_https_url(resource),
        (
            "MCP Resource 使用 HTTPS。"
            if _is_https_url(resource)
            else (
                "MCP Resource 缺失或 "
                "未使用 HTTPS。"
            )
        ),
        (
            "配置 HTTPS 的 "
            "AGENTGUARD_MCP_RESOURCE"
        ),
    )

    attestation_required = (
        _environment_enabled(
            env,
            "AGENTGUARD_REQUIRE_TOOL_ATTESTATION",
        )
    )

    add_check(
        "tool_attestation_required",
        attestation_required,
        (
            "工具清单强制校验已开启。"
            if attestation_required
            else (
                "工具清单强制校验未开启。"
            )
        ),
        (
            "设置 "
            "AGENTGUARD_REQUIRE_TOOL_ATTESTATION=1"
        ),
    )

    configured_manifest_digest = str(
        env.get(
            "AGENTGUARD_TOOL_MANIFEST_SHA256",
            "",
        )
    ).strip().lower()

    current_manifest_digest = (
        tool_manifest_digest()
    )

    manifest_digest_valid = (
        _valid_sha256_digest(
            configured_manifest_digest
        )
        and hmac.compare_digest(
            configured_manifest_digest,
            current_manifest_digest,
        )
    )

    add_check(
        "tool_manifest_pin",
        manifest_digest_valid,
        (
            "工具清单 Pin 与当前注册表一致。"
            if manifest_digest_valid
            else (
                "工具清单 Pin 缺失、格式错误 "
                "或与当前注册表不一致。"
            )
        ),
        (
            "将当前 tool_manifest_digest() "
            "写入 "
            "AGENTGUARD_TOOL_MANIFEST_SHA256"
        ),
    )

    checkpoint_required = (
        _environment_enabled(
            env,
            "AGENTGUARD_REQUIRE_AUDIT_CHECKPOINT",
        )
    )

    add_check(
        "audit_checkpoint_required",
        checkpoint_required,
        (
            "审计签名检查点已设为必需。"
            if checkpoint_required
            else (
                "审计签名检查点尚未设为必需。"
            )
        ),
        (
            "设置 "
            "AGENTGUARD_REQUIRE_AUDIT_CHECKPOINT=1"
        ),
    )

    key_pair_status = (
        _audit_key_pair_status(env)
    )

    add_check(
        "audit_ed25519_key_pair",
        bool(
            key_pair_status.get(
                "valid"
            )
        ),
        str(
            key_pair_status.get(
                "detail",
                "",
            )
        ),
        (
            "配置匹配的 "
            "AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_PEM "
            "和 "
            "AGENTGUARD_AUDIT_SIGNING_PUBLIC_KEY_PEM"
        ),
    )

    key_id = str(
        env.get(
            "AGENTGUARD_AUDIT_SIGNING_KEY_ID",
            "",
        )
    ).strip()

    add_check(
        "audit_key_id",
        bool(key_id),
        (
            "审计签名 Key ID 已显式配置。"
            if key_id
            else (
                "审计签名 Key ID 未配置。"
            )
        ),
        (
            "设置唯一的 "
            "AGENTGUARD_AUDIT_SIGNING_KEY_ID"
        ),
    )

    failed = [
        item
        for item in checks
        if not item["passed"]
    ]

    ready = not failed

    return {
        "schema": (
            "agentguard."
            "security_readiness.v1"
        ),
        "ready": ready,
        "status": (
            "ready"
            if ready
            else "not_ready"
        ),
        "agentguard_mode": (
            resolved_mode
        ),
        "competition_mode": True,
        "enforcement_requested": (
            enforcement_requested
        ),
        "passed_checks": (
            len(checks) - len(failed)
        ),
        "failed_checks": len(failed),
        "failed_check_ids": [
            item["id"]
            for item in failed
        ],
        "checks": checks,
        "reason": (
            "All production security "
            "requirements passed."
            if ready
            else (
                "One or more production "
                "security requirements failed."
            )
        ),
    }


INITIAL_SECURITY_READINESS = (
    build_security_readiness_report(
        mode=AGENTGUARD_MODE
    )
)

if (
    COMPETITION_MODE
    and INITIAL_SECURITY_READINESS[
        "enforcement_requested"
    ]
    and not INITIAL_SECURITY_READINESS[
        "ready"
    ]
):
    failed_ids = ", ".join(
        INITIAL_SECURITY_READINESS.get(
            "failed_check_ids",
            [],
        )
    )

    raise RuntimeError(
        "AgentGuard competition mode "
        "security readiness failed: "
        + failed_ids
    )


app = FastAPI(
    title="AgentGuard MCP Security Gateway",
    description=(
        "OAuth-protected MCP and AI Agent tool-call authorization gateway. "
        "The MCP adapter reuses AgentGuard Task Boundary, Capability Token, "
        "Runtime Monitor, Hybrid Sandbox and Audit Evidence controls."
    ),
    version="0.6.0",
)

BASE_DIR = Path(__file__).resolve().parent.parent

FRONTEND_INDEX = BASE_DIR / "frontend" / "index.html"
FRONTEND_TASK_CHAIN = BASE_DIR / "frontend" / "task_chain.html"
FRONTEND_SECURITY_DASHBOARD = BASE_DIR / "frontend" / "security_dashboard.html"
FRONTEND_ATTACK_CHAIN_RUNTIME = BASE_DIR / "frontend" / "attack_chain_runtime.html"
FRONTEND_SANDBOX_DASHBOARD = BASE_DIR / "frontend" / "sandbox_dashboard.html"
FRONTEND_AUTHORIZED_EVIDENCE = BASE_DIR / "frontend" / "authorized_evidence.html"
FRONTEND_SHOWCASE = BASE_DIR / "frontend" / "showcase.html"
FRONTEND_TOOL_PROXY = BASE_DIR / "frontend" / "tool_proxy.html"


def _serve_frontend_html(path: Path, missing_message: str):
    if path.exists():
        return FileResponse(path)

    return {
        "message": missing_message,
        "expected_path": str(path),
    }


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:9000",
        "http://localhost:9000",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "null",
    ],
    allow_origin_regex=r"^http://(127\.0\.0\.1|localhost):\d+$",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Always-available trusted APIs
# -----------------------------

# The MCP router is the only tool-execution entrypoint
# registered in competition mode. It validates the OAuth
# Bearer Token before reaching AgentGuard authorization.
app.include_router(mcp_router)

# Read-only reporting, evidence and local visualization APIs.
app.include_router(audit_router)
app.include_router(report_router)
app.include_router(security_overview_router)
app.include_router(sandbox_evidence_router)
app.include_router(showcase_report_router)
app.include_router(oauth_comparison_router)
app.include_router(research_eval_router)
app.include_router(research_strategy_router)
app.include_router(test_results_router)
app.include_router(frontend_data_router)
app.include_router(trusted_audit_router)
app.include_router(evidence_bundle_router)


# -----------------------------
# Demo/development-only APIs
# -----------------------------

if not COMPETITION_MODE:
    # These routes are retained for local development and
    # backward-compatible demonstrations. They are deliberately
    # absent in competition mode because they can accept tool
    # calls without entering through the protected MCP boundary.
    app.include_router(gateway_router)
    app.include_router(approval_router)
    app.include_router(task_contract_router)
    app.include_router(capability_router)
    app.include_router(runtime_router)
    app.include_router(attack_chain_router)
    app.include_router(agent_runtime_router)
    app.include_router(tool_proxy_router)
    app.include_router(external_agent_router)
    app.include_router(two_phase_tool_proxy_router)
    app.include_router(capability_token_router)
    app.include_router(llm_tool_call_router)
    app.include_router(docker_sandbox_router)
    app.include_router(native_sandbox_router)
    app.include_router(demo_router)


app.state.agentguard_mode = AGENTGUARD_MODE
app.state.competition_mode = COMPETITION_MODE
app.state.security_readiness = (
    INITIAL_SECURITY_READINESS
)

# -----------------------------
# Frontend pages
# -----------------------------

@app.get("/")
def index():
    return _serve_frontend_html(
        FRONTEND_INDEX,
        "Frontend file is missing",
    )


@app.get("/showcase")
def showcase_page():
    return _serve_frontend_html(
        FRONTEND_SHOWCASE,
        "Showcase frontend file is missing",
    )


@app.get("/tool-proxy")
def tool_proxy_page():
    return _serve_frontend_html(
        FRONTEND_TOOL_PROXY,
        "Tool Proxy frontend file is missing",
    )


@app.get("/task-chain")
def task_chain_page():
    return _serve_frontend_html(
        FRONTEND_TASK_CHAIN,
        "Task chain frontend file is missing",
    )


@app.get("/attack-chain-runtime")
def attack_chain_runtime_page():
    return _serve_frontend_html(
        FRONTEND_ATTACK_CHAIN_RUNTIME,
        "Attack chain runtime frontend file is missing",
    )


@app.get("/security-dashboard")
def security_dashboard_page():
    return _serve_frontend_html(
        FRONTEND_SECURITY_DASHBOARD,
        "Security dashboard frontend file is missing",
    )


@app.get("/sandbox-dashboard")
def sandbox_dashboard_page():
    return _serve_frontend_html(
        FRONTEND_SANDBOX_DASHBOARD,
        "Sandbox frontend file is missing",
    )


@app.get("/authorized-evidence")
def authorized_evidence_page():
    return _serve_frontend_html(
        FRONTEND_AUTHORIZED_EVIDENCE,
        "Authorized evidence frontend file is missing",
    )


# -----------------------------
# Health and readiness checks
# -----------------------------

@app.get("/api/readiness")
def api_readiness():
    report = (
        build_security_readiness_report(
            mode=AGENTGUARD_MODE
        )
    )

    app.state.security_readiness = (
        report
    )

    return JSONResponse(
        content=report,
        status_code=(
            200
            if report["ready"]
            else 503
        ),
    )


@app.get("/api/status")
def api_status():
    return {
        "message": "AgentGuard MCP Security Gateway is running",
        "version": "0.6.0",
        "agentguard_mode": AGENTGUARD_MODE,
        "competition_mode": COMPETITION_MODE,
        "execution_entrypoint": (
            "oauth_protected_mcp_only"
            if COMPETITION_MODE
            else "development_multi_entry"
        ),
        "security_readiness": {
            "ready": (
                build_security_readiness_report(
                    mode=AGENTGUARD_MODE
                )["ready"]
            ),
            "endpoint": "/api/readiness",
            "enforcement_environment": (
                STARTUP_SECURITY_ENFORCEMENT_ENV
            ),
        },
        "disabled_direct_route_prefixes": (
            list(
                COMPETITION_DISABLED_ROUTE_PREFIXES
            )
            if COMPETITION_MODE
            else []
        ),
        "architecture": {
            "mcp": (
                "MCP Client -> OAuth Bearer Token -> /mcp -> Tool Proxy -> "
                "Task Boundary / Capability Token / Runtime Monitor -> Hybrid Sandbox"
            ),
            "core": (
                "External caller -> Agent Runtime / Gateway -> "
                "Runtime Monitor -> ToolExecutor"
            ),
            "real_agent": (
                "MultiStepLLMAgent -> Capability Contract -> "
                "Runtime Monitor -> Hybrid Sandbox Executor"
            ),
            "demo": "FakeAgent -> Demo API -> Gateway -> ToolExecutor",
        },
        "registered_core_features": [
            "mcp_streamable_http",
            "oauth_protected_resource_metadata",
            "oauth_bearer_token_validation",
            "oauth_scope_filtering",
            "gateway",
            "capability_contract",
            "capability_token_two_phase_authorization",
            "runtime_monitor",
            "attack_chain_detector",
            "sandbox_evidence",
            "docker_sandbox_executor",
            "native_subprocess_sandbox",
            "showcase_report",
            "agent_runtime",
            "tool_proxy",
            "external_agent_adapter",
            "independent_test_runner",
            "frontend_local_runtime_data",
        ],
        "mcp": {
            "endpoint": "/mcp",
            "protected_resource_metadata": "/.well-known/oauth-protected-resource",
            "protocol_target": "2025-11-25",
            "demo_authorization_server": "http://127.0.0.1:9000",
        },
        "note": (
            "The included OAuth authorization server is a localhost-only competition demo. "
            "Production deployment should connect AgentGuard to a maintained OAuth/OIDC provider."
        ),
    }


# === Teacher review cleanup: legacy frontend route notice ===
# The project has migrated from FastAPI-served static HTML pages to
# a Vite + React frontend. Keep these compatibility routes friendly.
def _install_legacy_frontend_route_notice():
    try:
        from fastapi.responses import JSONResponse
    except Exception:
        return

    legacy_paths = {
        "/",
        "/showcase",
        "/task-chain",
        "/attack-chain-runtime",
        "/security-dashboard",
        "/sandbox-dashboard",
        "/authorized-evidence",
        "/tool-proxy",
    }

    try:
        app.router.routes = [
            route
            for route in app.router.routes
            if getattr(route, "path", None) not in legacy_paths
        ]
    except Exception:
        return

    async def legacy_frontend_notice():
        return JSONResponse(
            {
                "message": "旧版后端静态页面入口已废弃，请访问新版 React 前端。",
                "frontend": "http://127.0.0.1:5173",
                "backend": "http://127.0.0.1:8000",
                "docs": "http://127.0.0.1:8000/docs",
                "mcp": "http://127.0.0.1:8000/mcp",
                "oauth_metadata": "http://127.0.0.1:8000/.well-known/oauth-protected-resource",
                "recommended_demo_mode": "授权演示 -> 真沙箱执行（自动选择）",
            }
        )

    for path in sorted(legacy_paths):
        app.add_api_route(path, legacy_frontend_notice, methods=["GET"], include_in_schema=False)


_install_legacy_frontend_route_notice()
# === End teacher review cleanup ===
