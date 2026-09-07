from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import backend.oauth.token_service as token_service

from backend.oauth.token_service import (
    issue_access_token,
    verify_access_token,
)


@pytest.fixture(autouse=True)
def oauth_test_environment(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_MODE",
        "demo_hs256",
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_DEMO_SECRET",
        (
            "agentguard-test-secret-"
            "must-be-at-least-32-bytes"
        ),
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_ISSUER",
        "http://127.0.0.1:9000",
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RESOURCE",
        "http://127.0.0.1:8000/mcp",
    )

    monkeypatch.delenv(
        "AGENTGUARD_OAUTH_JWKS_URL",
        raising=False,
    )


def test_demo_access_token_round_trip():
    issued = issue_access_token(
        subject="alice",
        scopes=[
            "mcp:tools:list",
            "tool:file:read",
        ],
        audience=(
            "http://127.0.0.1:8000/mcp"
        ),
        issuer=(
            "http://127.0.0.1:9000"
        ),
        client_id="test-client",
        ttl_seconds=600,
    )

    verified = verify_access_token(
        issued["access_token"],
        expected_audience=(
            "http://127.0.0.1:8000/mcp"
        ),
        expected_issuer=(
            "http://127.0.0.1:9000"
        ),
    )

    assert verified["valid"] is True

    assert (
        verified["verification_mode"]
        == "demo_hs256"
    )

    assert (
        verified["payload"]["sub"]
        == "alice"
    )

    assert (
        verified["payload"]["client_id"]
        == "test-client"
    )

    assert verified["payload"]["scopes"] == [
        "mcp:tools:list",
        "tool:file:read",
    ]


def test_demo_access_token_rejects_wrong_audience():
    issued = issue_access_token(
        subject="alice",
        scopes=[
            "mcp:tools:list"
        ],
        audience=(
            "http://127.0.0.1:8000/mcp"
        ),
        issuer=(
            "http://127.0.0.1:9000"
        ),
    )

    verified = verify_access_token(
        issued["access_token"],
        expected_audience=(
            "http://127.0.0.1:9999/mcp"
        ),
        expected_issuer=(
            "http://127.0.0.1:9000"
        ),
    )

    assert verified["valid"] is False

    assert (
        verified["error"]
        == "invalid_audience"
    )


def test_demo_access_token_rejects_tampering():
    issued = issue_access_token(
        subject="alice",
        scopes=[
            "mcp:tools:list"
        ],
    )

    token = issued["access_token"]

    header_segment, payload_segment, signature_segment = (
        token.split(".")
    )

    # 修改签名段首字符，确保实际签名字节发生变化。
    # 修改最后一个 Base64URL 字符可能只改变未使用填充位，
    # 从而偶发解码为相同字节。
    replacement = (
        "A"
        if signature_segment[0] != "A"
        else "B"
    )

    tampered_token = ".".join(
        [
            header_segment,
            payload_segment,
            replacement
            + signature_segment[1:],
        ]
    )

    verified = verify_access_token(
        tampered_token
    )

    assert verified["valid"] is False

    assert (
        verified["error"]
        == "invalid_signature"
    )


def test_demo_secret_must_be_strong(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_DEMO_SECRET",
        "short",
    )

    with pytest.raises(
        RuntimeError,
        match="至少需要 32 字节",
    ):
        issue_access_token(
            subject="alice",
            scopes=[
                "mcp:tools:list"
            ],
        )


def test_jwks_mode_does_not_issue_tokens(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_MODE",
        "jwks_rs256",
    )

    with pytest.raises(
        RuntimeError,
        match="外部授权服务器签发",
    ):
        issue_access_token(
            subject="alice",
            scopes=[
                "mcp:tools:list"
            ],
        )


def test_jwks_mode_rejects_hs256_token(
    monkeypatch: pytest.MonkeyPatch,
):
    issued = issue_access_token(
        subject="alice",
        scopes=[
            "mcp:tools:list"
        ],
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_MODE",
        "jwks_rs256",
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_JWKS_URL",
        (
            "https://issuer.example/"
            ".well-known/jwks.json"
        ),
    )

    verified = verify_access_token(
        issued["access_token"]
    )

    assert verified["valid"] is False

    assert (
        verified["error"]
        == "unsupported_alg"
    )


def test_jwks_rs256_access_token_round_trip(
    monkeypatch: pytest.MonkeyPatch,
):
    issuer = "https://issuer.example"

    audience = "https://api.example/mcp"

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_MODE",
        "jwks_rs256",
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_ISSUER",
        issuer,
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RESOURCE",
        audience,
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_JWKS_URL",
        (
            f"{issuer}/"
            ".well-known/jwks.json"
        ),
    )

    private_key = (
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    )

    public_key = (
        private_key.public_key()
    )

    class StaticJwksClient:
        def get_signing_key_from_jwt(
            self,
            token: str,
        ):
            _ = token

            return SimpleNamespace(
                key=public_key
            )

    monkeypatch.setattr(
        token_service,
        "_get_jwks_client",
        lambda: StaticJwksClient(),
    )

    now = int(time.time())

    payload = {
        "iss": issuer,
        "sub": "alice",
        "aud": audience,
        "client_id": "keycloak-client",
        "scope": (
            "mcp:tools:list "
            "tool:file:read"
        ),
        "iat": now,
        "exp": now + 600,
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={
            "kid": "test-key-1",
            "typ": "JWT",
        },
    )

    verified = verify_access_token(
        token
    )

    assert verified["valid"] is True

    assert (
        verified["verification_mode"]
        == "jwks_rs256"
    )

    assert (
        verified["header"]["kid"]
        == "test-key-1"
    )

    assert (
        verified["payload"]["sub"]
        == "alice"
    )

    assert verified["payload"]["scopes"] == [
        "mcp:tools:list",
        "tool:file:read",
    ]


def test_jwks_rs256_rejects_wrong_audience(
    monkeypatch: pytest.MonkeyPatch,
):
    issuer = "https://issuer.example"

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_MODE",
        "jwks_rs256",
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_ISSUER",
        issuer,
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RESOURCE",
        "https://api.example/mcp",
    )

    monkeypatch.setenv(
        "AGENTGUARD_OAUTH_JWKS_URL",
        (
            f"{issuer}/"
            ".well-known/jwks.json"
        ),
    )

    private_key = (
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    )

    public_key = (
        private_key.public_key()
    )

    class StaticJwksClient:
        def get_signing_key_from_jwt(
            self,
            token: str,
        ):
            _ = token

            return SimpleNamespace(
                key=public_key
            )

    monkeypatch.setattr(
        token_service,
        "_get_jwks_client",
        lambda: StaticJwksClient(),
    )

    now = int(time.time())

    token = jwt.encode(
        {
            "iss": issuer,
            "sub": "alice",
            "aud": (
                "https://other.example/mcp"
            ),
            "scope": "mcp:tools:list",
            "iat": now,
            "exp": now + 600,
        },
        private_key,
        algorithm="RS256",
        headers={
            "kid": "test-key-2",
        },
    )

    verified = verify_access_token(
        token
    )

    assert verified["valid"] is False

    assert (
        verified["error"]
        == "invalid_audience"
    )



def _secure_readiness_environment():
    from cryptography.hazmat.primitives import (
        serialization,
    )

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from backend.mcp.tool_registry import (
        tool_manifest_digest,
    )

    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    private_pem = (
        private_key.private_bytes(
            encoding=(
                serialization
                .Encoding
                .PEM
            ),
            format=(
                serialization
                .PrivateFormat
                .PKCS8
            ),
            encryption_algorithm=(
                serialization
                .NoEncryption()
            ),
        ).decode("utf-8")
    )

    public_pem = (
        public_key.public_bytes(
            encoding=(
                serialization
                .Encoding
                .PEM
            ),
            format=(
                serialization
                .PublicFormat
                .SubjectPublicKeyInfo
            ),
        ).decode("utf-8")
    )

    return {
        "AGENTGUARD_MODE": (
            "competition"
        ),
        "AGENTGUARD_ENFORCE_STARTUP_SECURITY": (
            "1"
        ),
        "AGENTGUARD_OAUTH_MODE": (
            "jwks_rs256"
        ),
        "AGENTGUARD_OAUTH_JWKS_URL": (
            "https://identity.example/"
            ".well-known/jwks.json"
        ),
        "AGENTGUARD_OAUTH_ISSUER": (
            "https://identity.example"
        ),
        "AGENTGUARD_MCP_RESOURCE": (
            "https://agentguard.example/mcp"
        ),
        "AGENTGUARD_REQUIRE_TOOL_ATTESTATION": (
            "1"
        ),
        "AGENTGUARD_TOOL_MANIFEST_SHA256": (
            tool_manifest_digest()
        ),
        "AGENTGUARD_REQUIRE_AUDIT_CHECKPOINT": (
            "1"
        ),
        "AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_PEM": (
            private_pem
        ),
        "AGENTGUARD_AUDIT_SIGNING_PUBLIC_KEY_PEM": (
            public_pem
        ),
        "AGENTGUARD_AUDIT_SIGNING_KEY_ID": (
            "production-audit-key-2026"
        ),
    }


def test_competition_readiness_rejects_insecure_defaults():
    from backend.main import (
        build_security_readiness_report,
    )

    result = (
        build_security_readiness_report(
            {},
            mode="competition",
        )
    )

    assert result["ready"] is False

    assert (
        result["status"]
        == "not_ready"
    )

    assert (
        "oauth_jwks_rs256"
        in result["failed_check_ids"]
    )

    assert (
        "tool_manifest_pin"
        in result["failed_check_ids"]
    )

    assert (
        "audit_ed25519_key_pair"
        in result["failed_check_ids"]
    )


def test_competition_readiness_accepts_secure_configuration():
    from backend.main import (
        build_security_readiness_report,
    )

    environment = (
        _secure_readiness_environment()
    )

    result = (
        build_security_readiness_report(
            environment,
            mode="competition",
        )
    )

    assert result["ready"] is True

    assert result["failed_checks"] == 0

    assert (
        result["passed_checks"]
        == len(result["checks"])
    )


def test_competition_readiness_rejects_mismatched_audit_keys():
    from cryptography.hazmat.primitives import (
        serialization,
    )

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from backend.main import (
        build_security_readiness_report,
    )

    environment = (
        _secure_readiness_environment()
    )

    unrelated_public_key = (
        Ed25519PrivateKey
        .generate()
        .public_key()
    )

    environment[
        "AGENTGUARD_AUDIT_SIGNING_PUBLIC_KEY_PEM"
    ] = unrelated_public_key.public_bytes(
        encoding=(
            serialization.Encoding.PEM
        ),
        format=(
            serialization
            .PublicFormat
            .SubjectPublicKeyInfo
        ),
    ).decode("utf-8")

    result = (
        build_security_readiness_report(
            environment,
            mode="competition",
        )
    )

    assert result["ready"] is False

    assert (
        "audit_ed25519_key_pair"
        in result["failed_check_ids"]
    )
