from __future__ import annotations

import os
import secrets
import time
from typing import Any, Dict, Iterable, List, Optional

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWKClientError,
)


DEFAULT_OAUTH_ISSUER = "http://127.0.0.1:9000"
DEFAULT_MCP_RESOURCE = "http://127.0.0.1:8000/mcp"

DEMO_MODE = "demo_hs256"
JWKS_MODE = "jwks_rs256"

VALID_MODES = {
    DEMO_MODE,
    JWKS_MODE,
}

# 本地演示模式不再使用代码中写死的固定密钥。
# 未配置环境变量时，每次进程启动生成新的随机密钥。
# 该模式只适合本地单进程演示。
_EPHEMERAL_DEMO_SECRET = secrets.token_bytes(48)

_JWKS_CLIENT_CACHE: Dict[str, PyJWKClient] = {}


def oauth_mode() -> str:
    raw_mode = os.getenv(
        "AGENTGUARD_OAUTH_MODE",
        DEMO_MODE,
    ).strip().lower()

    aliases = {
        "demo": DEMO_MODE,
        "hs256": DEMO_MODE,
        "demo_hs256": DEMO_MODE,
        "jwks": JWKS_MODE,
        "rs256": JWKS_MODE,
        "jwks_rs256": JWKS_MODE,
    }

    mode = aliases.get(
        raw_mode,
        raw_mode,
    )

    if mode not in VALID_MODES:
        raise ValueError(
            "AGENTGUARD_OAUTH_MODE 必须是 "
            f"{DEMO_MODE} 或 {JWKS_MODE}，"
            f"当前值为：{raw_mode}"
        )

    return mode


def oauth_issuer() -> str:
    return os.getenv(
        "AGENTGUARD_OAUTH_ISSUER",
        DEFAULT_OAUTH_ISSUER,
    ).rstrip("/")


def mcp_resource() -> str:
    return os.getenv(
        "AGENTGUARD_MCP_RESOURCE",
        DEFAULT_MCP_RESOURCE,
    ).rstrip("/")


def oauth_jwks_url() -> str:
    return os.getenv(
        "AGENTGUARD_OAUTH_JWKS_URL",
        "",
    ).strip()


def oauth_clock_skew_seconds() -> int:
    raw_value = os.getenv(
        "AGENTGUARD_OAUTH_CLOCK_SKEW_SECONDS",
        "30",
    )

    try:
        value = int(raw_value)
    except ValueError:
        value = 30

    return max(
        0,
        min(value, 300),
    )


def _secret() -> bytes:
    configured = os.getenv(
        "AGENTGUARD_OAUTH_DEMO_SECRET",
        "",
    ).strip()

    if not configured:
        return _EPHEMERAL_DEMO_SECRET

    encoded = configured.encode("utf-8")

    if len(encoded) < 32:
        raise RuntimeError(
            "AGENTGUARD_OAUTH_DEMO_SECRET "
            "至少需要 32 字节。"
        )

    return encoded


def _get_jwks_client() -> PyJWKClient:
    url = oauth_jwks_url()

    if not url:
        raise RuntimeError(
            "JWKS 模式下必须配置 "
            "AGENTGUARD_OAUTH_JWKS_URL。"
        )

    client = _JWKS_CLIENT_CACHE.get(url)

    if client is None:
        client = PyJWKClient(
            url,
            cache_keys=True,
        )

        _JWKS_CLIENT_CACHE[url] = client

    return client


def normalize_scopes(
    value: Any,
) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        raw_items = value.replace(
            ",",
            " ",
        ).split()

    elif isinstance(value, Iterable):
        raw_items = [
            str(item)
            for item in value
        ]

    else:
        raw_items = [
            str(value)
        ]

    result: List[str] = []
    seen = set()

    for item in raw_items:
        scope = str(item).strip()

        if not scope or scope in seen:
            continue

        seen.add(scope)
        result.append(scope)

    return result


def issue_access_token(
    *,
    subject: str,
    scopes: Any,
    audience: Optional[str] = None,
    client_id: str = "agentguard-demo-client",
    ttl_seconds: int = 900,
    issuer: Optional[str] = None,
) -> Dict[str, Any]:
    if oauth_mode() != DEMO_MODE:
        raise RuntimeError(
            "JWKS/RS256 模式下 Access Token "
            "必须由外部授权服务器签发，"
            "AgentGuard 资源服务器不能自行签发。"
        )

    now = int(time.time())

    normalized_scopes = normalize_scopes(
        scopes
    )

    payload = {
        "iss": issuer or oauth_issuer(),
        "sub": str(subject),
        "aud": audience or mcp_resource(),
        "client_id": str(client_id),
        "scope": " ".join(
            normalized_scopes
        ),
        "iat": now,
        "exp": now + max(
            60,
            int(ttl_seconds),
        ),
        "jti": secrets.token_urlsafe(12),
        "token_use": "access_token",
    }

    token = jwt.encode(
        payload,
        _secret(),
        algorithm="HS256",
        headers={
            "typ": "JWT",
        },
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": (
            payload["exp"] - now
        ),
        "scope": payload["scope"],
        "payload": payload,
    }


def _error(
    error: str,
    reason: str,
    *,
    payload: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "valid": False,
        "error": error,
        "reason": reason,
    }

    if payload is not None:
        result["payload"] = payload

    return result


def verify_access_token(
    token: str,
    *,
    expected_audience: Optional[str] = None,
    expected_issuer: Optional[str] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    token = str(token or "").strip()

    if not token:
        return _error(
            "missing_token",
            "Access token 为空。",
        )

    try:
        mode = oauth_mode()
    except ValueError as exc:
        return _error(
            "oauth_configuration_error",
            str(exc),
        )

    try:
        header = jwt.get_unverified_header(
            token
        )
    except DecodeError:
        return _error(
            "malformed_token",
            "Access token 不是有效的 JWT。",
        )
    except InvalidTokenError as exc:
        return _error(
            "malformed_token",
            f"JWT Header 解析失败：{exc}",
        )

    algorithm = str(
        header.get("alg", "")
    ).upper()

    expected_algorithm = (
        "HS256"
        if mode == DEMO_MODE
        else "RS256"
    )

    if algorithm != expected_algorithm:
        return _error(
            "unsupported_alg",
            (
                f"当前 OAuth 模式为 {mode}，"
                f"只允许 {expected_algorithm}，"
                f"收到 {algorithm or 'unknown'}。"
            ),
        )

    issuer = (
        expected_issuer
        or oauth_issuer()
    ).rstrip("/")

    audience = (
        expected_audience
        or mcp_resource()
    ).rstrip("/")

    try:
        if mode == DEMO_MODE:
            verification_key = _secret()

        else:
            jwks_client = (
                _get_jwks_client()
            )

            verification_key = (
                jwks_client
                .get_signing_key_from_jwt(
                    token
                )
                .key
            )

        decode_options = {
            "require": [
                "exp",
                "iat",
                "iss",
                "aud",
                "sub",
            ],
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "verify_iss": True,
            "verify_aud": True,
        }

        # PyJWT 不直接支持传入固定 now。
        # now 参数主要保留给旧调用兼容；
        # 测试过期时间使用真实时间构造。
        _ = now

        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[
                expected_algorithm
            ],
            audience=audience,
            issuer=issuer,
            options=decode_options,
            leeway=(
                oauth_clock_skew_seconds()
            ),
        )

    except ExpiredSignatureError:
        return _error(
            "expired_token",
            "Access token 已过期。",
        )

    except ImmatureSignatureError:
        return _error(
            "immature_token",
            "Access token 尚未生效，"
            "或签发时间位于未来。",
        )

    except InvalidIssuedAtError:
        return _error(
            "invalid_iat",
            "Access token 的 iat 无效。",
        )

    except InvalidIssuerError:
        return _error(
            "invalid_issuer",
            "Access token 的 issuer "
            "与配置的授权服务器不一致。",
        )

    except InvalidAudienceError:
        return _error(
            "invalid_audience",
            "Access token 不是签发给"
            "当前 MCP Resource 的。",
        )

    except MissingRequiredClaimError as exc:
        return _error(
            "missing_claim",
            (
                "Access token 缺少必须声明："
                f"{exc.claim}"
            ),
        )

    except InvalidSignatureError:
        return _error(
            "invalid_signature",
            "Access token 签名验证失败。",
        )

    except InvalidAlgorithmError:
        return _error(
            "unsupported_alg",
            "Access token 使用了"
            "不允许的签名算法。",
        )

    except PyJWKClientError as exc:
        return _error(
            "jwks_error",
            f"无法获取或匹配 JWKS 公钥：{exc}",
        )

    except RuntimeError as exc:
        return _error(
            "oauth_configuration_error",
            str(exc),
        )

    except DecodeError as exc:
        return _error(
            "invalid_encoding",
            f"Access token 解码失败：{exc}",
        )

    except InvalidTokenError as exc:
        return _error(
            "invalid_token",
            f"Access token 验证失败：{exc}",
        )

    token_use = payload.get(
        "token_use"
    )

    # Cognito 等服务会提供 token_use；
    # Keycloak 等服务可能不提供。
    # 如果存在该字段，则必须明确是访问令牌。
    if (
        token_use is not None
        and token_use != "access_token"
    ):
        return _error(
            "invalid_token_use",
            "Token 不是 OAuth Access Token。",
            payload=dict(payload),
        )

    scope_value = payload.get(
        "scope"
    )

    if scope_value is None:
        scope_value = payload.get(
            "scp"
        )

    if scope_value is None:
        scope_value = payload.get(
            "scopes"
        )

    verified_payload = dict(payload)

    verified_payload["scopes"] = (
        normalize_scopes(
            scope_value
        )
    )

    return {
        "valid": True,
        "payload": verified_payload,
        "header": dict(header),
        "verification_mode": mode,
        "reason": (
            "Access token 的签名、issuer、"
            "audience、有效期及必要声明均有效。"
        ),
    }
