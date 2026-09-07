from __future__ import annotations

import hashlib
import hmac
import json
import os
from copy import deepcopy
from typing import Any, Dict, Iterable, List

from backend.oauth.token_service import normalize_scopes


MCP_LIST_SCOPE = "mcp:tools:list"
MCP_TASK_SCOPE = "mcp:tasks:manage"
MCP_APPROVAL_READ_SCOPE = "mcp:approvals:read"
MCP_APPROVAL_DECIDE_SCOPE = "mcp:approvals:decide"


_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "agentguard.task.create",
        "title": "Create AgentGuard trusted task",
        "description": (
            "Create a server-side AgentGuard task boundary before calling protected tools. "
            "Pass the user's original request as faithfully as possible. "
            "The returned taskHandle must be supplied to subsequent AgentGuard tool calls."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "originalTask": {
                    "type": "string",
                    "description": "The user's original task request.",
                }
            },
            "required": ["originalTask"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": {
            "agentguard/requiredScopes": [MCP_TASK_SCOPE],
        },
    },
    {
        "name": "file.read",
        "title": "Read sandbox file",
        "description": "Read a file that is authorized by AgentGuard and confined to the runtime sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Sandbox-relative path, for example public/notice.txt.",
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "_meta": {
            "agentguard/requiredScopes": ["tool:file:read"],
        },
    },
    {
        "name": "file.write",
        "title": "Write sandbox file",
        "description": "Write content to an AgentGuard-authorized sandbox-relative file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "_meta": {
            "agentguard/requiredScopes": ["tool:file:write", "sink:side-effect"],
        },
    },
    {
        "name": "file.delete",
        "title": "Delete sandbox file",
        "description": "Delete an AgentGuard-authorized regular file inside the runtime sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": {
            "agentguard/requiredScopes": ["tool:file:delete", "sink:side-effect"],
        },
    },
    {
        "name": "email.send",
        "title": "Send sandbox email",
        "description": "Create an email record in the sandbox outbox. The demo executor never sends real external email.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["to", "content"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "_meta": {
            "agentguard/requiredScopes": ["tool:email:send", "sink:side-effect"],
        },
    },
    {
        "name": "shell.run",
        "title": "Run restricted sandbox command",
        "description": "Run a very small allowlist of commands through the AgentGuard sandbox interpreter.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "_meta": {
            "agentguard/requiredScopes": ["tool:shell:run", "sink:side-effect"],
        },
    },
    {
        "name": "db.query",
        "title": "Query sandbox database",
        "description": "Execute a read-only SELECT query against the AgentGuard sandbox database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string"},
            },
            "required": ["sql"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "_meta": {
            "agentguard/requiredScopes": ["tool:db:query"],
        },
    },
]


# Standard MCP client compatibility: expose taskHandle as a normal
# tool argument because generic MCP clients cannot populate AgentGuard
# specific params._meta fields themselves.
for _tool in _TOOL_DEFINITIONS:
    if _tool.get("name") == "agentguard.task.create":
        continue

    _schema = _tool.get("inputSchema", {})
    _properties = _schema.setdefault("properties", {})

    _properties.setdefault(
        "taskHandle",
        {
            "type": "string",
            "description": (
                "Server-issued AgentGuard task handle returned by "
                "agentguard.task.create."
            ),
        },
    )


TOOL_MANIFEST_SCHEMA = (
    "agentguard.tool_manifest.v1"
)

TOOL_MANIFEST_PIN_ENV = (
    "AGENTGUARD_TOOL_MANIFEST_SHA256"
)

TOOL_MANIFEST_REQUIRED_ENV = (
    "AGENTGUARD_REQUIRE_TOOL_ATTESTATION"
)


def _canonical_json(
    value: Any,
) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _manifest_source() -> Dict[str, Any]:
    return {
        "schema": TOOL_MANIFEST_SCHEMA,
        "tools": [
            deepcopy(tool)
            for tool in sorted(
                _TOOL_DEFINITIONS,
                key=lambda item: item["name"],
            )
        ],
    }


def tool_manifest_digest() -> str:
    """
    对完整工具定义进行 SHA-256 摘要。

    摘要覆盖：
    - 工具名称
    - 工具说明
    - JSON Schema
    - 安全 annotations
    - 所需 OAuth Scope
    """
    return hashlib.sha256(
        _canonical_json(
            _manifest_source()
        )
    ).hexdigest()


def tool_definition_digest(
    tool: Dict[str, Any],
) -> str:
    return hashlib.sha256(
        _canonical_json(
            deepcopy(tool)
        )
    ).hexdigest()


def _env_enabled(
    name: str,
) -> bool:
    return os.getenv(
        name,
        "",
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def tool_manifest_attestation() -> Dict[str, Any]:
    """
    校验运行时工具清单是否与部署时固定的摘要一致。

    开发环境：
    - 未设置摘要时返回 unpinned，不中断运行。

    严格部署环境：
    - 设置 AGENTGUARD_REQUIRE_TOOL_ATTESTATION=1
    - 设置 AGENTGUARD_TOOL_MANIFEST_SHA256=<可信摘要>
    - 摘要不一致时 MCP 请求失败关闭。
    """
    actual_digest = (
        tool_manifest_digest()
    )

    expected_digest = os.getenv(
        TOOL_MANIFEST_PIN_ENV,
        "",
    ).strip().lower()

    required = _env_enabled(
        TOOL_MANIFEST_REQUIRED_ENV
    )

    if not expected_digest:
        return {
            "schema": (
                TOOL_MANIFEST_SCHEMA
            ),
            "algorithm": "sha256",
            "valid": not required,
            "status": (
                "missing_required_pin"
                if required
                else "unpinned"
            ),
            "required": required,
            "actual_digest": (
                actual_digest
            ),
            "expected_digest": "",
        }

    valid_format = (
        len(expected_digest) == 64
    )

    if valid_format:
        try:
            int(
                expected_digest,
                16,
            )
        except ValueError:
            valid_format = False

    if not valid_format:
        return {
            "schema": (
                TOOL_MANIFEST_SCHEMA
            ),
            "algorithm": "sha256",
            "valid": False,
            "status": "invalid_pin",
            "required": required,
            "actual_digest": (
                actual_digest
            ),
            "expected_digest": (
                expected_digest
            ),
        }

    matched = hmac.compare_digest(
        actual_digest,
        expected_digest,
    )

    return {
        "schema": TOOL_MANIFEST_SCHEMA,
        "algorithm": "sha256",
        "valid": matched,
        "status": (
            "verified"
            if matched
            else "mismatch"
        ),
        "required": required,
        "actual_digest": actual_digest,
        "expected_digest": (
            expected_digest
        ),
    }


def _attested_tool_copy(
    tool: Dict[str, Any],
) -> Dict[str, Any]:
    copied = deepcopy(tool)

    attestation = (
        tool_manifest_attestation()
    )

    meta = copied.setdefault(
        "_meta",
        {},
    )

    meta[
        "agentguard/definitionDigest"
    ] = tool_definition_digest(tool)

    meta[
        "agentguard/manifestDigest"
    ] = attestation["actual_digest"]

    meta[
        "agentguard/attestationStatus"
    ] = attestation["status"]

    return copied


def all_tool_definitions() -> List[Dict[str, Any]]:
    return [
        _attested_tool_copy(item)
        for item in sorted(
            _TOOL_DEFINITIONS,
            key=lambda tool: tool["name"],
        )
    ]


def required_list_scopes(tool: Dict[str, Any]) -> List[str]:
    meta = tool.get("_meta", {}) or {}
    return normalize_scopes(meta.get("agentguard/requiredScopes", []))


def tool_definitions_for_scopes(scopes: Iterable[str]) -> List[Dict[str, Any]]:
    granted = set(normalize_scopes(scopes))

    if MCP_LIST_SCOPE not in granted:
        return []

    visible: List[Dict[str, Any]] = []

    for tool in all_tool_definitions():
        required = set(required_list_scopes(tool))
        if required.issubset(granted):
            visible.append(tool)

    return visible


def get_tool_definition(name: str) -> Dict[str, Any] | None:
    normalized = str(name or "")

    for tool in _TOOL_DEFINITIONS:
        if tool["name"] == normalized:
            return _attested_tool_copy(
                tool
            )

    return None


def _supported_oauth_scopes_without_revocation() -> List[str]:
    values = {
        MCP_LIST_SCOPE,
        MCP_TASK_SCOPE,
        MCP_APPROVAL_READ_SCOPE,
        MCP_APPROVAL_DECIDE_SCOPE,
    }

    for tool in _TOOL_DEFINITIONS:
        values.update(
            required_list_scopes(tool)
        )

    values.update(
        {
            "sink:external-email",
            "source:sensitive-file",
        }
    )

    return sorted(values)


AGENTGUARD_REVOCATION_READ_SCOPE = (
    "mcp:revocations:read"
)

AGENTGUARD_REVOCATION_WRITE_SCOPE = (
    "mcp:revocations:write"
)


def supported_oauth_scopes():
    """
    Return all existing OAuth scopes plus the trusted
    revocation-management scopes.
    """
    existing = list(
        _supported_oauth_scopes_without_revocation()
    )

    for scope in (
        AGENTGUARD_REVOCATION_READ_SCOPE,
        AGENTGUARD_REVOCATION_WRITE_SCOPE,
    ):
        if scope not in existing:
            existing.append(scope)

    return existing
