import copy

import pytest

import backend.mcp.tool_registry as tool_registry

from backend.mcp.service import (
    InsufficientScopeError,
    McpProtocolError,
    handle_mcp_request,
)


@pytest.fixture(autouse=True)
def clear_manifest_environment(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv(
        "AGENTGUARD_TOOL_MANIFEST_SHA256",
        raising=False,
    )

    monkeypatch.delenv(
        "AGENTGUARD_REQUIRE_TOOL_ATTESTATION",
        raising=False,
    )


def _principal(scopes):
    return {
        "sub": "alice",
        "client_id": "test-mcp-client",
        "scope": " ".join(scopes),
        "scopes": list(scopes),
    }


def test_mcp_initialize_advertises_tools_capability():
    result = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "test",
                    "version": "1",
                },
            },
        },
        principal=_principal([]),
    )

    assert (
        result["result"]["protocolVersion"]
        == "2025-11-25"
    )

    assert (
        "tools"
        in result["result"]["capabilities"]
    )

    assert (
        result["result"]["serverInfo"]["name"]
        == "agentguard-mcp-gateway"
    )

    attestation = result["result"][
        "_meta"
    ]["agentguard/toolManifest"]

    assert attestation["valid"] is True
    assert attestation["status"] == "unpinned"

    assert len(
        attestation["actual_digest"]
    ) == 64


def test_mcp_tools_list_uses_access_token_scopes():
    result = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
        principal=_principal(
            [
                "mcp:tools:list",
                "tool:file:read",
            ]
        ),
    )

    tools = result["result"]["tools"]

    names = [
        tool["name"]
        for tool in tools
    ]

    assert names == ["file.read"]

    tool_meta = tools[0]["_meta"]

    assert len(
        tool_meta[
            "agentguard/definitionDigest"
        ]
    ) == 64

    assert len(
        tool_meta[
            "agentguard/manifestDigest"
        ]
    ) == 64

    assert (
        tool_meta[
            "agentguard/attestationStatus"
        ]
        == "unpinned"
    )


def test_mcp_tools_list_requires_list_scope():
    with pytest.raises(
        InsufficientScopeError
    ) as captured:
        handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": {},
            },
            principal=_principal(
                ["tool:file:read"]
            ),
        )

    assert (
        captured.value.required_scopes
        == ["mcp:tools:list"]
    )


def test_mcp_tool_call_checks_dynamic_scopes_before_gateway_execution():
    with pytest.raises(
        InsufficientScopeError
    ) as captured:
        handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "email.send",
                    "arguments": {
                        "to": (
                            "outside@example.com"
                        ),
                        "content": (
                            "public report"
                        ),
                    },
                },
            },
            principal=_principal(
                [
                    "tool:email:send",
                    "sink:side-effect",
                ]
            ),
        )

    assert (
        captured.value.required_scopes
        == ["sink:external-email"]
    )


def test_manifest_pin_accepts_current_registry(
    monkeypatch: pytest.MonkeyPatch,
):
    digest = (
        tool_registry
        .tool_manifest_digest()
    )

    monkeypatch.setenv(
        "AGENTGUARD_TOOL_MANIFEST_SHA256",
        digest,
    )

    monkeypatch.setenv(
        "AGENTGUARD_REQUIRE_TOOL_ATTESTATION",
        "1",
    )

    result = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "initialize",
            "params": {},
        },
        principal=_principal([]),
    )

    attestation = result["result"][
        "_meta"
    ]["agentguard/toolManifest"]

    assert attestation["valid"] is True
    assert attestation["status"] == "verified"

    assert (
        attestation["expected_digest"]
        == digest
    )


def test_required_attestation_rejects_missing_pin(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "AGENTGUARD_REQUIRE_TOOL_ATTESTATION",
        "1",
    )

    with pytest.raises(
        McpProtocolError
    ) as captured:
        handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "initialize",
                "params": {},
            },
            principal=_principal([]),
        )

    assert captured.value.code == -32010

    attestation = captured.value.data[
        "toolManifest"
    ]

    assert (
        attestation["status"]
        == "missing_required_pin"
    )


def test_manifest_mismatch_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "AGENTGUARD_TOOL_MANIFEST_SHA256",
        "0" * 64,
    )

    with pytest.raises(
        McpProtocolError
    ) as captured:
        handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/list",
                "params": {},
            },
            principal=_principal(
                [
                    "mcp:tools:list",
                    "tool:file:read",
                ]
            ),
        )

    assert captured.value.code == -32010

    assert (
        captured.value.data[
            "toolManifest"
        ]["status"]
        == "mismatch"
    )


def test_runtime_tool_definition_tampering_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
):
    trusted_digest = (
        tool_registry
        .tool_manifest_digest()
    )

    tampered_definitions = copy.deepcopy(
        tool_registry._TOOL_DEFINITIONS
    )

    tampered_definitions[0][
        "description"
    ] = (
        tampered_definitions[0][
            "description"
        ]
        + " tampered"
    )

    monkeypatch.setattr(
        tool_registry,
        "_TOOL_DEFINITIONS",
        tampered_definitions,
    )

    monkeypatch.setenv(
        "AGENTGUARD_TOOL_MANIFEST_SHA256",
        trusted_digest,
    )

    with pytest.raises(
        McpProtocolError
    ) as captured:
        handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/list",
                "params": {},
            },
            principal=_principal(
                [
                    "mcp:tools:list",
                    "tool:file:read",
                ]
            ),
        )

    assert captured.value.code == -32010

    assert (
        captured.value.data[
            "toolManifest"
        ]["status"]
        == "mismatch"
    )



def test_mcp_ingress_rejects_oversized_body(
    monkeypatch,
):
    from fastapi.testclient import (
        TestClient,
    )

    from backend.main import app

    from backend.routes import (
        mcp_routes,
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_MAX_BODY_BYTES",
        "128",
    )

    mcp_routes._reset_mcp_ingress_state()

    client = TestClient(app)

    response = client.post(
        "/mcp",
        content=(
            b"x" * 512
        ),
        headers={
            "Authorization": (
                "Bearer test-token"
            ),
            "Content-Type": (
                "application/json"
            ),
        },
    )

    assert response.status_code == 413

    assert (
        response.json()["error"]
        == "request_too_large"
    )


def test_mcp_ingress_rate_limit(
    monkeypatch,
):
    from fastapi.testclient import (
        TestClient,
    )

    from backend.main import app

    from backend.routes import (
        mcp_routes,
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RATE_LIMIT_ENABLED",
        "1",
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RATE_LIMIT_REQUESTS",
        "1",
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RATE_LIMIT_WINDOW_SECONDS",
        "60",
    )

    mcp_routes._reset_mcp_ingress_state()

    monkeypatch.setattr(
        mcp_routes,
        "verify_access_token",
        lambda *args, **kwargs: {
            "valid": True,
            "payload": {
                "sub": (
                    "rate-limit-test"
                ),
                "client_id": (
                    "pytest-client"
                ),
                "scopes": [
                    "mcp:tools:list"
                ],
            },
        },
    )

    monkeypatch.setattr(
        mcp_routes,
        "handle_mcp_request",
        lambda payload, principal: {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {},
        },
    )

    client = TestClient(app)

    headers = {
        "Authorization": (
            "Bearer test-token"
        )
    }

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping",
    }

    first = client.post(
        "/mcp",
        json=body,
        headers=headers,
    )

    second = client.post(
        "/mcp",
        json=body,
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 429

    assert (
        second.json()["error"]
        == "rate_limit_exceeded"
    )

    mcp_routes._reset_mcp_ingress_state()


def test_mcp_concurrency_gate_fails_fast():
    from backend.routes.mcp_routes import (
        _ConcurrencyGate,
    )

    gate = _ConcurrencyGate()

    assert gate.try_acquire(1) is True
    assert gate.try_acquire(1) is False

    gate.release()

    assert gate.try_acquire(1) is True

    gate.release()



def _configure_idempotency_route_test(
    *,
    monkeypatch,
    tmp_path,
    handler,
):
    from backend.routes import (
        mcp_routes,
    )

    from backend.task_session import (
        task_store,
    )

    task_store.DATABASE_PATH = (
        tmp_path
        / "mcp-idempotency-test.db"
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_IDEMPOTENCY_REQUIRED",
        "1",
    )

    monkeypatch.setenv(
        "AGENTGUARD_MCP_RATE_LIMIT_ENABLED",
        "0",
    )

    mcp_routes._reset_mcp_ingress_state()

    monkeypatch.setattr(
        mcp_routes,
        "verify_access_token",
        lambda *args, **kwargs: {
            "valid": True,
            "payload": {
                "sub": (
                    "idempotency-owner"
                ),
                "client_id": (
                    "idempotency-client"
                ),
                "scopes": [
                    "mcp:tools:list"
                ],
            },
        },
    )

    monkeypatch.setattr(
        mcp_routes,
        "handle_mcp_request",
        handler,
    )

    return mcp_routes


def test_mcp_idempotency_replays_completed_response(
    monkeypatch,
    tmp_path,
):
    from fastapi.testclient import (
        TestClient,
    )

    from backend.main import app

    calls = {
        "count": 0
    }

    def handler(
        payload,
        *,
        principal,
    ):
        calls["count"] += 1

        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "executed": True,
                "call_count": (
                    calls["count"]
                ),
            },
        }

    _configure_idempotency_route_test(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        handler=handler,
    )

    client = TestClient(app)

    headers = {
        "Authorization": (
            "Bearer test-token"
        ),
        "Idempotency-Key": (
            "retry-safe-request-0001"
        ),
    }

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "email.send",
            "arguments": {
                "to": (
                    "user@example.com"
                ),
            },
        },
    }

    first = client.post(
        "/mcp",
        json=payload,
        headers=headers,
    )

    replay_payload = dict(payload)
    replay_payload["id"] = 2

    second = client.post(
        "/mcp",
        json=replay_payload,
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert calls["count"] == 1

    assert (
        second.headers[
            "x-agentguard-"
            "idempotent-replay"
        ]
        == "true"
    )

    assert (
        second.json()["id"]
        == 2
    )

    assert (
        second.json()["result"][
            "call_count"
        ]
        == 1
    )


def test_mcp_idempotency_key_reuse_conflict(
    monkeypatch,
    tmp_path,
):
    from fastapi.testclient import (
        TestClient,
    )

    from backend.main import app

    calls = {
        "count": 0
    }

    def handler(
        payload,
        *,
        principal,
    ):
        calls["count"] += 1

        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "executed": True
            },
        }

    _configure_idempotency_route_test(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        handler=handler,
    )

    client = TestClient(app)

    headers = {
        "Authorization": (
            "Bearer test-token"
        ),
        "Idempotency-Key": (
            "retry-safe-request-0002"
        ),
    }

    first_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "email.send",
            "arguments": {
                "to": "first@example.com"
            },
        },
    }

    changed_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "email.send",
            "arguments": {
                "to": (
                    "attacker@example.com"
                )
            },
        },
    }

    first = client.post(
        "/mcp",
        json=first_payload,
        headers=headers,
    )

    second = client.post(
        "/mcp",
        json=changed_payload,
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 409

    assert calls["count"] == 1

    assert (
        second.json()["error"]
        == "idempotency_conflict"
    )


def test_mcp_tools_call_requires_idempotency_key(
    monkeypatch,
    tmp_path,
):
    from fastapi.testclient import (
        TestClient,
    )

    from backend.main import app

    def handler(
        payload,
        *,
        principal,
    ):
        raise AssertionError(
            "Handler must not be called."
        )

    _configure_idempotency_route_test(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        handler=handler,
    )

    client = TestClient(app)

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "file.read",
                "arguments": {
                    "path": (
                        "public/notice.txt"
                    )
                },
            },
        },
        headers={
            "Authorization": (
                "Bearer test-token"
            ),
        },
    )

    assert response.status_code == 428

    assert (
        response.json()["error"]
        == "idempotency_key_required"
    )



def _task_binding_principal(
    *,
    client_id: str = "client-a",
    scopes=None,
):
    selected_scopes = list(
        scopes
        or [
            "mcp:tasks:manage",
            "tool:file:read",
        ]
    )

    return {
        "iss": (
            "https://issuer.example"
        ),
        "sub": "alice",
        "client_id": client_id,
        "aud": [
            "https://mcp.example"
        ],
        "scope": " ".join(
            selected_scopes
        ),
        "scopes": selected_scopes,
    }


def test_task_oauth_binding_allows_scope_reduction():
    from backend.mcp.service import (
        _assert_task_authorization_binding,
        _bind_task_session_authorization,
    )

    from backend.task_session.session_models import (
        TaskSession,
    )

    session = TaskSession(
        user="alice",
        original_input=(
            "读取公开通知"
        ),
        agent_type="mcp",
    )

    _bind_task_session_authorization(
        session=session,
        principal=(
            _task_binding_principal()
        ),
    )

    _assert_task_authorization_binding(
        session=session,
        principal=(
            _task_binding_principal(
                scopes=[
                    "mcp:tasks:manage"
                ],
            )
        ),
    )


def test_task_oauth_binding_rejects_different_client():
    from backend.mcp.service import (
        McpProtocolError,
        _assert_task_authorization_binding,
        _bind_task_session_authorization,
    )

    from backend.task_session.session_models import (
        TaskSession,
    )

    session = TaskSession(
        user="alice",
        original_input=(
            "读取公开通知"
        ),
        agent_type="mcp",
    )

    _bind_task_session_authorization(
        session=session,
        principal=(
            _task_binding_principal(
                client_id="client-a"
            )
        ),
    )

    with pytest.raises(
        McpProtocolError
    ) as captured:
        _assert_task_authorization_binding(
            session=session,
            principal=(
                _task_binding_principal(
                    client_id="client-b"
                )
            ),
        )

    assert captured.value.code == -32003

    assert (
        "client_id"
        in captured.value.message
    )


def test_task_oauth_binding_rejects_scope_expansion():
    from backend.mcp.service import (
        McpProtocolError,
        _assert_task_authorization_binding,
        _bind_task_session_authorization,
    )

    from backend.task_session.session_models import (
        TaskSession,
    )

    session = TaskSession(
        user="alice",
        original_input=(
            "读取公开通知"
        ),
        agent_type="mcp",
    )

    _bind_task_session_authorization(
        session=session,
        principal=(
            _task_binding_principal(
                scopes=[
                    "mcp:tasks:manage",
                    "tool:file:read",
                ],
            )
        ),
    )

    with pytest.raises(
        McpProtocolError
    ) as captured:
        _assert_task_authorization_binding(
            session=session,
            principal=(
                _task_binding_principal(
                    scopes=[
                        "mcp:tasks:manage",
                        "tool:file:read",
                        "tool:email:send",
                    ],
                )
            ),
        )

    assert captured.value.code == -32003

    assert (
        "tool:email:send"
        in captured.value.message
    )


def test_task_oauth_binding_detects_stored_tampering():
    from backend.mcp.service import (
        McpProtocolError,
        _assert_task_authorization_binding,
        _bind_task_session_authorization,
    )

    from backend.task_session.session_models import (
        TaskSession,
    )

    principal = (
        _task_binding_principal()
    )

    session = TaskSession(
        user="alice",
        original_input=(
            "读取公开通知"
        ),
        agent_type="mcp",
    )

    _bind_task_session_authorization(
        session=session,
        principal=principal,
    )

    session.oauth_authorization_binding[
        "client_id"
    ] = "tampered-client"

    with pytest.raises(
        McpProtocolError
    ) as captured:
        _assert_task_authorization_binding(
            session=session,
            principal=principal,
        )

    assert captured.value.code == -32003

    assert (
        "fingerprint"
        in captured.value.message.lower()
    )


def test_create_trusted_task_records_oauth_binding(
    monkeypatch,
):
    from backend.mcp import (
        service,
    )

    captured = {}

    def fake_create_session(
        session,
    ):
        captured["session"] = session

        return (
            "agt_oauth_binding_test",
            1,
        )

    monkeypatch.setattr(
        service,
        "create_session",
        fake_create_session,
    )

    result = (
        service._create_trusted_task(
            principal=(
                _task_binding_principal()
            ),
            params={
                "originalTask": (
                    "读取公开通知"
                )
            },
        )
    )

    session = captured["session"]

    assert (
        result["taskHandle"]
        == "agt_oauth_binding_test"
    )

    assert (
        session
        .oauth_authorization_binding[
            "client_id"
        ]
        == "client-a"
    )

    assert (
        session
        .oauth_authorization_fingerprint
        .startswith("sha256:")
    )


def test_prepare_proxy_request_rejects_task_client_takeover(
    monkeypatch,
):
    from backend.mcp import (
        service,
    )

    from backend.mcp.service import (
        McpProtocolError,
        _bind_task_session_authorization,
    )

    from backend.task_session.session_models import (
        TaskSession,
    )

    session = TaskSession(
        user="alice",
        original_input=(
            "读取公开通知"
        ),
        task_handle="agt_bound_task",
        agent_type="mcp",
    )

    _bind_task_session_authorization(
        session=session,
        principal=(
            _task_binding_principal(
                client_id="client-a"
            )
        ),
    )

    monkeypatch.setattr(
        service,
        "load_session",
        lambda **kwargs: (
            session,
            1,
        ),
    )

    with pytest.raises(
        McpProtocolError
    ) as captured:
        service._prepare_proxy_request(
            principal=(
                _task_binding_principal(
                    client_id="client-b"
                )
            ),
            name="file.read",
            arguments={
                "path": (
                    "public/notice.txt"
                )
            },
            meta={
                "agentguard/taskHandle": (
                    "agt_bound_task"
                )
            },
        )

    assert captured.value.code == -32003
