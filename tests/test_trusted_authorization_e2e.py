from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import (
    serialization,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from starlette.requests import Request

import backend.audit.trusted_audit_store as audit_store
import backend.proxy.tool_proxy_service as proxy_service
import backend.revocation.revocation_store as revocation_store
import backend.routes.trusted_audit_routes as trusted_routes

from backend.audit.trusted_audit_store import (
    get_trusted_audit_events,
    verify_trusted_audit_chain,
)
from backend.capability.capability_contract import (
    CapabilityCheckResult,
)
from backend.evidence.evidence_bundle import (
    build_task_evidence_bundle,
    verify_task_evidence_bundle,
)
from backend.mcp.service import (
    handle_mcp_request,
)
from backend.mcp.tool_registry import (
    supported_oauth_scopes,
)
from backend.runtime.task_state import (
    RuntimeStepRecord,
)
from backend.routes.security_overview_routes import (
    task_security_overview,
)
from backend.task_session.task_store import (
    connect,
    create_data_reference,
    get_approval_ticket,
    load_session,
)


class TrustedAuthorizationEndToEndTest(
    unittest.TestCase
):
    def setUp(self):
        self.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        temporary_path = Path(
            self.temporary_directory.name
        )

        evidence_environment_names = [
            (
                "AGENTGUARD_"
                "AUDIT_SIGNING_PRIVATE_KEY_PEM"
            ),
            (
                "AGENTGUARD_"
                "AUDIT_SIGNING_PUBLIC_KEY_PEM"
            ),
            (
                "AGENTGUARD_"
                "AUDIT_SIGNING_KEY_ID"
            ),
        ]

        self.original_evidence_environment = {
            name: os.environ.get(name)
            for name in evidence_environment_names
        }

        evidence_private_key = (
            Ed25519PrivateKey.generate()
        )

        evidence_public_key = (
            evidence_private_key.public_key()
        )

        os.environ[
            "AGENTGUARD_"
            "AUDIT_SIGNING_PRIVATE_KEY_PEM"
        ] = evidence_private_key.private_bytes(
            encoding=(
                serialization.Encoding.PEM
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

        os.environ[
            "AGENTGUARD_"
            "AUDIT_SIGNING_PUBLIC_KEY_PEM"
        ] = evidence_public_key.public_bytes(
            encoding=(
                serialization.Encoding.PEM
            ),
            format=(
                serialization
                .PublicFormat
                .SubjectPublicKeyInfo
            ),
        ).decode("utf-8")

        os.environ[
            "AGENTGUARD_"
            "AUDIT_SIGNING_KEY_ID"
        ] = (
            "trusted-e2e-evidence-key"
        )

        self.original_audit_db_path = (
            audit_store.AUDIT_DB_PATH
        )

        self.original_revocation_db_path = (
            revocation_store
            .REVOCATION_DB_PATH
        )

        audit_store.AUDIT_DB_PATH = (
            temporary_path
            / "trusted-e2e-audit.db"
        )

        revocation_store.REVOCATION_DB_PATH = (
            temporary_path
            / "trusted-e2e-revocation.db"
        )

        self.original_runtime_step = (
            proxy_service.run_runtime_step
        )

        self.original_sandbox = (
            proxy_service
            .execute_tool_in_real_sandbox
        )

        self.original_write_log = (
            proxy_service.write_log
        )

        self.original_verify_token = (
            trusted_routes
            .verify_access_token
        )

        self.runtime_calls = []
        self.sandbox_calls = []
        self.task_handle = ""

        def fake_runtime_step(
            *,
            state,
            tool,
            params,
            input_labels=None,
            output_content=None,
            input_from_steps=None,
        ):
            self.runtime_calls.append(
                {
                    "tool": tool,
                    "params": dict(
                        params or {}
                    ),
                }
            )

            step_index = (
                state.current_step
                + 1
            )

            record = RuntimeStepRecord(
                step_index=step_index,
                tool=tool,
                params=dict(
                    params or {}
                ),
                input_from_steps=list(
                    input_from_steps
                    or []
                ),
                input_labels=list(
                    input_labels
                    or []
                ),
                output_labels=[],
                label_sources={},
                decision="confirm",
                risk_score=40,
                reason=[
                    (
                        "Human approval "
                        "is required."
                    )
                ],
                executed=False,
                blocked=False,
                requires_confirmation=True,
                confirmed=False,
                confirmation_status=(
                    "pending"
                ),
            )

            state.steps.append(
                record
            )

            state.current_step = (
                step_index
            )

            state.used_risk += 40
            state.final_decision = (
                "confirm"
            )

            if (
                step_index
                not in state
                .pending_confirm_steps
            ):
                state.pending_confirm_steps.append(
                    step_index
                )

            return CapabilityCheckResult(
                decision="confirm",
                risk_score=40,
                reason=[
                    (
                        "Human approval "
                        "is required."
                    )
                ],
            )

        def fake_sandbox(
            *,
            tool,
            params,
            profile_name,
            prefer,
        ):
            self.sandbox_calls.append(
                {
                    "tool": tool,
                    "params": dict(
                        params
                    ),
                }
            )

            return {
                "success": True,
                "tool_result": {
                    "success": True,
                    "result": (
                        "email sent"
                    ),
                },
                "sandbox_evidence": {
                    "executed": True,
                    "run_id": (
                        "trusted-e2e-run"
                    ),
                    "engine": (
                        "test-double"
                    ),
                },
            }

        def fake_verify_token(
            token,
            *,
            expected_audience,
            expected_issuer,
        ):
            principals = {
                "owner-token": {
                    "sub": (
                        "trusted-e2e-owner"
                    ),
                    "client_id": (
                        "task-agent"
                    ),
                    "scopes": [
                        "mcp:tasks:manage",
                        "tool:email:send",
                        "sink:side-effect",
                        "sink:external-email",
                    ],
                },
                "reviewer-token": {
                    "sub": (
                        "trusted-e2e-reviewer"
                    ),
                    "client_id": (
                        "review-console"
                    ),
                    "scopes": [
                        "mcp:approvals:read",
                        "mcp:approvals:decide",
                    ],
                },
                "admin-token": {
                    "sub": (
                        "trusted-e2e-admin"
                    ),
                    "client_id": (
                        "security-console"
                    ),
                    "scopes": [
                        "mcp:revocations:read",
                        "mcp:revocations:write",
                        "mcp:approvals:read",
                    ],
                },
            }

            principal = (
                principals.get(token)
            )

            if principal is None:
                return {
                    "valid": False,
                    "reason": (
                        "Invalid test token."
                    ),
                }

            return {
                "valid": True,
                "payload": principal,
            }

        proxy_service.run_runtime_step = (
            fake_runtime_step
        )

        proxy_service.execute_tool_in_real_sandbox = (
            fake_sandbox
        )

        # ???? JSONL ????????????
        proxy_service.write_log = (
            lambda **kwargs: None
        )

        trusted_routes.verify_access_token = (
            fake_verify_token
        )

        self.owner = {
            "sub": (
                "trusted-e2e-owner"
            ),
            "client_id": "task-agent",
            "scopes": [
                "mcp:tasks:manage",
                "tool:email:send",
                "sink:side-effect",
                "sink:external-email",
            ],
        }

        self.reviewer = {
            "sub": (
                "trusted-e2e-reviewer"
            ),
            "client_id": (
                "review-console"
            ),
            "scopes": [
                "mcp:approvals:read",
                "mcp:approvals:decide",
            ],
        }

        self.admin = {
            "sub": (
                "trusted-e2e-admin"
            ),
            "client_id": (
                "security-console"
            ),
            "scopes": [
                "mcp:revocations:read",
                "mcp:revocations:write",
                "mcp:approvals:read",
            ],
        }

    def tearDown(self):
        proxy_service.run_runtime_step = (
            self.original_runtime_step
        )

        proxy_service.execute_tool_in_real_sandbox = (
            self.original_sandbox
        )

        proxy_service.write_log = (
            self.original_write_log
        )

        trusted_routes.verify_access_token = (
            self.original_verify_token
        )

        for (
            name,
            original_value,
        ) in self.original_evidence_environment.items():
            if original_value is None:
                os.environ.pop(
                    name,
                    None,
                )
            else:
                os.environ[name] = (
                    original_value
                )

        if self.task_handle:
            connection = connect()

            try:
                connection.execute(
                    """
                    DELETE FROM
                    trusted_task_sessions
                    WHERE task_handle = ?
                    """,
                    (
                        self.task_handle,
                    ),
                )

                connection.commit()

            finally:
                connection.close()

        audit_store.AUDIT_DB_PATH = (
            self.original_audit_db_path
        )

        revocation_store.REVOCATION_DB_PATH = (
            self.original_revocation_db_path
        )

        self.temporary_directory.cleanup()

    @staticmethod
    def _request(
        token: str,
    ) -> Request:
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [
                    (
                        b"authorization",
                        (
                            "Bearer "
                            + token
                        ).encode(
                            "utf-8"
                        ),
                    ),
                ],
                "query_string": b"",
                "server": (
                    "127.0.0.1",
                    8000,
                ),
                "client": (
                    "127.0.0.1",
                    50000,
                ),
                "scheme": "http",
            }
        )

    @staticmethod
    def _structured_result(
        response,
    ):
        return response[
            "result"
        ]["structuredContent"]

    def test_complete_trusted_authorization_chain(
        self,
    ):
        # ====================================================
        # 1. ?????????
        # ====================================================

        create_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": (
                        "agentguard/"
                        "tasks/create"
                    ),
                    "params": {
                        "originalTask": (
                            "Send the reviewed "
                            "public result to "
                            "external@example.com."
                        ),
                    },
                },
                principal=self.owner,
            )
        )

        self.task_handle = (
            create_response[
                "result"
            ]["taskHandle"]
        )

        self.assertTrue(
            self.task_handle.startswith(
                "agt_"
            )
        )

        # ====================================================
        # 2. ????????? data_ref
        # ====================================================

        original_data_ref = (
            create_data_reference(
                task_handle=(
                    self.task_handle
                ),
                user=(
                    "trusted-e2e-owner"
                ),
                step_index=10,
                labels=[
                    "public",
                ],
            )
        )

        replacement_data_ref = (
            create_data_reference(
                task_handle=(
                    self.task_handle
                ),
                user=(
                    "trusted-e2e-owner"
                ),
                step_index=11,
                labels=[
                    "public",
                ],
            )
        )

        original_arguments = {
            "to": (
                "external@example.com"
            ),
            "subject": (
                "Reviewed result"
            ),
            "content": (
                "Forward the referenced "
                "public output."
            ),
        }

        # ====================================================
        # 3. ???????????????????
        # ====================================================

        confirm_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": (
                        "tools/call"
                    ),
                    "params": {
                        "name": (
                            "email.send"
                        ),
                        "arguments": (
                            original_arguments
                        ),
                        "_meta": {
                            (
                                "agentguard/"
                                "taskHandle"
                            ): (
                                self.task_handle
                            ),
                            (
                                "agentguard/"
                                "dataRefs"
                            ): [
                                original_data_ref,
                            ],
                            (
                                "agentguard/"
                                "inputLabels"
                            ): [
                                "safe",
                            ],
                            (
                                "agentguard/"
                                "inputFromSteps"
                            ): [
                                999,
                            ],
                            (
                                "agentguard/"
                                "agentConfidence"
                            ): 0.01,
                        },
                    },
                },
                principal=self.owner,
            )
        )

        confirm_result = (
            self._structured_result(
                confirm_response
            )
        )

        self.assertEqual(
            confirm_result[
                "decision"
            ],
            "confirm",
        )

        self.assertFalse(
            confirm_result[
                "executed"
            ]
        )

        approval_ticket = (
            confirm_result[
                "approval_ticket"
            ]
        )

        self.assertTrue(
            approval_ticket.startswith(
                "aga_"
            )
        )

        self.assertEqual(
            len(self.runtime_calls),
            1,
        )

        self.assertEqual(
            len(self.sandbox_calls),
            0,
        )

        session, version = (
            load_session(
                task_handle=(
                    self.task_handle
                ),
                expected_user=(
                    "trusted-e2e-owner"
                ),
            )
        )

        self.assertEqual(
            version,
            2,
        )

        steps = session.runtime_state[
            "steps"
        ]

        self.assertEqual(
            len(steps),
            1,
        )

        self.assertEqual(
            steps[0][
                "input_from_steps"
            ],
            [10],
        )

        self.assertEqual(
            steps[0][
                "input_labels"
            ],
            ["public"],
        )

        self.assertNotIn(
            999,
            steps[0][
                "input_from_steps"
            ],
        )

        self.assertNotIn(
            "safe",
            steps[0][
                "input_labels"
            ],
        )

        # ====================================================
        # 4. ???????
        # ====================================================

        approve_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": (
                        "agentguard/"
                        "approvals/decide"
                    ),
                    "params": {
                        "approvalTicket": (
                            approval_ticket
                        ),
                        "taskHandle": (
                            self.task_handle
                        ),
                        "decision": (
                            "approve"
                        ),
                    },
                },
                principal=self.reviewer,
            )
        )

        self.assertEqual(
            approve_response[
                "result"
            ]["status"],
            "approved",
        )

        # ====================================================
        # 5. ?????????????
        # ====================================================

        changed_params_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": (
                        "tools/call"
                    ),
                    "params": {
                        "name": (
                            "email.send"
                        ),
                        "arguments": {
                            **original_arguments,
                            "to": (
                                "attacker@example.com"
                            ),
                        },
                        "_meta": {
                            (
                                "agentguard/"
                                "taskHandle"
                            ): (
                                self.task_handle
                            ),
                            (
                                "agentguard/"
                                "dataRefs"
                            ): [
                                original_data_ref,
                            ],
                            (
                                "agentguard/"
                                "approvalTicket"
                            ): (
                                approval_ticket
                            ),
                        },
                    },
                },
                principal=self.owner,
            )
        )

        changed_params_result = (
            self._structured_result(
                changed_params_response
            )
        )

        self.assertEqual(
            changed_params_result[
                "decision"
            ],
            "deny",
        )

        self.assertEqual(
            len(self.sandbox_calls),
            0,
        )

        # ====================================================
        # 6. ?? data_ref ?????????
        # ====================================================

        changed_ref_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": (
                        "tools/call"
                    ),
                    "params": {
                        "name": (
                            "email.send"
                        ),
                        "arguments": (
                            original_arguments
                        ),
                        "_meta": {
                            (
                                "agentguard/"
                                "taskHandle"
                            ): (
                                self.task_handle
                            ),
                            (
                                "agentguard/"
                                "dataRefs"
                            ): [
                                replacement_data_ref,
                            ],
                            (
                                "agentguard/"
                                "approvalTicket"
                            ): (
                                approval_ticket
                            ),
                        },
                    },
                },
                principal=self.owner,
            )
        )

        changed_ref_result = (
            self._structured_result(
                changed_ref_response
            )
        )

        self.assertEqual(
            changed_ref_result[
                "decision"
            ],
            "deny",
        )

        self.assertEqual(
            len(self.sandbox_calls),
            0,
        )

        # ====================================================
        # 7. ????????????
        # ====================================================

        valid_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": (
                        "tools/call"
                    ),
                    "params": {
                        "name": (
                            "email.send"
                        ),
                        "arguments": (
                            original_arguments
                        ),
                        "_meta": {
                            (
                                "agentguard/"
                                "taskHandle"
                            ): (
                                self.task_handle
                            ),
                            (
                                "agentguard/"
                                "dataRefs"
                            ): [
                                original_data_ref,
                            ],
                            (
                                "agentguard/"
                                "approvalTicket"
                            ): (
                                approval_ticket
                            ),
                        },
                    },
                },
                principal=self.owner,
            )
        )

        valid_result = (
            self._structured_result(
                valid_response
            )
        )

        self.assertEqual(
            valid_result[
                "decision"
            ],
            "allow",
        )

        self.assertTrue(
            valid_result[
                "executed"
            ]
        )

        self.assertEqual(
            valid_result[
                "approval_status"
            ],
            "consumed",
        )

        self.assertEqual(
            len(self.sandbox_calls),
            1,
        )

        replay_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": (
                        "tools/call"
                    ),
                    "params": {
                        "name": (
                            "email.send"
                        ),
                        "arguments": (
                            original_arguments
                        ),
                        "_meta": {
                            (
                                "agentguard/"
                                "taskHandle"
                            ): (
                                self.task_handle
                            ),
                            (
                                "agentguard/"
                                "dataRefs"
                            ): [
                                original_data_ref,
                            ],
                            (
                                "agentguard/"
                                "approvalTicket"
                            ): (
                                approval_ticket
                            ),
                        },
                    },
                },
                principal=self.owner,
            )
        )

        replay_result = (
            self._structured_result(
                replay_response
            )
        )

        self.assertEqual(
            replay_result[
                "decision"
            ],
            "deny",
        )

        self.assertEqual(
            len(self.sandbox_calls),
            1,
        )

        ticket_record = (
            get_approval_ticket(
                approval_ticket=(
                    approval_ticket
                ),
                expected_task_handle=(
                    self.task_handle
                ),
                expected_user=(
                    "trusted-e2e-owner"
                ),
            )
        )

        self.assertEqual(
            ticket_record["status"],
            "consumed",
        )

        # ====================================================
        # 8. ???????????????????
        # ====================================================

        private_capability_token = (
            "agc_trusted_e2e_private_token"
        )

        capability_revoke_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": (
                        "agentguard/"
                        "revocations/"
                        "capability/revoke"
                    ),
                    "params": {
                        "taskHandle": (
                            self.task_handle
                        ),
                        "capabilityToken": (
                            private_capability_token
                        ),
                        "reason": (
                            "Unused capability "
                            "token cancelled."
                        ),
                    },
                },
                principal=self.owner,
            )
        )

        self.assertEqual(
            capability_revoke_response[
                "result"
            ]["status"],
            "revoked",
        )

        task_revoke_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": (
                        "agentguard/"
                        "revocations/"
                        "task/revoke"
                    ),
                    "params": {
                        "taskHandle": (
                            self.task_handle
                        ),
                        "reason": (
                            "Emergency task "
                            "shutdown."
                        ),
                    },
                },
                principal=self.admin,
            )
        )

        self.assertEqual(
            task_revoke_response[
                "result"
            ]["status"],
            "revoked",
        )

        revocation_list_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": (
                        "agentguard/"
                        "revocations/list"
                    ),
                    "params": {
                        "taskHandle": (
                            self.task_handle
                        ),
                    },
                },
                principal=self.admin,
            )
        )

        self.assertEqual(
            revocation_list_response[
                "result"
            ]["revocation_count"],
            2,
        )

        # ====================================================
        # 9. ????????? Runtime ???????
        # ====================================================

        revoked_response = (
            handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": (
                        "tools/call"
                    ),
                    "params": {
                        "name": (
                            "email.send"
                        ),
                        "arguments": {
                            "to": (
                                "external@example.com"
                            ),
                            "subject": (
                                "Blocked"
                            ),
                            "content": (
                                "This must not run."
                            ),
                        },
                        "_meta": {
                            (
                                "agentguard/"
                                "taskHandle"
                            ): (
                                self.task_handle
                            ),
                        },
                    },
                },
                principal=self.owner,
            )
        )

        revoked_result = (
            self._structured_result(
                revoked_response
            )
        )

        self.assertEqual(
            revoked_result[
                "decision"
            ],
            "deny",
        )

        self.assertFalse(
            revoked_result[
                "executed"
            ]
        )

        self.assertEqual(
            len(self.runtime_calls),
            1,
        )

        self.assertEqual(
            len(self.sandbox_calls),
            1,
        )

        # ====================================================
        # 10. ??????????????????
        # ====================================================

        chain_result = (
            verify_trusted_audit_chain()
        )

        self.assertTrue(
            chain_result["valid"]
        )

        events = (
            get_trusted_audit_events(
                task_handle=(
                    self.task_handle
                ),
                limit=1000,
            )
        )

        stored_evidence_text = (
            repr(events)
        )

        self.assertNotIn(
            approval_ticket,
            stored_evidence_text,
        )

        self.assertNotIn(
            private_capability_token,
            stored_evidence_text,
        )

        evidence_bundle = (
            build_task_evidence_bundle(
                task_handle=(
                    self.task_handle
                ),
                expected_user=(
                    "trusted-e2e-owner"
                ),
            )
        )

        evidence_result = (
            verify_task_evidence_bundle(
                evidence_bundle
            )
        )

        self.assertTrue(
            evidence_result["valid"]
        )

        self.assertTrue(
            evidence_result[
                "bundle_signature_valid"
            ]
        )

        self.assertTrue(
            evidence_result[
                "bundle_signature_present"
            ]
        )

        self.assertIn(
            "bundle_signature",
            evidence_bundle,
        )

        # 模拟攻击者修改证据内容后，
        # 主动重新计算 bundle_hash。
        # 普通哈希检查会通过，但旧签名无法伪造。
        tampered_bundle = copy.deepcopy(
            evidence_bundle
        )

        tampered_bundle["task"][
            "task_version"
        ] = (
            int(
                tampered_bundle[
                    "task"
                ]["task_version"]
            )
            + 1
        )

        unsigned_body = dict(
            tampered_bundle
        )

        unsigned_body.pop(
            "bundle_signature",
            None,
        )

        unsigned_body.pop(
            "bundle_hash",
            None,
        )

        tampered_bundle[
            "bundle_hash"
        ] = hashlib.sha256(
            json.dumps(
                unsigned_body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        tampered_result = (
            verify_task_evidence_bundle(
                tampered_bundle,
                require_signature=True,
            )
        )

        self.assertTrue(
            tampered_result[
                "bundle_hash_valid"
            ]
        )

        self.assertFalse(
            tampered_result[
                "bundle_signature_valid"
            ]
        )

        self.assertFalse(
            tampered_result["valid"]
        )

        unsigned_bundle = copy.deepcopy(
            evidence_bundle
        )

        unsigned_bundle.pop(
            "bundle_signature",
            None,
        )

        unsigned_result = (
            verify_task_evidence_bundle(
                unsigned_bundle,
                require_signature=True,
            )
        )

        self.assertTrue(
            unsigned_result[
                "bundle_hash_valid"
            ]
        )

        self.assertFalse(
            unsigned_result[
                "bundle_signature_present"
            ]
        )

        self.assertFalse(
            unsigned_result["valid"]
        )

        self.assertNotIn(
            approval_ticket,
            repr(evidence_bundle),
        )

        self.assertNotIn(
            private_capability_token,
            repr(evidence_bundle),
        )

        # ====================================================
        # 11. ?????????? revoked
        # ====================================================

        overview_response = (
            task_security_overview(
                task_handle=(
                    self.task_handle
                ),
                request=self._request(
                    "owner-token"
                ),
            )
        )

        overview = json.loads(
            overview_response.body
        )

        self.assertEqual(
            overview["overall"][
                "status"
            ],
            "revoked",
        )

        self.assertTrue(
            overview[
                "revocations"
            ]["task_revoked"]
        )

        self.assertEqual(
            overview[
                "revocations"
            ]["revocation_count"],
            2,
        )

        self.assertTrue(
            overview["audit"][
                "chain_integrity"
            ]["valid"]
        )

        self.assertTrue(
            overview[
                "decision_snapshots"
            ]["all_snapshots_valid"]
        )

        self.assertTrue(
            overview[
                "evidence"
            ]["valid"]
        )

        self.assertEqual(
            overview["approvals"][
                "consumed"
            ],
            1,
        )

        self.assertEqual(
            overview["approvals"][
                "pending"
            ],
            0,
        )

        # ====================================================
        # 12. ???????????????????
        # ====================================================

        final_session, final_version = (
            load_session(
                task_handle=(
                    self.task_handle
                ),
                expected_user=(
                    "trusted-e2e-owner"
                ),
            )
        )

        self.assertEqual(
            final_version,
            3,
        )

        final_steps = (
            final_session
            .runtime_state["steps"]
        )

        self.assertEqual(
            len(final_steps),
            1,
        )

        self.assertEqual(
            final_steps[0][
                "decision"
            ],
            "allow",
        )

        self.assertTrue(
            final_steps[0][
                "confirmed"
            ]
        )

        self.assertTrue(
            final_steps[0][
                "executed"
            ]
        )

        # ====================================================
        # 13. OAuth ?? scopes ?????
        # ====================================================

        scopes = (
            supported_oauth_scopes()
        )

        self.assertIn(
            "mcp:revocations:read",
            scopes,
        )

        self.assertIn(
            "mcp:revocations:write",
            scopes,
        )

        print(
            "task_handle:",
            self.task_handle,
        )
        print(
            "trusted_lineage_verified:",
            True,
        )
        print(
            "changed_params_decision:",
            changed_params_result[
                "decision"
            ],
        )
        print(
            "changed_data_ref_decision:",
            changed_ref_result[
                "decision"
            ],
        )
        print(
            "approval_status:",
            ticket_record["status"],
        )
        print(
            "replay_decision:",
            replay_result[
                "decision"
            ],
        )
        print(
            "revoked_task_decision:",
            revoked_result[
                "decision"
            ],
        )
        print(
            "runtime_call_count:",
            len(self.runtime_calls),
        )
        print(
            "sandbox_call_count:",
            len(self.sandbox_calls),
        )
        print(
            "audit_chain_valid:",
            chain_result["valid"],
        )
        print(
            "evidence_bundle_valid:",
            evidence_result[
                "valid"
            ],
        )
        print(
            "security_overview_status:",
            overview["overall"][
                "status"
            ],
        )
        print(
            "raw_sensitive_identifiers_absent:",
            True,
        )
        print(
            "trusted_authorization_e2e: verified"
        )


if __name__ == "__main__":
    unittest.main()
