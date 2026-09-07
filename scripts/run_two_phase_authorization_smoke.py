from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.guardrails.capability_token_ledger import get_token_status, reset_token_ledger
from backend.guardrails.capability_token import verify_capability_token
from backend.proxy.proxy_models import ToolProxyAuthorizeRequest
from backend.proxy.two_phase_tool_proxy_service import (
    execute_tool_with_capability,
    prepare_tool_authorization,
)


def _request(capability_token: str = "") -> ToolProxyAuthorizeRequest:
    return ToolProxyAuthorizeRequest(
        user="user",
        original_task="请读取 public/notice.txt 并总结",
        tool="file.read",
        params={"path": "public/notice.txt"},
        requested_scopes=["tool:file:read"],
        oauth_token_claims={"scope": "tool:file:read"},
        auth_mode="oauth_scope",
        agent_platform="openclaw",
        sandbox_profile="local_readonly",
        execute=False,
        capability_token=capability_token,
    )


def main() -> None:
    reset_token_ledger()

    print("=== AgentGuard Two-Phase Authorization Smoke Test ===")

    phase1 = prepare_tool_authorization(_request())

    print("\n[Phase 1] prepare")
    print("decision:", phase1.decision)
    print("executed:", phase1.executed)
    print("token issued:", phase1.capability_token.get("issued"))

    token = phase1.capability_token["token"]
    verified = verify_capability_token(token)
    token_id = verified["payload"]["token_id"]

    print("token id:", token_id)
    print("ledger status:", get_token_status(token_id)["status"])

    phase2 = execute_tool_with_capability(_request(capability_token=token))

    print("\n[Phase 2] execute with valid token")
    print("decision:", phase2.decision)
    print("executed:", phase2.executed)
    print("ledger status:", get_token_status(token_id)["status"])

    replay = execute_tool_with_capability(_request(capability_token=token))

    print("\n[Phase 3] replay same token")
    print("decision:", replay.decision)
    print("executed:", replay.executed)

    token_stage = next(
        item for item in replay.authorization_trace
        if item["stage"] == "capability_token"
    )

    print("block stage:", token_stage["stage"])
    print("ledger status:", token_stage["extra"].get("ledger_status"))
    print("reason:", " | ".join(token_stage["reason"]))

    print("\n=== Smoke Test Finished ===")


if __name__ == "__main__":
    main()
