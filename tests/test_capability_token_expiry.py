from backend.guardrails.capability_token import (
    issue_capability_token,
    validate_capability_token_for_request,
)
from backend.guardrails.task_boundary_guard import build_capability_contract


def test_expired_capability_token_is_denied():
    original_task = "请读取 public/notice.txt 并总结"
    contract = build_capability_contract(original_task)

    token_info = issue_capability_token(
        user="user",
        agent_platform="openclaw",
        original_task=original_task,
        capability_contract=contract,
        tool="file.read",
        params={"path": "public/notice.txt"},
        ttl_minutes=-1,
    )

    result = validate_capability_token_for_request(
        token=token_info["token"],
        user="user",
        agent_platform="openclaw",
        original_task=original_task,
        expected_contract=contract,
        tool="file.read",
        params={"path": "public/notice.txt"},
        require_token=True,
    )

    assert result["decision"] == "deny"
    assert result["risk_delta"] == 100
    assert "expired" in " ".join(result["reason"]).lower()
