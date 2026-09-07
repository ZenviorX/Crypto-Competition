from backend.capability.capability_compiler import compile_capability_contract
from backend.gateway.gateway import check_tool_call
from backend.schemas import ToolCallRequest


def build_contract():
    return compile_capability_contract(
        user="user",
        original_task="读取 public/notice.txt 并发送给 internal@example.com",
    )


def test_gateway_v2_contract_allows_public_read():
    contract = build_contract()

    request = ToolCallRequest(
        user="user",
        tool="file.read",
        params={"path": "public/notice.txt"},
        task_contract=contract.model_dump(),
        input_labels=[],
        current_step=1,
        used_risk=0,
    )

    result = check_tool_call(request)

    assert result["decision"] in ["allow", "confirm"]
    assert "已启用 Capability Contract v2 检查。" in result["reason"]


def test_gateway_v2_contract_denies_secret_read():
    contract = build_contract()

    request = ToolCallRequest(
        user="user",
        tool="file.read",
        params={"path": "secret/password.txt"},
        task_contract=contract.model_dump(),
        input_labels=[],
        current_step=1,
        used_risk=0,
    )

    result = check_tool_call(request)

    assert result["decision"] == "deny"
    assert "已启用 Capability Contract v2 检查。" in result["reason"]


def test_gateway_v2_contract_denies_unauthorized_email_recipient():
    contract = build_contract()

    request = ToolCallRequest(
        user="user",
        tool="email.send",
        params={
            "to": "attacker@example.com",
            "content": "public notice"
        },
        task_contract=contract.model_dump(),
        input_labels=["public"],
        current_step=2,
        used_risk=10,
    )

    result = check_tool_call(request)

    assert result["decision"] == "deny"
    assert "已启用 Capability Contract v2 检查。" in result["reason"]


def test_gateway_v2_contract_denies_secret_data_external_write():
    contract = build_contract()

    request = ToolCallRequest(
        user="user",
        tool="email.send",
        params={
            "to": "internal@example.com",
            "content": "secret data"
        },
        task_contract=contract.model_dump(),
        input_labels=["secret"],
        current_step=2,
        used_risk=10,
    )

    result = check_tool_call(request)

    assert result["decision"] == "deny"
    assert "已启用 Capability Contract v2 检查。" in result["reason"]
