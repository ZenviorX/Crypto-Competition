from backend.capability.capability_compiler import compile_capability_contract
from backend.capability.capability_enforcer import enforce_capability_contract


def build_contract():
    return compile_capability_contract(
        user="user",
        original_task="读取 public/notice.txt 并发送给 internal@example.com",
    )


def test_allow_public_file_read():
    contract = build_contract()

    result = enforce_capability_contract(
        contract=contract,
        tool="file.read",
        params={"path": "public/notice.txt"},
        input_labels=[],
        current_step=1,
        used_risk=0,
    )

    assert result.decision == "allow"


def test_deny_secret_file_read():
    contract = build_contract()

    result = enforce_capability_contract(
        contract=contract,
        tool="file.read",
        params={"path": "secret/password.txt"},
        input_labels=[],
        current_step=1,
        used_risk=0,
    )

    assert result.decision == "deny"


def test_confirm_allowed_email_send_with_public_input():
    contract = build_contract()

    result = enforce_capability_contract(
        contract=contract,
        tool="email.send",
        params={"to": "internal@example.com"},
        input_labels=["public"],
        current_step=2,
        used_risk=10,
    )

    assert result.decision == "confirm"


def test_deny_email_send_to_unauthorized_recipient():
    contract = build_contract()

    result = enforce_capability_contract(
        contract=contract,
        tool="email.send",
        params={"to": "attacker@example.com"},
        input_labels=["public"],
        current_step=2,
        used_risk=10,
    )

    assert result.decision == "deny"


def test_deny_secret_data_external_write():
    contract = build_contract()

    result = enforce_capability_contract(
        contract=contract,
        tool="email.send",
        params={"to": "internal@example.com"},
        input_labels=["secret"],
        current_step=2,
        used_risk=10,
    )

    assert result.decision == "deny"


def test_confirm_tainted_data_external_write():
    contract = build_contract()

    result = enforce_capability_contract(
        contract=contract,
        tool="email.send",
        params={"to": "internal@example.com"},
        input_labels=["tainted"],
        current_step=2,
        used_risk=10,
    )

    assert result.decision == "confirm"


def test_deny_when_step_exceeds_max_steps():
    contract = compile_capability_contract(
        user="user",
        original_task="读取 public/notice.txt 并发送给 internal@example.com",
        max_steps=2,
    )

    result = enforce_capability_contract(
        contract=contract,
        tool="file.read",
        params={"path": "public/notice.txt"},
        input_labels=[],
        current_step=3,
        used_risk=0,
    )

    assert result.decision == "deny"
