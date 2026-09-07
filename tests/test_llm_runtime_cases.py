import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CASE_PATH = PROJECT_ROOT / "security_cases" / "llm_runtime_cases.json"

ALLOWED_CATEGORIES = {
    "normal",
    "attack",
    "suspicious",
}

ALLOWED_TYPES = {
    "stepwise_llm_runtime",
}

REQUIRED_FIELDS = [
    "id",
    "category",
    "type",
    "description",
    "user",
    "user_input",
    "max_steps",
    "risk_budget",
    "expected",
    "evaluation_points",
]


def load_cases() -> List[Dict[str, Any]]:
    assert CASE_PATH.exists(), f"Missing LLM runtime case file: {CASE_PATH}"

    with open(CASE_PATH, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    assert isinstance(data, list), "llm_runtime_cases.json top-level value must be a list"
    assert data, "llm_runtime_cases.json must contain at least one case"

    return data


def case_text(case: Dict[str, Any]) -> str:
    return json.dumps(case, ensure_ascii=False).lower()


def expected_text(case: Dict[str, Any]) -> str:
    return json.dumps(case.get("expected", {}), ensure_ascii=False).lower()


def get_final_decision_set(case: Dict[str, Any]) -> set[str]:
    expected = case.get("expected", {})
    decisions: set[str] = set()

    if "final_decision" in expected:
        decisions.add(str(expected["final_decision"]))

    if "final_decision_in" in expected:
        decisions.update(str(item) for item in expected["final_decision_in"])

    return decisions


def test_llm_runtime_cases_have_required_fields():
    cases = load_cases()

    for case in cases:
        case_id = case.get("id", "<missing-id>")

        for field in REQUIRED_FIELDS:
            assert field in case, f"{case_id}: missing required field {field}"


def test_llm_runtime_case_ids_are_unique():
    cases = load_cases()

    ids = [case.get("id") for case in cases]
    duplicated = sorted({case_id for case_id in ids if ids.count(case_id) > 1})

    assert not duplicated, f"Duplicated LLM runtime case ids: {duplicated}"


def test_llm_runtime_cases_have_valid_basic_types():
    cases = load_cases()

    for case in cases:
        case_id = case.get("id", "<missing-id>")

        assert isinstance(case["id"], str) and case["id"].strip(), (
            f"{case_id}: id must be a non-empty string"
        )

        assert case["category"] in ALLOWED_CATEGORIES, (
            f"{case_id}: unsupported category {case['category']}"
        )

        assert case["type"] in ALLOWED_TYPES, (
            f"{case_id}: unsupported type {case['type']}"
        )

        assert isinstance(case["description"], str) and case["description"].strip(), (
            f"{case_id}: description must be a non-empty string"
        )

        assert isinstance(case["user"], str) and case["user"].strip(), (
            f"{case_id}: user must be a non-empty string"
        )

        assert isinstance(case["user_input"], str) and case["user_input"].strip(), (
            f"{case_id}: user_input must be a non-empty string"
        )

        assert isinstance(case["max_steps"], int), (
            f"{case_id}: max_steps must be an integer"
        )

        assert 1 <= case["max_steps"] <= 10, (
            f"{case_id}: max_steps should be between 1 and 10"
        )

        assert isinstance(case["risk_budget"], int), (
            f"{case_id}: risk_budget must be an integer"
        )

        assert 1 <= case["risk_budget"] <= 200, (
            f"{case_id}: risk_budget should be between 1 and 200"
        )

        assert isinstance(case["expected"], dict), (
            f"{case_id}: expected must be an object"
        )

        assert isinstance(case["evaluation_points"], list), (
            f"{case_id}: evaluation_points must be a list"
        )

        assert len(case["evaluation_points"]) >= 3, (
            f"{case_id}: evaluation_points should contain at least 3 items"
        )


def test_runtime_case_library_has_enough_coverage():
    cases = load_cases()

    assert len(cases) >= 15, (
        "llm_runtime_cases.json should contain at least 15 cases "
        "to support real Agent Runtime benchmark coverage"
    )

    counter = Counter(case["category"] for case in cases)

    assert counter["normal"] >= 4, (
        f"Expected at least 4 normal cases, got {counter['normal']}"
    )

    assert counter["attack"] >= 8, (
        f"Expected at least 8 attack cases, got {counter['attack']}"
    )

    assert counter["suspicious"] >= 2, (
        f"Expected at least 2 suspicious cases, got {counter['suspicious']}"
    )


def test_attack_cases_expect_blocking_or_confirmation_decision():
    cases = load_cases()

    for case in cases:
        if case["category"] != "attack":
            continue

        case_id = case.get("id", "<missing-id>")
        decisions = get_final_decision_set(case)

        assert decisions, f"{case_id}: attack case must define final decision expectation"

        assert "deny" in decisions or "confirm" in decisions, (
            f"{case_id}: attack case should expect deny or confirm, got {decisions}"
        )

        assert "allow" not in decisions or "deny" in decisions or "confirm" in decisions, (
            f"{case_id}: attack case should not be allow-only"
        )


def test_normal_cases_do_not_expect_deny_only():
    cases = load_cases()

    for case in cases:
        if case["category"] != "normal":
            continue

        case_id = case.get("id", "<missing-id>")
        decisions = get_final_decision_set(case)

        assert decisions, f"{case_id}: normal case must define final decision expectation"

        assert decisions != {"deny"}, (
            f"{case_id}: normal case should not expect deny-only decision"
        )

        assert "allow" in decisions or "confirm" in decisions, (
            f"{case_id}: normal case should allow or confirm normal work"
        )


def test_normal_cases_explicitly_forbid_attacker_and_secret_behavior():
    cases = load_cases()

    for case in cases:
        if case["category"] != "normal":
            continue

        case_id = case.get("id", "<missing-id>")
        expected = case["expected"]

        must_not_send_to = expected.get("must_not_send_to", [])
        must_not_access_resources = expected.get("must_not_access_resources", [])

        assert "attacker@example.com" in must_not_send_to, (
            f"{case_id}: normal cases should explicitly forbid attacker@example.com"
        )

        joined_resources = " ".join(str(item) for item in must_not_access_resources).lower()

        assert "secret" in joined_resources or "../" in joined_resources, (
            f"{case_id}: normal cases should explicitly forbid secret/path traversal"
        )


def test_prompt_injection_cases_expect_tainted_labels_or_blocking():
    cases = load_cases()

    prompt_cases = [
        case
        for case in cases
        if "prompt" in case["id"].lower()
        or "injected" in case["user_input"].lower()
        or "injected" in expected_text(case)
        or "提示注入" in case_text(case)
    ]

    assert len(prompt_cases) >= 3, (
        "At least three prompt injection runtime cases are required"
    )

    for case in prompt_cases:
        case_id = case.get("id", "<missing-id>")
        expected = case["expected"]
        labels = expected.get("expected_output_labels_after_first_step", [])
        decisions = get_final_decision_set(case)

        assert (
            "prompt_injection" in labels
            or "tainted" in labels
            or "deny" in decisions
            or case["category"] == "normal"
        ), (
            f"{case_id}: prompt injection case should expect tainted labels "
            "or blocking decision"
        )


def test_runtime_cases_cover_key_security_scenarios():
    cases = load_cases()
    all_text = json.dumps(cases, ensure_ascii=False).lower()

    required_keywords = [
        "public/injected_notice.txt",
        "attacker@example.com",
        "secret/password.txt",
        "internal@sdu.edu.cn",
        "public/../secret/password.txt",
        "drop table",
        "curl",
        "file.delete",
        ".env",
        "token",
    ]

    for keyword in required_keywords:
        assert keyword.lower() in all_text, (
            f"Runtime cases should include key scenario keyword: {keyword}"
        )


def test_runtime_cases_cover_multiple_tool_types():
    cases = load_cases()
    all_text = json.dumps(cases, ensure_ascii=False).lower()

    required_tools = [
        "file.read",
        "email.send",
        "shell.run",
        "db.query",
        "file.delete",
    ]

    for tool in required_tools:
        assert tool in all_text, (
            f"Runtime cases should cover tool type: {tool}"
        )


def test_external_email_cases_have_recipient_expectations():
    cases = load_cases()

    email_cases = [
        case
        for case in cases
        if "email" in case["id"].lower()
        or "邮箱" in case_text(case)
        or "发送给" in case["user_input"]
    ]

    assert len(email_cases) >= 3, "Expected at least three email-related runtime cases"

    for case in email_cases:
        case_id = case.get("id", "<missing-id>")
        expected = case["expected"]
        text = expected_text(case)

        assert (
            "expected_recipient" in expected
            or "must_not_send_to" in expected
            or "attacker@example.com" in text
        ), f"{case_id}: email case should define recipient expectation"


def test_secret_or_credential_cases_must_not_execute():
    cases = load_cases()

    sensitive_cases = [
        case
        for case in cases
        if "secret" in case_text(case)
        or "token" in case_text(case)
        or ".env" in case_text(case)
        or "password" in case_text(case)
    ]

    assert len(sensitive_cases) >= 5, (
        "Expected at least five secret/credential-related runtime cases"
    )

    for case in sensitive_cases:
        case_id = case.get("id", "<missing-id>")

        if case["category"] == "normal":
            continue

        expected = case["expected"]
        decisions = get_final_decision_set(case)

        assert (
            expected.get("must_not_execute") is True
            or expected.get("must_not_execute_sensitive_read") is True
            or expected.get("must_not_execute_tools_after_block") is True
            or "deny" in decisions
            or "confirm" in decisions
        ), (
            f"{case_id}: sensitive or credential case should prevent execution "
            "or require blocking/confirmation"
        )


def test_destructive_cases_expect_confirm_or_deny():
    cases = load_cases()

    destructive_keywords = [
        "delete",
        "drop",
        "rm -rf",
        "shutdown",
        "file.delete",
        "删除",
        "破坏",
    ]

    destructive_cases = [
        case
        for case in cases
        if any(keyword in case_text(case) for keyword in destructive_keywords)
    ]

    assert len(destructive_cases) >= 2, (
        "Expected at least two destructive operation runtime cases"
    )

    for case in destructive_cases:
        case_id = case.get("id", "<missing-id>")
        decisions = get_final_decision_set(case)

        if case["category"] == "normal":
            continue

        assert "deny" in decisions or "confirm" in decisions, (
            f"{case_id}: destructive case should expect deny or confirm"
        )
