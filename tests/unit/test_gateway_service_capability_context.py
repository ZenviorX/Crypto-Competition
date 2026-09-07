from backend.gateway.gateway_service import handle_tool_request
from backend.schemas import ToolCallRequest


def build_email_contract():
    return {
        "contract_version": "2.0",
        "task_id": "test-capability-context",
        "user": "user",
        "original_task": "Send a safe summary to an internal recipient.",
        "task_goal": "send_internal_summary",
        "capabilities": [
            {
                "tool": "email.send",
                "mode": "external_write",
                "resource_patterns": [],
                "recipients": ["team@sdu.edu.cn"],
                "allowed_input_labels": [
                    "public",
                    "internal",
                    "tainted",
                    "prompt_injection",
                    "unknown",
                ],
                "output_labels": [],
                "risk_cost": 20,
                "require_approval": False,
            }
        ],
        "forbidden_tools": ["shell.run"],
        "forbidden_resources": ["data/secret/*"],
        "max_steps": 3,
        "risk_budget": 40,
    }


def get_gateway_result(response):
    return response["gateway_result"]


def test_gateway_service_passes_current_step_to_capability_contract():
    request = ToolCallRequest(
        user="user",
        tool="email.send",
        params={
            "to": "team@sdu.edu.cn",
            "content": "normal summary",
        },
        task_contract=build_email_contract(),
        current_step=4,
        used_risk=0,
        input_labels=["public"],
    )

    response = handle_tool_request(request)
    gateway_result = get_gateway_result(response)

    assert response["executed"] is False
    assert gateway_result["decision"] == "deny"
    assert any(
        "exceeds contract max_steps" in reason
        for reason in gateway_result["reason"]
    )


def test_gateway_service_passes_used_risk_to_capability_contract():
    request = ToolCallRequest(
        user="user",
        tool="email.send",
        params={
            "to": "team@sdu.edu.cn",
            "content": "normal summary",
        },
        task_contract=build_email_contract(),
        current_step=1,
        used_risk=30,
        input_labels=["public"],
    )

    response = handle_tool_request(request)
    gateway_result = get_gateway_result(response)

    assert response["executed"] is False
    assert gateway_result["decision"] == "deny"
    assert any(
        "Risk budget exceeded" in reason
        for reason in gateway_result["reason"]
    )


def test_gateway_service_passes_secret_label_to_capability_contract():
    request = ToolCallRequest(
        user="user",
        tool="email.send",
        params={
            "to": "team@sdu.edu.cn",
            "content": "summary derived from secret data",
        },
        task_contract=build_email_contract(),
        current_step=1,
        used_risk=0,
        input_labels=["secret"],
    )

    response = handle_tool_request(request)
    gateway_result = get_gateway_result(response)

    assert response["executed"] is False
    assert gateway_result["decision"] == "deny"
    assert any(
        "Sensitive or secret data is not allowed" in reason
        for reason in gateway_result["reason"]
    )


def test_gateway_service_passes_prompt_injection_label_to_capability_contract():
    request = ToolCallRequest(
        user="user",
        tool="email.send",
        params={
            "to": "team@sdu.edu.cn",
            "content": "summary derived from injected public content",
        },
        task_contract=build_email_contract(),
        current_step=1,
        used_risk=0,
        input_labels=["prompt_injection"],
    )

    response = handle_tool_request(request)
    gateway_result = get_gateway_result(response)

    assert response["executed"] is False
    assert gateway_result["decision"] in {"confirm", "deny"}
    assert any(
        "Tainted or unknown data is flowing into an external_write tool" in reason
        for reason in gateway_result["reason"]
    )