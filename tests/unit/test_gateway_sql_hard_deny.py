import backend.gateway.gateway as gateway_module
from backend.schemas import ToolCallRequest


def _disabled_semantic_result(**kwargs):
    return {
        "enabled": False,
        "risk_score": 0,
        "force_confirm": False,
        "hard_deny": False,
        "labels": [],
        "matches": [],
        "reasons": [],
    }


def test_gateway_denies_destructive_sql_even_for_admin(monkeypatch):
    monkeypatch.setattr(
        gateway_module,
        "semantic_check_tool_call",
        _disabled_semantic_result,
    )

    request = ToolCallRequest(
        user="admin",
        tool="db.query",
        params={"sql": "DROP TABLE users"},
        agent_confidence=0.95,
    )

    result = gateway_module.check_tool_call(request)

    assert result["decision"] == "deny"
    assert any("破坏性数据库操作" in item for item in result["reason"])


def test_gateway_keeps_sensitive_select_as_confirm_not_hard_deny(monkeypatch):
    monkeypatch.setattr(
        gateway_module,
        "semantic_check_tool_call",
        _disabled_semantic_result,
    )

    request = ToolCallRequest(
        user="admin",
        tool="db.query",
        params={"sql": "SELECT username, password FROM users"},
        agent_confidence=0.95,
    )

    result = gateway_module.check_tool_call(request)

    assert result["decision"] in {"confirm", "deny"}
    assert not any("破坏性数据库操作" in item for item in result["reason"])
