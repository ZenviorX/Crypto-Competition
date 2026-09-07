from backend.gateway import check_tool_call
from backend.schemas import ToolCallRequest


def _disabled_semantic_result(**_kwargs):
    return {
        "enabled": False,
        "risk_score": 0,
        "force_confirm": False,
        "hard_deny": False,
        "labels": [],
        "matches": [],
        "reasons": [],
    }


def _result_reason(result):
    return "\n".join(result.get("reason", []))


def test_gateway_denies_encoded_path_traversal_keyword(monkeypatch):
    """
    dangerous_keywords.path 中的编码路径穿越关键词应当真正参与判断，
    例如 %2e%2e 这类编码绕过应触发 hard_deny。
    """
    monkeypatch.setattr(
        "backend.gateway.gateway.semantic_check_tool_call",
        _disabled_semantic_result,
    )

    def fake_dangerous_keywords(category: str):
        if category == "path":
            return ["%2e%2e"]
        if category == "sensitive_path":
            return []
        return []

    monkeypatch.setattr(
        "backend.gateway.gateway.get_dangerous_keywords",
        fake_dangerous_keywords,
    )
    monkeypatch.setattr(
        "backend.gateway.gateway.get_resource_risk",
        lambda _path: (0, []),
    )

    request = ToolCallRequest(
        user="admin",
        tool="file.read",
        params={"path": "public/%2e%2e%2fsecret/password.txt"},
    )

    result = check_tool_call(request)

    assert result["decision"] == "deny"
    assert "路径命中高危关键词" in _result_reason(result)
    assert "路径穿越或编码绕过风险" in _result_reason(result)


def test_gateway_uses_sensitive_path_keywords_for_risk_scoring(monkeypatch):
    """
    dangerous_keywords.sensitive_path 中的敏感资源关键词应当增加风险分。
    在 admin 读取路径未命中角色 deny 的情况下，也应至少进入人工确认。
    """
    monkeypatch.setattr(
        "backend.gateway.gateway.semantic_check_tool_call",
        _disabled_semantic_result,
    )

    def fake_dangerous_keywords(category: str):
        if category == "path":
            return []
        if category == "sensitive_path":
            return ["vault"]
        return []

    monkeypatch.setattr(
        "backend.gateway.gateway.get_dangerous_keywords",
        fake_dangerous_keywords,
    )
    monkeypatch.setattr(
        "backend.gateway.gateway.get_resource_risk",
        lambda _path: (0, []),
    )

    request = ToolCallRequest(
        user="admin",
        tool="file.read",
        params={"path": "public/vault_notes.txt"},
    )

    result = check_tool_call(request)

    assert result["decision"] == "confirm"
    assert result["risk_score"] >= 40
    assert "路径命中敏感资源关键词：vault" in _result_reason(result)
