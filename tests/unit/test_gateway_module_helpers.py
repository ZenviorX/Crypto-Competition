from backend.gateway.result_builder import (
    build_explanations,
    build_gateway_result,
    default_semantic_guard_result,
    get_risk_level,
)
from backend.gateway.security_detectors import (
    is_destructive_sql_keyword,
    is_path_bypass_keyword,
)


def test_result_builder_adds_stable_semantic_guard_field():
    result = build_gateway_result(
        decision="allow",
        risk_score=8,
        reason=["公开文件读取，风险较低"],
        user="alice",
        role="user",
        tool="file.read",
        params={"path": "public/notice.txt"},
    )

    assert result["decision"] == "allow"
    assert result["risk_level"] == "low"
    assert result["semantic_guard"] == default_semantic_guard_result()
    assert result["explanations"][0]["factor"] in {"resource_path", "general"}


def test_risk_level_boundaries_are_stable():
    assert get_risk_level(0) == "low"
    assert get_risk_level(29) == "low"
    assert get_risk_level(30) == "medium"
    assert get_risk_level(59) == "medium"
    assert get_risk_level(60) == "high"
    assert get_risk_level(79) == "high"
    assert get_risk_level(80) == "critical"


def test_build_explanations_classifies_semantic_guard_reason():
    explanations = build_explanations(["语义检测命中风险标签：data_exfiltration"])
    assert explanations == [
        {
            "factor": "semantic_guard",
            "reason": "语义检测命中风险标签：data_exfiltration",
        }
    ]


def test_path_bypass_detector_identifies_encoded_traversal():
    assert is_path_bypass_keyword("%2e%2e")
    assert is_path_bypass_keyword("%252f")
    assert is_path_bypass_keyword("../")
    assert not is_path_bypass_keyword("secret")


def test_destructive_sql_detector_identifies_hard_deny_keywords():
    assert is_destructive_sql_keyword("DROP TABLE")
    assert is_destructive_sql_keyword("delete from")
    assert is_destructive_sql_keyword("xp_cmdshell")
    assert not is_destructive_sql_keyword("select password")
