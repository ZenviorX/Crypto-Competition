from copy import deepcopy

from backend.evidence.integrity import (
    attach_integrity_manifest,
    verify_report_integrity,
)


def _sample_report():
    return {
        "summary": {
            "generated_at": "2026-06-09T00:00:00+00:00",
            "total": 2,
            "passed": 2,
            "failed": 0,
            "pass_rate": 1.0,
        },
        "cases": [
            {
                "id": "normal_public_read",
                "category": "normal",
                "passed": True,
                "final_decision": "allow",
                "steps": [
                    {
                        "step_id": 1,
                        "tool": "file.read",
                        "decision": "allow",
                        "risk_score": 10,
                        "executed": True,
                        "blocked": False,
                        "requires_confirmation": False,
                        "input_labels": [],
                        "output_labels": ["public"],
                    }
                ],
            },
            {
                "id": "attack_secret_read",
                "category": "attack",
                "passed": True,
                "final_decision": "deny",
                "steps": [
                    {
                        "step_id": 1,
                        "tool": "file.read",
                        "decision": "deny",
                        "risk_score": 100,
                        "executed": False,
                        "blocked": True,
                        "requires_confirmation": False,
                        "input_labels": [],
                        "output_labels": [],
                    }
                ],
            },
        ],
    }


def test_integrity_manifest_verifies_clean_report():
    report = attach_integrity_manifest(_sample_report())
    result = verify_report_integrity(report)

    assert result["valid"] is True
    assert result["root_hash"]
    assert result["report_hash_without_integrity"]
    assert result["total_cases"] == 2


def test_integrity_manifest_detects_case_tampering():
    report = attach_integrity_manifest(_sample_report())
    tampered = deepcopy(report)

    tampered["cases"][1]["final_decision"] = "allow"
    tampered["cases"][1]["steps"][0]["decision"] = "allow"

    result = verify_report_integrity(tampered)

    assert result["valid"] is False
    assert any("mismatch" in item for item in result["reason"])


def test_integrity_manifest_detects_missing_manifest():
    result = verify_report_integrity(_sample_report())

    assert result["valid"] is False
    assert "missing integrity manifest" in result["reason"]
