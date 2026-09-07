import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.audit import audit_logger


class TestAuditHashChain(unittest.TestCase):
    def test_write_log_contains_hash_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_log = Path(temp_dir) / "audit.log"

            with patch.object(audit_logger, "LOG_FILE", temp_log):
                record = audit_logger.write_log(
                    user="user",
                    tool="file.read",
                    params={"path": "public/notice.txt"},
                    gateway_result={
                        "decision": "allow",
                        "risk_score": 10,
                        "risk_level": "low",
                        "reason": ["测试日志"],
                        "explanations": [{"factor": "tool", "reason": "测试"}],
                    },
                    executed=True,
                )

                self.assertIn("prev_hash", record)
                self.assertIn("record_hash", record)
                self.assertEqual(len(record["record_hash"]), 64)

    def test_verify_audit_chain_success(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_log = Path(temp_dir) / "audit.log"

            with patch.object(audit_logger, "LOG_FILE", temp_log):
                audit_logger.write_log(
                    user="user",
                    tool="file.read",
                    params={"path": "public/notice.txt"},
                    gateway_result={
                        "decision": "allow",
                        "risk_score": 10,
                        "risk_level": "low",
                        "reason": ["第一条日志"],
                        "explanations": [],
                    },
                    executed=True,
                )

                audit_logger.write_log(
                    user="user",
                    tool="file.read",
                    params={"path": "secret/password.txt"},
                    gateway_result={
                        "decision": "deny",
                        "risk_score": 100,
                        "risk_level": "critical",
                        "reason": ["第二条日志"],
                        "explanations": [],
                    },
                    executed=False,
                )

                result = audit_logger.verify_audit_chain()

                self.assertTrue(result["valid"])
                self.assertEqual(result["checked_records"], 2)

    def test_verify_audit_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_log = Path(temp_dir) / "audit.log"

            with patch.object(audit_logger, "LOG_FILE", temp_log):
                audit_logger.write_log(
                    user="user",
                    tool="file.read",
                    params={"path": "public/notice.txt"},
                    gateway_result={
                        "decision": "allow",
                        "risk_score": 10,
                        "risk_level": "low",
                        "reason": ["原始日志"],
                        "explanations": [],
                    },
                    executed=True,
                )

                lines = temp_log.read_text(encoding="utf-8").splitlines()
                record = json.loads(lines[0])
                record["decision"] = "deny"

                temp_log.write_text(
                    json.dumps(record, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )

                result = audit_logger.verify_audit_chain()

                self.assertFalse(result["valid"])
                self.assertIn("篡改", result["reason"])


if __name__ == "__main__":
    unittest.main()
