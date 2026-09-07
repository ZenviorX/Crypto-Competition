import unittest

from backend.task_contract.contract_builder import build_task_contract
from backend.task_contract.contract_enforcer import check_call_against_contract


class TestContractEnforcer(unittest.TestCase):

    def setUp(self):
        self.contract = build_task_contract(
            user="user",
            task_text="读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"
        )

    def test_allow_read_authorized_file(self):
        result = check_call_against_contract(
            contract=self.contract,
            tool="file.read",
            params={
                "path": "public/injected_notice.txt"
            }
        )

        self.assertEqual(result.decision, "allow")

    def test_deny_read_secret_file(self):
        result = check_call_against_contract(
            contract=self.contract,
            tool="file.read",
            params={
                "path": "secret/password.txt"
            }
        )

        self.assertEqual(result.decision, "deny")
        self.assertGreaterEqual(result.risk_score, 100)

    def test_deny_read_unrelated_file(self):
        result = check_call_against_contract(
            contract=self.contract,
            tool="file.read",
            params={
                "path": "public/other_notice.txt"
            }
        )

        self.assertEqual(result.decision, "deny")

    def test_allow_send_to_authorized_email(self):
        result = check_call_against_contract(
            contract=self.contract,
            tool="email.send",
            params={
                "to": "internal@sdu.edu.cn",
                "content": "这是整理后的公开通知。"
            }
        )

        self.assertEqual(result.decision, "allow")

    def test_deny_send_to_unauthorized_email(self):
        result = check_call_against_contract(
            contract=self.contract,
            tool="email.send",
            params={
                "to": "attacker@example.com",
                "content": "这是整理后的公开通知。"
            }
        )

        self.assertEqual(result.decision, "deny")
        self.assertGreaterEqual(result.risk_score, 100)

    def test_deny_shell_run(self):
        result = check_call_against_contract(
            contract=self.contract,
            tool="shell.run",
            params={
                "cmd": "dir"
            }
        )

        self.assertEqual(result.decision, "deny")


if __name__ == "__main__":
    unittest.main()
