import unittest

from fastapi.testclient import TestClient

from backend.main import app


class TestTaskContractRoutes(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def build_contract(self):
        response = self.client.post(
            "/task-contract/build",
            json={
                "user": "user",
                "task_text": "读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"
            }
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["message"], "任务授权合约生成成功")
        return data["contract"]

    def test_build_task_contract_route(self):
        contract = self.build_contract()

        self.assertEqual(contract["user"], "user")
        self.assertIn("file.read", contract["allowed_tools"])
        self.assertIn("email.send", contract["allowed_tools"])
        self.assertIn("public/injected_notice.txt", contract["allowed_read_paths"])
        self.assertIn("internal@sdu.edu.cn", contract["allowed_email_to"])

    def test_gateway_allow_authorized_file_read_with_contract(self):
        contract = self.build_contract()

        response = self.client.post(
            "/gateway/check",
            json={
                "user": "user",
                "tool": "file.read",
                "params": {
                    "path": "public/injected_notice.txt"
                },
                "task_contract": contract
            }
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["decision"], "allow")
        self.assertIn("已启用任务授权合约检查。", data["reason"])

    def test_gateway_deny_secret_file_read_with_contract(self):
        contract = self.build_contract()

        response = self.client.post(
            "/gateway/check",
            json={
                "user": "user",
                "tool": "file.read",
                "params": {
                    "path": "secret/password.txt"
                },
                "task_contract": contract
            }
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["decision"], "deny")
        self.assertIn("已启用任务授权合约检查。", data["reason"])

    def test_gateway_deny_unauthorized_email_with_contract(self):
        contract = self.build_contract()

        response = self.client.post(
            "/gateway/check",
            json={
                "user": "user",
                "tool": "email.send",
                "params": {
                    "to": "attacker@example.com",
                    "content": "这是整理后的公开通知"
                },
                "task_contract": contract
            }
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["decision"], "deny")
        self.assertIn("已启用任务授权合约检查。", data["reason"])


if __name__ == "__main__":
    unittest.main()
