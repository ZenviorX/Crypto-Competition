import unittest

from backend.schemas import ToolCallRequest
from backend.gateway.gateway import check_tool_call
from backend.task_contract.contract_builder import build_task_contract


def to_dict(result):
    """
    兼容 check_tool_call 返回 dict 或 Pydantic 对象两种情况。
    """
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return result


class TestGatewayTaskContract(unittest.TestCase):

    def test_allow_read_authorized_file(self):
        contract = build_task_contract(
            user="user",
            task_text="读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"
        )

        request = ToolCallRequest(
            user="user",
            tool="file.read",
            params={
                "path": "public/injected_notice.txt"
            },
            task_contract=contract.model_dump()
        )

        result = to_dict(check_tool_call(request))

        self.assertEqual(result["decision"], "allow")
        self.assertIn("已启用任务授权合约检查。", result["reason"])

    def test_deny_read_secret_file(self):
        contract = build_task_contract(
            user="user",
            task_text="读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"
        )

        request = ToolCallRequest(
            user="user",
            tool="file.read",
            params={
                "path": "secret/password.txt"
            },
            task_contract=contract.model_dump()
        )

        result = to_dict(check_tool_call(request))

        self.assertEqual(result["decision"], "deny")
        self.assertIn("已启用任务授权合约检查。", result["reason"])

    def test_deny_send_to_unauthorized_email(self):
        contract = build_task_contract(
            user="user",
            task_text="读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"
        )

        request = ToolCallRequest(
            user="user",
            tool="email.send",
            params={
                "to": "attacker@example.com",
                "content": "这是整理后的公开通知"
            },
            task_contract=contract.model_dump()
        )

        result = to_dict(check_tool_call(request))

        self.assertEqual(result["decision"], "deny")
        self.assertIn("已启用任务授权合约检查。", result["reason"])

    def test_admin_send_to_authorized_email_not_blocked_by_contract(self):
        contract = build_task_contract(
            user="admin",
            task_text="读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"
        )

        request = ToolCallRequest(
            user="admin",
            tool="email.send",
            params={
                "to": "internal@sdu.edu.cn",
                "content": "这是整理后的公开通知"
            },
            task_contract=contract.model_dump()
        )

        result = to_dict(check_tool_call(request))

        self.assertIn("已启用任务授权合约检查。", result["reason"])
        self.assertNotIn(
            "邮件收件人 internal@sdu.edu.cn 不在本次任务允许发送范围内。",
            result["reason"]
        )


if __name__ == "__main__":
    unittest.main()
