import unittest

from backend.gateway import check_tool_call
from backend.schemas import ToolCallRequest


class GatewayPolicyTest(unittest.TestCase):
    def _check(self, user, tool, params):
        request = ToolCallRequest(user=user, tool=tool, params=params)
        return check_tool_call(request)

    def test_public_file_read_is_allowed_for_student(self):
        result = self._check("student", "file.read", {"path": "public/notice.txt"})
        self.assertEqual(result["decision"], "allow")

    def test_secret_file_read_is_denied_for_student(self):
        result = self._check("student", "file.read", {"path": "secret/password.txt"})
        self.assertEqual(result["decision"], "deny")

    def test_admin_file_delete_requires_confirmation(self):
        result = self._check("admin", "file.delete", {"path": "public/notice.txt"})
        self.assertEqual(result["decision"], "confirm")

    def test_path_traversal_is_hard_denied(self):
        result = self._check("alice", "file.read", {"path": "../../secret/password.txt"})
        self.assertEqual(result["decision"], "deny")

    def test_admin_high_risk_shell_call_requires_confirmation(self):
        result = self._check("admin", "shell.run", {"command": "dir"})
        self.assertEqual(result["decision"], "confirm")


if __name__ == "__main__":
    unittest.main()
