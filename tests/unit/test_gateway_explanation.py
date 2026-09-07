import unittest

from backend.schemas import ToolCallRequest
from backend.gateway.gateway import check_tool_call


class TestGatewayExplanation(unittest.TestCase):
    def test_secret_file_read_has_risk_level_and_explanations(self):
        request = ToolCallRequest(
            user="user",
            tool="file.read",
            params={
                "path": "secret/password.txt"
            }
        )

        result = check_tool_call(request)

        self.assertEqual(result["decision"], "deny")
        self.assertIn("risk_score", result)
        self.assertIn("risk_level", result)
        self.assertIn(result["risk_level"], ["high", "critical"])

        self.assertIn("explanations", result)
        self.assertIsInstance(result["explanations"], list)
        self.assertGreater(len(result["explanations"]), 0)

        factors = [item["factor"] for item in result["explanations"]]
        self.assertTrue(
            "resource_path" in factors or "role_policy" in factors
        )

    def test_public_file_read_has_explanation_fields(self):
        request = ToolCallRequest(
            user="user",
            tool="file.read",
            params={
                "path": "public/notice.txt"
            }
        )

        result = check_tool_call(request)

        self.assertIn("decision", result)
        self.assertIn("risk_score", result)
        self.assertIn("risk_level", result)
        self.assertIn("explanations", result)

        self.assertIsInstance(result["explanations"], list)
        self.assertGreater(len(result["explanations"]), 0)

    def test_unknown_tool_has_structured_explanations(self):
        request = ToolCallRequest(
            user="user",
            tool="unknown.tool",
            params={}
        )

        result = check_tool_call(request)

        self.assertEqual(result["decision"], "deny")
        self.assertIn("risk_level", result)
        self.assertEqual(result["risk_level"], "critical")
        self.assertIn("explanations", result)
        self.assertGreater(len(result["explanations"]), 0)


if __name__ == "__main__":
    unittest.main()
