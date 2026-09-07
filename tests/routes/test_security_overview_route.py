import unittest

from fastapi.testclient import TestClient

from backend.main import app


class TestSecurityOverviewRoute(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_security_overview_route_available(self):
        response = self.client.get("/security/overview")

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["project"], "Agent-Authorization")
        self.assertIn("metrics", data)
        self.assertIn("reports", data)
        self.assertIn("features", data)

        self.assertGreaterEqual(data["metrics"]["gateway_security_cases"], 30)
        self.assertGreaterEqual(data["metrics"]["attack_chain_cases"], 8)
        self.assertGreaterEqual(data["metrics"]["total_security_cases"], 38)

    def test_security_overview_features_enabled(self):
        response = self.client.get("/security/overview")

        self.assertEqual(response.status_code, 200)

        data = response.json()
        feature_keys = {item["key"] for item in data["features"]}

        self.assertIn("explainable_risk", feature_keys)
        self.assertIn("audit_hash_chain", feature_keys)
        self.assertIn("attack_chain_runtime", feature_keys)
        self.assertIn("gateway_benchmark", feature_keys)
        self.assertIn("attack_chain_benchmark", feature_keys)


if __name__ == "__main__":
    unittest.main()
