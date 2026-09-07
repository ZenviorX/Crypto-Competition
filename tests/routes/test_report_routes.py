import unittest

from fastapi.testclient import TestClient

from backend.main import app


class TestReportRoutes(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_gateway_benchmark_report_route(self):
        response = self.client.get("/reports/gateway-benchmark")

        self.assertIn(response.status_code, [200, 404])

        if response.status_code == 200:
            self.assertIn("Agent Authorization Gateway Benchmark Report", response.text)

    def test_attack_chain_report_route(self):
        response = self.client.get("/reports/attack-chain")

        self.assertIn(response.status_code, [200, 404])

        if response.status_code == 200:
            self.assertIn("Multi-step Attack Chain Demo Report", response.text)


if __name__ == "__main__":
    unittest.main()
