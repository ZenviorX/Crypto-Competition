import unittest

from backend.task_contract.contract_builder import build_task_contract


class TestTaskContract(unittest.TestCase):

    def test_build_contract_for_read_and_email_task(self):
        task = "读取 public/injected_notice.txt 并发给 internal@sdu.edu.cn"

        contract = build_task_contract(
            user="user",
            task_text=task
        )

        self.assertEqual(contract.user, "user")
        self.assertIn("file.read", contract.allowed_tools)
        self.assertIn("email.send", contract.allowed_tools)

        self.assertIn("public/injected_notice.txt", contract.allowed_read_paths)
        self.assertIn("internal@sdu.edu.cn", contract.allowed_email_to)

        self.assertIn("secret/*", contract.denied_paths)
        self.assertIn("shell.run", contract.denied_tools)


if __name__ == "__main__":
    unittest.main()
