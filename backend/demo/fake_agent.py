import re
from typing import Any, Dict

from backend.schemas import AgentPlanResult
from backend.utils import clean_text_value


class FakeAgent:
    """
    Demo-only FakeAgent.

    FakeAgent is not part of the core gateway. Its only purpose is to simulate
    how an upstream AI Agent may convert natural-language input into a
    structured tool-call plan.

    It must not execute tools.
    It must not make authorization decisions.
    It only produces a plan.
    """

    name = "FakeAgent"

    def plan(self, user_input: str) -> AgentPlanResult:
        user_input = user_input.strip()

        if self._is_send_email_task(user_input):
            return AgentPlanResult.model_validate(self._build_send_email_call(user_input))
        if self._is_delete_file_task(user_input):
            return AgentPlanResult.model_validate(self._build_delete_file_call(user_input))
        if self._is_read_file_task(user_input):
            return AgentPlanResult.model_validate(self._build_read_file_call(user_input))
        if self._is_shell_task(user_input):
            return AgentPlanResult.model_validate(self._build_shell_call(user_input))
        if self._is_db_query_task(user_input):
            return AgentPlanResult.model_validate(self._build_db_query_call(user_input))

        return AgentPlanResult.model_validate({
            "agent": self.name,
            "status": "unsupported",
            "confidence": 0.0,
            "message": "当前演示 FakeAgent 暂时无法识别该任务。",
            "unsupported_reason": "用户输入无法映射到系统支持的演示工具类型。",
            "clarification_question": "请明确说明要读取文件、发送邮件、删除文件、执行命令还是查询数据库。",
            "original_input": user_input,
            "tool_call": None,
        })

    def _is_send_email_task(self, text: str) -> bool:
        lowered = text.lower()
        return "发邮件" in text or "发送邮件" in text or "send email" in lowered

    def _is_read_file_task(self, text: str) -> bool:
        lowered = text.lower()
        if "读取文件" in text or "查看文件" in text or "读文件" in text or "read file" in lowered:
            return True
        return bool(re.search(r"(?:读取|查看)[：:\s]+[^，,\s]+", text))

    def _is_delete_file_task(self, text: str) -> bool:
        lowered = text.lower()
        return "删除文件" in text or "删掉文件" in text or "remove file" in lowered or "delete file" in lowered

    def _is_shell_task(self, text: str) -> bool:
        lowered = text.lower()
        return "执行命令" in text or "运行命令" in text or "shell" in lowered or "run command" in lowered

    def _is_db_query_task(self, text: str) -> bool:
        lowered = text.lower()
        return "查询数据库" in text or "执行sql" in lowered or "执行 sql" in lowered or "query db" in lowered

    def _extract_file_path(self, text: str) -> str:
        patterns = [
            r"(?:读取文件|查看文件|读文件|删除文件|删掉文件)[：:\s]*(.+)$",
            r"(?:读取|查看)[：:\s]+(.+)$",
            r"(?:read file|delete file|remove file)[：:\s]*(.+)$",
            r"文件[：:\s]*(.+)$",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                value = clean_text_value(match.group(1))
                value = re.split(r"\s*(?:并|然后|之后|，|,)\s*", value, maxsplit=1)[0]
                return clean_text_value(value)
        return "unknown"

    def _build_send_email_call(self, text: str) -> Dict[str, Any]:
        receiver = "unknown"
        content = "未提取到邮件正文"
        receiver_match = re.search(r"给(.+?)(?:发邮件|发送邮件)", text)
        if receiver_match:
            receiver = clean_text_value(receiver_match.group(1))
        content_match = re.search(r"内容(?:是|为)?[：:]?(.+)", text)
        if content_match:
            content = clean_text_value(content_match.group(1))
        missing_params = []
        if not receiver or receiver == "unknown": missing_params.append("to")
        if not content or content == "未提取到邮件正文": missing_params.append("content")
        return {
            "agent": self.name,
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.92,
            "missing_params": missing_params,
            "clarification_question": "请补充邮件收件人和正文内容。" if missing_params else None,
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "email.send",
                "description": "发送邮件",
                "arguments": {"to": receiver, "subject": "演示 FakeAgent 邮件", "content": content},
                "need_auth": True,
            },
        }

    def _build_read_file_call(self, text: str) -> Dict[str, Any]:
        file_path = self._extract_file_path(text)
        missing_params = []
        if not file_path or file_path == "unknown": missing_params.append("path")
        return {
            "agent": self.name,
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.95,
            "missing_params": missing_params,
            "clarification_question": "请补充要读取的文件路径。" if missing_params else None,
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "file.read",
                "description": "读取文件内容",
                "arguments": {"path": file_path},
                "need_auth": True,
            },
        }

    def _build_delete_file_call(self, text: str) -> Dict[str, Any]:
        file_path = self._extract_file_path(text)
        missing_params = []
        if not file_path or file_path == "unknown": missing_params.append("path")
        return {
            "agent": self.name,
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.90,
            "missing_params": missing_params,
            "clarification_question": "请补充要删除的文件路径。" if missing_params else None,
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "file.delete",
                "description": "删除文件",
                "arguments": {"path": file_path},
                "need_auth": True,
            },
        }

    def _build_shell_call(self, text: str) -> Dict[str, Any]:
        command = text
        command_match = re.search(r"(?:命令|command)[是为:：\s]*(.+)", text, re.IGNORECASE)
        if command_match:
            command = clean_text_value(command_match.group(1))
        command = re.sub(r"^(?:command|cmd)\s*[=:：]\s*", "", command, flags=re.IGNORECASE)
        missing_params = []
        if not command: missing_params.append("command")
        return {
            "agent": self.name,
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.90,
            "missing_params": missing_params,
            "clarification_question": "请补充要执行的命令。" if missing_params else None,
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "shell.run",
                "description": "执行系统命令",
                "arguments": {"command": command},
                "need_auth": True,
            },
        }

    def _build_db_query_call(self, text: str) -> Dict[str, Any]:
        sql = text
        sql_match = re.search(r"(?:sql|SQL|查询语句)[是为:：\s]*(.+)", text)
        if sql_match:
            sql = clean_text_value(sql_match.group(1))
        missing_params = []
        if not sql: missing_params.append("sql")
        return {
            "agent": self.name,
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.90,
            "missing_params": missing_params,
            "clarification_question": "请补充要执行的 SQL 查询语句。" if missing_params else None,
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "db.query",
                "description": "数据库查询",
                "arguments": {"sql": sql},
                "need_auth": True,
            },
        }
