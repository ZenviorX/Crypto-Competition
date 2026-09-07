import re
from typing import Dict, Any

from backend.agents.base_agent import BaseAgent
from backend.schemas import AgentPlanResult
from backend.utils import clean_text_value


class FakeAgent(BaseAgent):
    """
    模拟智能体模块。
    根据用户输入的自然语言任务生成一个结构化的工具调用请求。
    """

    def plan(self, user_input: str) -> AgentPlanResult:
        """
        根据用户输入生成工具调用计划。
        """
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
            "agent": "FakeAgent",
            "status": "unsupported",
            "confidence": 0.0,
            "message": "当前模拟智能体暂时无法识别该任务",
            "unsupported_reason": "用户输入无法映射到系统支持的工具类型",
            "clarification_question": "请明确说明要读取文件、发送邮件、删除文件、执行命令还是查询数据库。",
            "original_input": user_input,
            "tool_call": None,
        })

    def _is_send_email_task(self, text: str) -> bool:
        return (
            "发邮件" in text
            or "发送邮件" in text
            or "send email" in text.lower()
        )

    def _is_read_file_task(self, text: str) -> bool:
        return (
            "读取文件" in text
            or "查看文件" in text
            or "读文件" in text
            or "read file" in text.lower()
        )

    def _is_delete_file_task(self, text: str) -> bool:
        return (
            "删除文件" in text
            or "删掉文件" in text
            or "remove file" in text.lower()
            or "delete file" in text.lower()
        )

    def _is_shell_task(self, text: str) -> bool:
        return (
            "执行命令" in text
            or "运行命令" in text
            or "shell" in text.lower()
            or "run command" in text.lower()
        )

    def _is_db_query_task(self, text: str) -> bool:
        return (
            "查询数据库" in text
            or "执行sql" in text.lower()
            or "执行 sql" in text.lower()
            or "query db" in text.lower()
        )

    def _extract_file_path(self, text: str) -> str:
        """
        从自然语言中提取文件路径。
        支持：
        读取文件：public/notice.txt
        查看文件 public/notice.txt
        删除文件：secret/password.txt
        """
        patterns = [
            r"(?:读取文件|查看文件|读文件|删除文件|删掉文件)[：:\s]*(.+)$",
            r"(?:read file|delete file|remove file)[：:\s]*(.+)$",
            r"文件[：:\s]*(.+)$",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return clean_text_value(match.group(1))

        return "unknown"

    def _build_send_email_call(self, text: str) -> Dict[str, Any]:
        """
        构造发送邮件工具调用。
        """
        receiver = "unknown"
        content = "未提取到邮件正文"

        receiver_match = re.search(r"给(.+?)(?:发邮件|发送邮件)", text)
        if receiver_match:
            receiver = clean_text_value(receiver_match.group(1))

        content_match = re.search(r"内容(?:是|为)?[：:]?(.+)", text)
        if content_match:
            content = clean_text_value(content_match.group(1))

        missing_params = []

        if not receiver or receiver == "unknown":
            missing_params.append("to")

        if not content or content == "未提取到邮件正文":
            missing_params.append("content")

        return {
            "agent": "FakeAgent",
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.92,
            "missing_params": missing_params,
            "clarification_question": (
                "请补充邮件收件人和正文内容。" if missing_params else None
            ),
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "email.send",
                "description": "发送邮件",
                "arguments": {
                    "to": receiver,
                    "subject": "模拟智能体邮件",
                    "content": content,
                },
                "need_auth": True,
            },
        }

    def _build_read_file_call(self, text: str) -> Dict[str, Any]:
        file_path = self._extract_file_path(text)
        missing_params = []

        if not file_path or file_path == "unknown":
            missing_params.append("path")

        return {
            "agent": "FakeAgent",
            "status": "need_clarification" if missing_params else "planned",
            "confidence": 0.65 if missing_params else 0.95,
            "missing_params": missing_params,
            "clarification_question": (
                "请补充要读取的文件路径。" if missing_params else None
            ),
            "original_input": text,
            "tool_call": None if missing_params else {
                "tool_name": "file.read",
                "description": "读取文件内容",
                "arguments": {
                    "file_path": file_path,
                },
                "need_auth": True,
            },
        }

    def _build_delete_file_call(self, text: str) -> Dict[str, Any]:
        file_path = self._extract_file_path(text)

        return {
            "agent": "FakeAgent",
            "status": "planned",
            "confidence": 0.9,
            "missing_params": [],
            "clarification_question": None,
            "original_input": text,
            "tool_call": {
                "tool_name": "file.delete",
                "description": "删除文件",
                "arguments": {
                    "file_path": file_path
                },
                "need_auth": True
            }
        }

    def _build_shell_call(self, text: str) -> Dict[str, Any]:
        command = text

        command_match = re.search(r"(?:命令|command)[是为:：\s]*(.+)", text, re.IGNORECASE)
        if command_match:
            command = clean_text_value(command_match.group(1))

        return {
            "agent": "FakeAgent",
            "status": "planned",
            "confidence": 0.9,
            "missing_params": [],
            "clarification_question": None,
            "original_input": text,
            "tool_call": {
                "tool_name": "shell.run",
                "description": "执行系统命令",
                "arguments": {
                    "command": command
                },
                "need_auth": True
            }
        }

    def _build_db_query_call(self, text: str) -> Dict[str, Any]:
        sql = text

        sql_match = re.search(r"(?:sql|SQL|查询语句)[是为:：\s]*(.+)", text)
        if sql_match:
            sql = clean_text_value(sql_match.group(1))

        return {
            "agent": "FakeAgent",
            "status": "planned",
            "confidence": 0.9,
            "missing_params": [],
            "clarification_question": None,
            "original_input": text,
            "tool_call": {
                "tool_name": "db.query",
                "description": "数据库查询",
                "arguments": {
                    "sql": sql
                },
                "need_auth": True
            }
        }
