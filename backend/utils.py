from typing import Dict, Any


TOOL_NAME_MAP = {
    # 旧版本工具名 → 新版本标准工具名
    "read_file": "file.read",
    "send_email": "email.send",
    "delete_file": "file.delete",
    "remove_file": "file.delete",
    "run_code": "shell.run",
    "execute_command": "shell.run",
    "command.run": "shell.run",
    "query_db": "db.query",
    "db_query": "db.query",
}


def normalize_tool_name(tool: str) -> str:
    """
    将不同来源的工具名统一成标准格式。
    例如：
    read_file  → file.read
    send_email → email.send
    run_code   → shell.run
    """
    if not tool:
        return "unknown"

    tool = tool.strip().lower()
    return TOOL_NAME_MAP.get(tool, tool)


def clean_text_value(value: Any) -> str:
    """
    清洗 FakeAgent 从自然语言里提取出来的参数。
    """
    if value is None:
        return ""

    value = str(value).strip()
    value = value.lstrip(":：").strip()
    value = value.strip('"').strip("'").strip()
    return value


def get_path(params: Dict[str, Any]) -> str:
    """
    兼容不同版本的路径字段。
    旧版可能叫 path，新版 fake_agent.py 可能叫 file_path。
    """
    path = (
        params.get("path")
        or params.get("file_path")
        or params.get("filename")
        or params.get("target")
        or ""
    )
    return clean_text_value(path)


def get_content(params: Dict[str, Any]) -> str:
    """
    统一获取文本内容字段。
    """
    return clean_text_value(
        params.get("content")
        or params.get("body")
        or params.get("text")
        or ""
    )


def get_command(params: Dict[str, Any]) -> str:
    """
    统一获取命令字段。
    """
    return clean_text_value(
        params.get("command")
        or params.get("cmd")
        or params.get("code")
        or ""
    )


def normalize_params(tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if params is None:
        params = {}

    tool = normalize_tool_name(tool)
    normalized = dict(params)

    if tool in ["file.read", "file.delete", "file.write"]:
        normalized["path"] = get_path(params)

    if tool == "email.send":
        normalized["to"] = clean_text_value(params.get("to", ""))
        normalized["subject"] = clean_text_value(params.get("subject", "模拟智能体邮件"))
        normalized["content"] = get_content(params)

    if tool == "shell.run":
        normalized["command"] = get_command(params)

    if tool == "db.query":
        normalized["sql"] = clean_text_value(params.get("sql", ""))

    return normalized