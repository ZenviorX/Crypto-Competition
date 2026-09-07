**工具调用规范化 + 风险规则优化 + 文件沙箱防护 + 人工确认机制 + 审计日志增强**。

Task1 已经完成了 FastAPI 接口、`gateway.py` 风险判断、`tool_executor.py` 模拟工具执行和 `/agent/call` 闭环；
Task2 又加入了 `fake_agent.py`，实现自然语言输入到工具调用的转换，并接入审计日志。
Task3 要解决的核心问题是：`fake_agent.py` 生成的是 `file.read / email.send / file.delete / shell.run`，但旧版执行器主要识别 `read_file / send_email / run_code`，所以需要统一工具名和参数格式，同时把 `confirm` 做成真正的人工确认流程。

---

# Task3：工具调用规范化与授权网关优化

## 一、Task3 目标

Task3 的目标是把前两步“能跑的原型”升级成更完整的安全网关系统，主要完成：

```text
1. 统一工具命名格式
2. 统一工具参数格式
3. 修复 file.read 无法被执行器识别的问题
4. 修复 FakeAgent 路径提取多冒号的问题
5. 优化 gateway.py 风险评分规则
6. 增加文件路径沙箱校验，防止路径穿越
7. 增加人工确认 pending 机制
8. 增强审计日志，记录 allow / confirm / deny 全流程
```

最终流程变成：

```text
用户自然语言输入
        ↓
FakeAgent 生成工具调用计划
        ↓
工具名和参数规范化
        ↓
gateway.py 风险评估
        ↓
allow / confirm / deny
        ↓
allow：执行工具
confirm：进入人工确认队列
deny：直接拦截
        ↓
写入审计日志
        ↓
返回结果
```

---

# 二、Task3 完整项目结构

建议你们现在项目结构调整成这样：

```text
ai-agent-auth-gateway/
│
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── schemas.py
│   ├── fake_agent.py
│   ├── gateway.py
│   ├── tool_executor.py
│   ├── audit_logger.py
│   ├── approval_store.py
│   └── utils.py
│
├── data/
│   ├── public/
│   │   └── notice.txt
│   └── secret/
│       └── password.txt
│
├── logs/
│   └── audit.log
│
├── venv/
└── requirements.txt
```

其中 `logs/` 可以不用手动创建，代码会自动创建。

---

# 三、完整代码

## 1. `backend/schemas.py`

```python
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional


class ToolCallRequest(BaseModel):
    """
    结构化工具调用请求。
    user：发起工具调用的用户
    tool：工具名称
    params：工具参数
    """
    user: str = "test_user"
    tool: str
    params: Dict[str, Any] = Field(default_factory=dict)


class GatewayResponse(BaseModel):
    """
    授权网关判断结果。
    decision:
        allow   允许执行
        confirm 需要人工确认
        deny    拒绝执行
    """
    decision: str
    risk_score: int
    reason: List[str]


class AgentTextRequest(BaseModel):
    """
    模拟智能体输入请求。
    user：当前用户
    user_input：自然语言任务
    """
    user: str = "test_user"
    user_input: str


class ApprovalRejectRequest(BaseModel):
    """
    人工拒绝确认请求。
    """
    reason: Optional[str] = "人工拒绝执行"
```

---

## 2. `backend/utils.py`

这个文件是 Task3 的关键：专门负责 **工具名规范化、参数规范化、文本清洗**。

```python
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
    主要解决：
    读取文件：README.md
    被提取成：
    : README.md
    或 ：README.md
    的问题。
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
    """
    将参数字段也统一一下，方便 gateway.py 和 tool_executor.py 使用。
    """
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
```

---

## 3. `backend/fake_agent.py`

这是 Task3 优化后的模拟智能体。重点修复了路径提取不干净的问题。

```python
import re
from typing import Dict, Any

from backend.utils import clean_text_value


class FakeAgent:
    """
    模拟智能体模块。
    它的作用不是直接执行工具，而是根据用户输入的自然语言任务，
    生成一个结构化的工具调用请求。
    """

    def plan(self, user_input: str) -> Dict[str, Any]:
        """
        根据用户输入生成工具调用计划。
        """
        user_input = user_input.strip()

        if self._is_send_email_task(user_input):
            return self._build_send_email_call(user_input)

        if self._is_delete_file_task(user_input):
            return self._build_delete_file_call(user_input)

        if self._is_read_file_task(user_input):
            return self._build_read_file_call(user_input)

        if self._is_shell_task(user_input):
            return self._build_shell_call(user_input)

        if self._is_db_query_task(user_input):
            return self._build_db_query_call(user_input)

        return {
            "agent": "FakeAgent",
            "status": "unsupported",
            "message": "当前模拟智能体暂时无法识别该任务",
            "original_input": user_input,
            "tool_call": None
        }

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

        return {
            "agent": "FakeAgent",
            "status": "planned",
            "original_input": text,
            "tool_call": {
                "tool_name": "email.send",
                "description": "发送邮件",
                "arguments": {
                    "to": receiver,
                    "subject": "模拟智能体邮件",
                    "content": content
                },
                "need_auth": True
            }
        }

    def _build_read_file_call(self, text: str) -> Dict[str, Any]:
        file_path = self._extract_file_path(text)

        return {
            "agent": "FakeAgent",
            "status": "planned",
            "original_input": text,
            "tool_call": {
                "tool_name": "file.read",
                "description": "读取文件内容",
                "arguments": {
                    "file_path": file_path
                },
                "need_auth": True
            }
        }

    def _build_delete_file_call(self, text: str) -> Dict[str, Any]:
        file_path = self._extract_file_path(text)

        return {
            "agent": "FakeAgent",
            "status": "planned",
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
```

---

## 4. `backend/gateway.py`

这是 Task3 优化后的授权网关。重点：识别新工具名，重新设计风险等级。

```python
from backend.schemas import ToolCallRequest
from backend.utils import (
    normalize_tool_name,
    normalize_params,
    get_path,
    get_content,
    get_command,
)


def check_tool_call(request: ToolCallRequest):
    """
    授权网关核心逻辑：
    1. 统一工具名
    2. 统一参数名
    3. 根据工具类型、路径、内容、用户身份等计算风险分
    4. 返回 allow / confirm / deny
    """
    risk_score = 0
    reason = []

    user = request.user
    tool = normalize_tool_name(request.tool)
    params = normalize_params(tool, request.params)

    path = get_path(params)
    content = get_content(params)
    command = get_command(params)
    sql = str(params.get("sql", ""))

    path_lower = path.lower().replace("\\", "/")
    content_lower = content.lower()
    command_lower = command.lower()
    sql_lower = sql.lower()
    user_lower = user.lower()

    # 1. 工具自身风险判断
    if tool == "shell.run":
        risk_score += 80
        reason.append("系统命令或代码执行工具风险极高")

    elif tool == "file.delete":
        risk_score += 80
        reason.append("文件删除操作风险极高")

    elif tool == "email.send":
        risk_score += 40
        reason.append("邮件发送工具存在数据外发风险，需要用户确认")

    elif tool == "file.write":
        risk_score += 50
        reason.append("文件写入操作可能修改本地数据")

    elif tool == "file.read":
        risk_score += 10
        reason.append("文件读取操作存在一定信息泄露风险")

    elif tool == "db.query":
        risk_score += 20
        reason.append("数据库查询操作存在一定数据泄露风险")

    else:
        risk_score += 30
        reason.append("未知工具类型，存在不确定风险")

    # 2. 文件路径风险判断
    sensitive_path_keywords = [
        "secret",
        "private",
        "password",
        "passwd",
        "key",
        "token",
        "credential",
        "config",
        ".env",
        "shadow",
        "id_rsa",
    ]

    for keyword in sensitive_path_keywords:
        if keyword in path_lower:
            risk_score += 30
            reason.append(f"访问路径包含敏感关键词：{keyword}")

    # 3. 路径穿越风险判断
    if ".." in path_lower:
        risk_score += 60
        reason.append("路径中包含 ..，可能存在路径穿越风险")

    if path_lower.startswith("/") or ":" in path_lower:
        risk_score += 40
        reason.append("路径疑似绝对路径，存在越权访问风险")

    # 4. 用户权限判断
    if user_lower == "student" and tool == "shell.run":
        risk_score += 40
        reason.append("student 用户无权执行系统命令")

    if user_lower == "student" and path_lower.startswith("secret/"):
        risk_score += 40
        reason.append("student 用户无权访问 secret 目录")

    if user_lower in ["guest", "anonymous"] and tool in ["email.send", "file.write", "file.delete", "shell.run"]:
        risk_score += 40
        reason.append("低权限用户无权执行该类高风险工具")

    # 5. 邮件外发风险判断
    if tool == "email.send":
        to = str(params.get("to", "")).strip()

        if not to or to == "unknown":
            risk_score += 20
            reason.append("邮件接收人为空或无法识别，存在误发风险")

        elif not to.endswith("@sdu.edu.cn"):
            risk_score += 25
            reason.append("邮件发送目标不是校内邮箱，存在数据外发风险")

        if any(word in content_lower for word in ["password", "secret", "token", "密钥", "密码"]):
            risk_score += 30
            reason.append("邮件内容包含敏感信息关键词")

    # 6. 内容风险判断
    dangerous_words = [
        "ignore previous rules",
        "ignore previous instructions",
        "忽略之前的规则",
        "忽略以上要求",
        "password",
        "secret",
        "token",
        "credential",
        "delete",
        "drop table",
        "rm -rf",
        "shutdown",
        "format",
        "绕过",
        "越权",
    ]

    for word in dangerous_words:
        if word.lower() in content_lower:
            risk_score += 20
            reason.append(f"内容包含危险关键词：{word}")

    # 7. 命令风险判断
    dangerous_commands = [
        "rm -rf",
        "del ",
        "format",
        "shutdown",
        "reboot",
        "taskkill",
        "curl",
        "wget",
        "nc ",
        "netcat",
        "chmod 777",
        "powershell",
    ]

    for cmd in dangerous_commands:
        if cmd in command_lower:
            risk_score += 30
            reason.append(f"命令中包含高危操作：{cmd}")

    # 8. SQL 风险判断
    dangerous_sql = [
        "drop table",
        "delete from",
        "truncate",
        "update ",
        "insert into",
        "alter table",
        "create table",
    ]

    if tool == "db.query":
        for keyword in dangerous_sql:
            if keyword in sql_lower:
                risk_score += 50
                reason.append(f"SQL 语句包含高危操作：{keyword}")

        if sql_lower and not sql_lower.strip().startswith("select"):
            risk_score += 30
            reason.append("当前数据库工具只建议执行 SELECT 查询")

    # 9. 根据风险分做最终决策
    if risk_score >= 70:
        decision = "deny"
    elif risk_score >= 40:
        decision = "confirm"
    else:
        decision = "allow"

    if not reason:
        reason.append("未发现明显风险")

    return {
        "decision": decision,
        "risk_score": risk_score,
        "reason": reason,
        "normalized_tool": tool,
        "normalized_params": params,
    }
```

---

## 5. `backend/tool_executor.py`

这是 Task3 修复最关键的地方：让执行器真正支持 `file.read / email.send / file.delete / shell.run`。

注意：`file.delete` 和 `shell.run` 这里只做模拟，不真实删除文件、不真实执行命令。

```python
from pathlib import Path

from backend.utils import normalize_tool_name, normalize_params, get_path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def execute_tool(tool: str, params: dict):
    """
    工具执行入口。
    这里只执行被网关 allow 或人工确认后的工具调用。
    """
    tool = normalize_tool_name(tool)
    params = normalize_params(tool, params)

    if tool == "file.read":
        return read_file(params)

    if tool == "email.send":
        return send_email(params)

    if tool == "file.delete":
        return delete_file(params)

    if tool == "shell.run":
        return run_shell(params)

    if tool == "db.query":
        return query_db(params)

    if tool == "file.write":
        return write_file(params)

    return {
        "success": False,
        "result": f"未知工具：{tool}"
    }


def _safe_data_path(path: str):
    """
    将用户传入路径限制在 data/ 目录内。
    防止路径穿越：
    ../../Windows/System32
    ../secret/password.txt
    C:\\Users\\xxx\\.env
    """
    if not path:
        return None, "文件路径为空"

    raw_path = Path(path)

    if raw_path.is_absolute():
        return None, "非法路径：禁止使用绝对路径"

    base_dir = DATA_DIR.resolve()
    target_path = (DATA_DIR / path).resolve()

    try:
        target_path.relative_to(base_dir)
    except ValueError:
        return None, "非法路径：禁止访问 data 目录之外的文件"

    return target_path, None


def read_file(params: dict):
    path = get_path(params)
    file_path, error = _safe_data_path(path)

    if error:
        return {
            "success": False,
            "result": error
        }

    if not file_path.exists():
        return {
            "success": False,
            "result": "文件不存在"
        }

    if not file_path.is_file():
        return {
            "success": False,
            "result": "目标不是普通文件"
        }

    content = file_path.read_text(encoding="utf-8")

    return {
        "success": True,
        "result": content
    }


def send_email(params: dict):
    to = params.get("to", "")
    subject = params.get("subject", "模拟智能体邮件")
    content = params.get("content", "")

    return {
        "success": True,
        "result": {
            "message": "模拟发送邮件成功",
            "to": to,
            "subject": subject,
            "content": content
        }
    }


def delete_file(params: dict):
    """
    比赛原型阶段不真实删除文件，只模拟。
    真实项目中，即使人工确认，也应进行更严格的二次校验。
    """
    path = get_path(params)

    return {
        "success": True,
        "result": f"模拟删除文件：{path}。注意：原型系统未真实删除文件。"
    }


def run_shell(params: dict):
    """
    比赛原型阶段不真实执行系统命令，只模拟。
    """
    command = params.get("command", "")

    return {
        "success": True,
        "result": f"模拟执行系统命令：{command}。注意：原型系统未真实执行命令。"
    }


def query_db(params: dict):
    sql = params.get("sql", "")

    return {
        "success": True,
        "result": f"模拟执行数据库查询：{sql}"
    }


def write_file(params: dict):
    """
    原型阶段只模拟写文件，不真实写入。
    """
    path = get_path(params)
    content = params.get("content", "")

    return {
        "success": True,
        "result": {
            "message": "模拟写入文件成功，原型系统未真实写入",
            "path": path,
            "content": content
        }
    }
```

---

## 6. `backend/audit_logger.py`

审计日志增强版，记录每次请求、决策、风险分、是否执行等信息。

```python
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import uuid4


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "audit.log"


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _mask_sensitive_value(key: str, value: Any):
    """
    简单脱敏，避免日志里直接保存 password、token、key 等敏感值。
    """
    key_lower = key.lower()

    if any(word in key_lower for word in ["password", "token", "secret", "key", "credential"]):
        return "***MASKED***"

    if isinstance(value, dict):
        return {k: _mask_sensitive_value(k, v) for k, v in value.items()}

    return value


def _mask_params(params: Dict[str, Any]):
    if not isinstance(params, dict):
        return params

    return {k: _mask_sensitive_value(k, v) for k, v in params.items()}


def write_log(
    user: str,
    tool: str,
    params: Dict[str, Any],
    gateway_result: Dict[str, Any],
    executed: bool,
    original_input: Optional[str] = None,
    message: Optional[str] = None,
    pending_id: Optional[str] = None,
    tool_result: Optional[Dict[str, Any]] = None,
):
    """
    写入一条审计日志。
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    record = {
        "request_id": str(uuid4()),
        "time": _now(),
        "user": user,
        "original_input": original_input,
        "tool": tool,
        "params": _mask_params(params),
        "decision": gateway_result.get("decision"),
        "risk_score": gateway_result.get("risk_score"),
        "reason": gateway_result.get("reason"),
        "executed": executed,
        "pending_id": pending_id,
        "message": message,
        "tool_result": tool_result,
    }

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def get_logs(limit: int = 50):
    """
    读取最近 limit 条审计日志。
    """
    if not LOG_FILE.exists():
        return []

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    lines = lines[-limit:]

    logs = []
    for line in lines:
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return logs[::-1]
```

---

## 7. `backend/approval_store.py`

人工确认队列。`confirm` 的请求不会直接执行，而是生成 `pending_id`，等待人工确认。

```python
from datetime import datetime
from uuid import uuid4
from typing import Dict, Any, Optional


PENDING_REQUESTS: Dict[str, Dict[str, Any]] = {}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _model_to_dict(model):
    """
    兼容 Pydantic v1 和 v2。
    """
    if hasattr(model, "model_dump"):
        return model.model_dump()

    return model.dict()


def create_pending_request(
    tool_request,
    gateway_result: Dict[str, Any],
    original_input: Optional[str] = None,
    agent_result: Optional[Dict[str, Any]] = None,
):
    pending_id = str(uuid4())

    PENDING_REQUESTS[pending_id] = {
        "pending_id": pending_id,
        "status": "pending",
        "created_at": _now(),
        "tool_request": _model_to_dict(tool_request),
        "gateway_result": gateway_result,
        "original_input": original_input,
        "agent_result": agent_result,
    }

    return pending_id


def list_pending_requests(limit: int = 50):
    items = list(PENDING_REQUESTS.values())
    items = items[-limit:]
    return items[::-1]


def get_pending_request(pending_id: str):
    return PENDING_REQUESTS.get(pending_id)


def pop_pending_request(pending_id: str):
    return PENDING_REQUESTS.pop(pending_id, None)
```

---

## 8. `backend/main.py`

这是 Task3 完整入口，包含：

```text
/gateway/check
/agent/plan
/agent/simulate
/agent/call
/approval/pending
/approval/confirm/{pending_id}
/approval/reject/{pending_id}
/audit/logs
```

```python
from fastapi import FastAPI

from backend.schemas import (
    ToolCallRequest,
    GatewayResponse,
    AgentTextRequest,
    ApprovalRejectRequest,
)
from backend.gateway import check_tool_call
from backend.tool_executor import execute_tool
from backend.audit_logger import write_log, get_logs
from backend.fake_agent import FakeAgent
from backend.utils import normalize_tool_name, normalize_params
from backend.approval_store import (
    create_pending_request,
    list_pending_requests,
    get_pending_request,
    pop_pending_request,
)


app = FastAPI(
    title="AI Agent Auth Gateway",
    description="面向 AI 智能体工具调用的授权与安全防护系统",
    version="0.3.0"
)

fake_agent = FakeAgent()


@app.get("/")
def index():
    return {
        "message": "AI Agent Auth Gateway is running",
        "version": "0.3.0",
        "task": "Task3 - 工具调用规范化与授权网关优化"
    }


@app.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(request: ToolCallRequest):
    """
    单独测试安全网关。
    输入结构化工具调用请求，返回网关判断结果。
    """
    result = check_tool_call(request)

    return {
        "decision": result["decision"],
        "risk_score": result["risk_score"],
        "reason": result["reason"]
    }


@app.post("/agent/plan")
def agent_plan(request: AgentTextRequest):
    """
    模拟智能体规划接口。
    输入自然语言任务，只生成工具调用计划，不执行工具，也不经过网关。
    """
    plan_result = fake_agent.plan(request.user_input)

    return {
        "user": request.user,
        "agent_result": plan_result
    }


def _handle_tool_request(
    request: ToolCallRequest,
    original_input: str = None,
    agent_result: dict = None,
):
    """
    统一处理工具调用：
    1. 规范化工具名和参数
    2. 网关检查
    3. allow 则执行
    4. confirm 则进入人工确认队列
    5. deny 则拦截
    6. 全流程写入审计日志
    """
    normalized_tool = normalize_tool_name(request.tool)
    normalized_params = normalize_params(normalized_tool, request.params)

    normalized_request = ToolCallRequest(
        user=request.user,
        tool=normalized_tool,
        params=normalized_params
    )

    check_result = check_tool_call(normalized_request)

    # deny：直接拦截
    if check_result["decision"] == "deny":
        write_log(
            user=normalized_request.user,
            tool=normalized_request.tool,
            params=normalized_request.params,
            gateway_result=check_result,
            executed=False,
            original_input=original_input,
            message="工具调用已被安全网关拦截",
        )

        return {
            "executed": False,
            "message": "工具调用已被安全网关拦截",
            "agent_result": agent_result,
            "gateway_result": check_result,
            "tool_result": None,
            "pending_id": None
        }

    # confirm：进入人工确认队列
    if check_result["decision"] == "confirm":
        pending_id = create_pending_request(
            tool_request=normalized_request,
            gateway_result=check_result,
            original_input=original_input,
            agent_result=agent_result,
        )

        write_log(
            user=normalized_request.user,
            tool=normalized_request.tool,
            params=normalized_request.params,
            gateway_result=check_result,
            executed=False,
            original_input=original_input,
            message="工具调用需要人工确认，已进入 pending 队列",
            pending_id=pending_id,
        )

        return {
            "executed": False,
            "message": "工具调用需要人工确认，已进入 pending 队列",
            "agent_result": agent_result,
            "gateway_result": check_result,
            "tool_result": None,
            "pending_id": pending_id
        }

    # allow：直接执行
    tool_result = execute_tool(
        normalized_request.tool,
        normalized_request.params
    )

    write_log(
        user=normalized_request.user,
        tool=normalized_request.tool,
        params=normalized_request.params,
        gateway_result=check_result,
        executed=True,
        original_input=original_input,
        message="工具调用已通过安全检查并执行",
        tool_result=tool_result,
    )

    return {
        "executed": True,
        "message": "工具调用已通过安全检查并执行",
        "agent_result": agent_result,
        "gateway_result": check_result,
        "tool_result": tool_result,
        "pending_id": None
    }


@app.post("/agent/simulate")
def agent_simulate(request: AgentTextRequest):
    """
    模拟完整智能体调用流程。
    流程：
    1. 用户输入自然语言任务
    2. FakeAgent 生成工具调用计划
    3. 将工具调用请求交给安全网关
    4. 根据网关结果决定执行、拦截或进入人工确认
    5. 写入审计日志
    """
    plan_result = fake_agent.plan(request.user_input)

    if plan_result["status"] != "planned" or plan_result["tool_call"] is None:
        return {
            "executed": False,
            "message": "模拟智能体未能生成有效工具调用",
            "agent_result": plan_result,
            "gateway_result": None,
            "tool_result": None,
            "pending_id": None
        }

    tool_call = plan_result["tool_call"]

    tool_request = ToolCallRequest(
        user=request.user,
        tool=tool_call["tool_name"],
        params=tool_call["arguments"]
    )

    return _handle_tool_request(
        request=tool_request,
        original_input=request.user_input,
        agent_result=plan_result,
    )


@app.post("/agent/call")
def agent_call(request: ToolCallRequest):
    """
    结构化工具调用接口。
    这个接口不是自然语言输入，而是直接输入 tool 和 params。
    """
    return _handle_tool_request(request=request)


@app.get("/approval/pending")
def approval_pending(limit: int = 50):
    """
    查看所有待人工确认的工具调用请求。
    """
    return {
        "pending": list_pending_requests(limit)
    }


@app.post("/approval/confirm/{pending_id}")
def approval_confirm(pending_id: str):
    """
    人工确认执行某个 pending 请求。
    确认后才真正调用 tool_executor.py。
    """
    pending = pop_pending_request(pending_id)

    if pending is None:
        return {
            "success": False,
            "message": "pending_id 不存在或已经被处理"
        }

    tool_request_data = pending["tool_request"]

    tool_request = ToolCallRequest(
        user=tool_request_data["user"],
        tool=tool_request_data["tool"],
        params=tool_request_data["params"]
    )

    tool_result = execute_tool(tool_request.tool, tool_request.params)

    gateway_result = pending["gateway_result"]
    gateway_result["decision"] = "confirmed"

    write_log(
        user=tool_request.user,
        tool=tool_request.tool,
        params=tool_request.params,
        gateway_result=gateway_result,
        executed=True,
        original_input=pending.get("original_input"),
        message="人工确认后执行工具调用",
        pending_id=pending_id,
        tool_result=tool_result,
    )

    return {
        "success": True,
        "message": "人工确认成功，工具调用已执行",
        "pending_id": pending_id,
        "tool_request": tool_request_data,
        "tool_result": tool_result
    }


@app.post("/approval/reject/{pending_id}")
def approval_reject(pending_id: str, request: ApprovalRejectRequest):
    """
    人工拒绝某个 pending 请求。
    """
    pending = pop_pending_request(pending_id)

    if pending is None:
        return {
            "success": False,
            "message": "pending_id 不存在或已经被处理"
        }

    tool_request_data = pending["tool_request"]

    gateway_result = pending["gateway_result"]
    gateway_result["decision"] = "rejected"

    write_log(
        user=tool_request_data["user"],
        tool=tool_request_data["tool"],
        params=tool_request_data["params"],
        gateway_result=gateway_result,
        executed=False,
        original_input=pending.get("original_input"),
        message=request.reason,
        pending_id=pending_id,
    )

    return {
        "success": True,
        "message": "已人工拒绝该工具调用",
        "pending_id": pending_id,
        "reason": request.reason
    }


@app.get("/audit/logs")
def audit_logs(limit: int = 50):
    """
    查看审计日志。
    """
    return {
        "logs": get_logs(limit)
    }
```

---

# 四、测试数据准备

在项目根目录创建：

```text
data/public/notice.txt
data/secret/password.txt
```

`data/public/notice.txt` 内容：

```text
这是公开通知文件，可以被正常读取。
```

`data/secret/password.txt` 内容：

```text
admin_password=123456
```

---

# 五、运行方式

在项目根目录运行：

```bash
venv\Scripts\activate
uvicorn backend.main:app --reload
```

然后打开：

```text
http://127.0.0.1:8000/docs
```

---

# 六、测试样例

## 1. 测试普通文件读取：应该 allow 并执行

接口：

```text
POST /agent/simulate
```

请求：

```json
{
  "user": "alice",
  "user_input": "读取文件：public/notice.txt"
}
```

预期：

```text
decision: allow
executed: true
tool_result: 读取到 notice.txt 内容
```

---

## 2. 测试敏感文件读取：应该 deny

请求：

```json
{
  "user": "student",
  "user_input": "读取文件：secret/password.txt"
}
```

预期：

```text
decision: deny
executed: false
reason 中包含 secret / password / student 无权访问
```

---

## 3. 测试发送邮件：应该 confirm

请求：

```json
{
  "user": "alice",
  "user_input": "给张三发邮件，内容是明天下午三点开会"
}
```

预期：

```text
decision: confirm
executed: false
pending_id: 系统生成一个 UUID
```

然后查看待确认列表：

```text
GET /approval/pending
```

再人工确认：

```text
POST /approval/confirm/{pending_id}
```

确认后预期：

```text
success: true
message: 人工确认成功，工具调用已执行
tool_result: 模拟发送邮件成功
```

---

## 4. 测试删除文件：应该 deny

请求：

```json
{
  "user": "alice",
  "user_input": "删除文件：public/notice.txt"
}
```

预期：

```text
decision: deny
executed: false
reason: 文件删除操作风险极高
```

---

## 5. 测试执行命令：应该 deny

请求：

```json
{
  "user": "student",
  "user_input": "执行命令：rm -rf /"
}
```

预期：

```text
decision: deny
executed: false
reason: 系统命令或代码执行工具风险极高
```

---

## 6. 测试路径穿越：应该 deny

请求：

```json
{
  "user": "alice",
  "user_input": "读取文件：../../secret/password.txt"
}
```

预期：

```text
decision: deny
executed: false
reason: 路径中包含 ..，可能存在路径穿越风险
```

---

## 7. 查看审计日志

接口：

```text
GET /audit/logs
```

预期可以看到类似：

```json
{
  "user": "alice",
  "original_input": "给张三发邮件，内容是明天下午三点开会",
  "tool": "email.send",
  "decision": "confirm",
  "risk_score": 65,
  "executed": false,
  "pending_id": "xxxx-xxxx-xxxx"
}
```

---

# 七、Task3 报告里可以这样写

## Task3 实现思路

Task3 在 Task1 和 Task2 的基础上，进一步对系统进行了工程化和安全性优化。前两步中，系统已经能够接收工具调用请求、进行风险判断，并通过 FakeAgent 将自然语言任务转换为结构化工具调用。但是在测试过程中发现，模拟智能体生成的工具名与工具执行器支持的工具名不完全一致，例如 FakeAgent 生成 `file.read`，而旧版执行器主要识别 `read_file`，导致网关允许后执行器无法执行。此外，部分参数字段也存在不统一的问题，例如旧版使用 `path`，新版使用 `file_path`。因此，Task3 首先增加了工具名和参数规范化模块，对不同来源的工具调用格式进行统一处理。

在安全规则方面，Task3 重新设计了风险评分机制。系统会根据工具类型、文件路径、用户身份、邮件目标、文本内容、命令内容和 SQL 内容等因素计算风险分。其中，普通文件读取属于低风险操作，可以在安全路径下直接执行；邮件发送属于中风险操作，需要人工确认；文件删除和系统命令执行属于高风险操作，默认直接拦截。为了防止智能体通过路径穿越访问系统敏感文件，Task3 还在工具执行器中加入了基于 `data/` 目录的沙箱限制，确保所有文件读取都只能发生在项目允许的数据目录内。

此外，Task3 增加了人工确认机制。当网关判断某个请求为 `confirm` 时，系统不会立即执行工具，而是生成一个 `pending_id`，将请求加入待确认队列。管理员或用户可以通过 `/approval/pending` 查看待确认请求，并通过 `/approval/confirm/{pending_id}` 或 `/approval/reject/{pending_id}` 进行确认或拒绝。最后，系统对每次工具调用进行审计日志记录，包括用户、原始输入、工具名、参数、风险分、决策结果、执行状态和待确认编号等信息，从而形成“规划—授权—确认—执行—审计”的完整闭环。

---

# 八、Task3 完成后的项目亮点

你们后续答辩可以重点说这几个点：

```text
1. 工具调用规范化
   兼容 read_file / file.read 等不同工具命名方式。

2. 参数格式统一
   兼容 path / file_path / filename 等不同字段。

3. 风险评分机制
   按工具类型、路径、用户身份、内容关键词等多维度评分。

4. 文件沙箱防护
   限制智能体只能读取 data/ 目录内的文件，防止路径穿越。

5. 人工确认机制
   中风险操作不会直接执行，而是进入 pending 队列等待确认。

6. 审计日志
   记录每次智能体工具调用行为，便于追踪和复盘。
```

---

# 九、Task3 最终总结

Task3 完成后，你们的系统就不再只是简单的 FastAPI Demo，而是一个比较完整的 **AI Agent 工具调用授权网关原型**：

```text
自然语言任务
↓
模拟智能体规划工具调用
↓
工具名与参数规范化
↓
授权网关风险评分
↓
allow / confirm / deny
↓
直接执行 / 人工确认 / 安全拦截
↓
审计日志记录
```

这一步的核心价值是：**让智能体不能随便调用工具，而是必须经过授权、安全判断、人工确认和审计记录。**这正好贴合你们“智能体授权与安全防护系统”的信安赛方向。