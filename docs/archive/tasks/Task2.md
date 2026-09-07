*==模拟智能体模块。==*

>用户输入一句自然语言任务 → 模拟 Agent 判断要调用什么工具 → 生成一个“工具调用请求” → 暂时不真正执行工具→ 接到授权网关→网关决定允许、拒绝还是二次确认

在 `backend` 目录下新建一个文件`fake_agent.py

```python
import re
from typing import Dict, Any


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

        if self._is_read_file_task(user_input):
            return self._build_read_file_call(user_input)

        if self._is_delete_file_task(user_input):
            return self._build_delete_file_call(user_input)

        if self._is_shell_task(user_input):
            return self._build_shell_call(user_input)

        return {
            "agent": "FakeAgent",
            "status": "unsupported",
            "message": "当前模拟智能体暂时无法识别该任务",
            "original_input": user_input,
            "tool_call": None
        }

    def _is_send_email_task(self, text: str) -> bool:
        return "发邮件" in text or "发送邮件" in text or "send email" in text.lower()

    def _is_read_file_task(self, text: str) -> bool:
        return "读取文件" in text or "查看文件" in text or "读文件" in text

    def _is_delete_file_task(self, text: str) -> bool:
        return "删除文件" in text or "删掉文件" in text or "remove file" in text.lower()

    def _is_shell_task(self, text: str) -> bool:
        return "执行命令" in text or "运行命令" in text or "shell" in text.lower()

    def _build_send_email_call(self, text: str) -> Dict[str, Any]:
        """
        构造发送邮件工具调用。
        这里只做简单模拟，后面可以替换成大模型解析。
        """

        receiver = "unknown"
        content = "未提取到邮件正文"

        receiver_match = re.search(r"给(.+?)发邮件", text)
        if receiver_match:
            receiver = receiver_match.group(1).strip()

        content_match = re.search(r"内容[是为:：](.+)", text)
        if content_match:
            content = content_match.group(1).strip()

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
        file_path = "unknown"

        file_match = re.search(r"文件(.+)", text)
        if file_match:
            file_path = file_match.group(1).strip()

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
        file_path = "unknown"

        file_match = re.search(r"文件(.+)", text)
        if file_match:
            file_path = file_match.group(1).strip()

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

        command_match = re.search(r"命令[是为:：](.+)", text)
        if command_match:
            command = command_match.group(1).strip()

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
```

同时修改一下main.py，把 `fake_agent.py` 接进来。

```python
from fastapi import FastAPI
from pydantic import BaseModel

from backend.schemas import ToolCallRequest, GatewayResponse
from backend.gateway import check_tool_call
from backend.tool_executor import execute_tool
from backend.audit_logger import write_log, get_logs
from backend.fake_agent import FakeAgent


app = FastAPI(
    title="AI Agent Auth Gateway",
    description="面向 AI 智能体工具调用的授权与安全防护系统",
    version="0.1.0"
)

fake_agent = FakeAgent()


class AgentTextRequest(BaseModel):
    """
    模拟智能体输入请求。

    user 表示当前发起请求的用户；
    user_input 表示用户输入给智能体的自然语言任务。
    """
    user: str = "test_user"
    user_input: str


@app.get("/")
def index():
    return {
        "message": "AI Agent Auth Gateway is running"
    }


@app.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(request: ToolCallRequest):
    """
    单独测试安全网关。

    输入结构化工具调用请求，返回网关判断结果。
    """
    return check_tool_call(request)


@app.post("/agent/plan")
def agent_plan(request: AgentTextRequest):
    """
    模拟智能体规划接口。

    输入自然语言任务，只生成工具调用计划，不执行工具，也不经过网关。
    这个接口主要用于观察智能体会把用户任务转换成什么 tool_call。
    """
    plan_result = fake_agent.plan(request.user_input)

    return {
        "user": request.user,
        "agent_result": plan_result
    }


@app.post("/agent/simulate")
def agent_simulate(request: AgentTextRequest):
    """
    模拟完整智能体调用流程。

    流程：
    1. 用户输入自然语言任务；
    2. FakeAgent 生成工具调用计划；
    3. 将工具调用请求交给安全网关；
    4. 根据网关结果决定是否执行工具；
    5. 写入审计日志。
    """

    plan_result = fake_agent.plan(request.user_input)

    if plan_result["status"] != "planned" or plan_result["tool_call"] is None:
        return {
            "executed": False,
            "message": "模拟智能体未能生成有效工具调用",
            "agent_result": plan_result,
            "gateway_result": None,
            "tool_result": None
        }

    tool_call = plan_result["tool_call"]

    tool_request = ToolCallRequest(
        user=request.user,
        tool=tool_call["tool_name"],
        params=tool_call["arguments"]
    )

    check_result = check_tool_call(tool_request)

    if check_result["decision"] == "deny":
        write_log(
            user=tool_request.user,
            tool=tool_request.tool,
            params=tool_request.params,
            gateway_result=check_result,
            executed=False
        )

        return {
            "executed": False,
            "message": "智能体生成的工具调用已被安全网关拦截",
            "agent_result": plan_result,
            "gateway_result": check_result,
            "tool_result": None
        }

    if check_result["decision"] == "confirm":
        write_log(
            user=tool_request.user,
            tool=tool_request.tool,
            params=tool_request.params,
            gateway_result=check_result,
            executed=False
        )

        return {
            "executed": False,
            "message": "智能体生成的工具调用需要人工确认，暂不执行",
            "agent_result": plan_result,
            "gateway_result": check_result,
            "tool_result": None
        }

    tool_result = execute_tool(tool_request.tool, tool_request.params)

    write_log(
        user=tool_request.user,
        tool=tool_request.tool,
        params=tool_request.params,
        gateway_result=check_result,
        executed=True
    )

    return {
        "executed": True,
        "message": "智能体生成的工具调用已通过安全检查并执行",
        "agent_result": plan_result,
        "gateway_result": check_result,
        "tool_result": tool_result
    }


@app.post("/agent/call")
def agent_call(request: ToolCallRequest):
    """
    结构化工具调用接口。

    这个接口不是自然语言输入，而是直接输入 tool 和 params。
    适合单独测试安全网关和工具执行模块。
    """

    check_result = check_tool_call(request)

    if check_result["decision"] == "deny":
        write_log(
            user=request.user,
            tool=request.tool,
            params=request.params,
            gateway_result=check_result,
            executed=False
        )

        return {
            "executed": False,
            "message": "工具调用已被安全网关拦截",
            "gateway_result": check_result,
            "tool_result": None
        }

    if check_result["decision"] == "confirm":
        write_log(
            user=request.user,
            tool=request.tool,
            params=request.params,
            gateway_result=check_result,
            executed=False
        )

        return {
            "executed": False,
            "message": "工具调用需要人工确认，暂不执行",
            "gateway_result": check_result,
            "tool_result": None
        }

    tool_result = execute_tool(request.tool, request.params)

    write_log(
        user=request.user,
        tool=request.tool,
        params=request.params,
        gateway_result=check_result,
        executed=True
    )

    return {
        "executed": True,
        "message": "工具调用已通过安全检查并执行",
        "gateway_result": check_result,
        "tool_result": tool_result
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

保存并运行。

>运行方式还是不变，详见[[运行方式1]]。

那么到目前为止，我们已经成功完成了：

```text
自然语言输入
    ↓
fake_agent.py 生成 tool_call
    ↓
main.py 的 /agent/simulate 接口接收
    ↓
gateway.py 做安全判断
    ↓
tool_executor.py 执行
    ↓
audit_logger.py 写入审计日志
```


*==但是这里也暴露出一个需要改进的地方：

```JSON
"tool": "email.send",
"decision": "allow",
"risk_score": 0,
"reason": [
  "未发现明显风险"
]
```

对于“发邮件”这种外部动作，直接 `allow` 且风险分为 0 不太合理。正常来说，发邮件至少应该是：

```text
email.send → confirm
```

那么我们下一步就要修改授权网关规则，让 `gateway.py` 正确识别这些新工具名：

```text
email.send
file.read
file.delete
shell.run
```

并给它们设置不同的风险等级。

那么我们修改一下 `gateway.py`：

```python
from backend.schemas import ToolCallRequest


def check_tool_call(request: ToolCallRequest):
    risk_score = 0
    reason = []

    user = request.user
    tool = request.tool
    params = request.params

    tool_lower = tool.lower()

    # 兼容不同字段名：
    # 旧版本可能使用 path，新版本 fake_agent.py 使用 file_path
    path = str(
        params.get("path")
        or params.get("file_path")
        or params.get("filename")
        or params.get("target")
        or ""
    )

    to = str(params.get("to", ""))
    content = str(params.get("content", ""))
    command = str(params.get("command", ""))

    path_lower = path.lower()
    content_lower = content.lower()
    command_lower = command.lower()

    # 1. 工具自身风险判断
    if tool_lower in ["run_code", "shell.run", "execute_command", "command.run"]:
        risk_score += 80
        reason.append("系统命令或代码执行工具风险极高")

    elif tool_lower in ["send_email", "email.send"]:
        risk_score += 40
        reason.append("邮件发送工具存在数据外发风险，需要用户确认")

    elif tool_lower in ["delete_file", "file.delete", "remove_file"]:
        risk_score += 80
        reason.append("文件删除操作风险极高")

    elif tool_lower in ["read_file", "file.read"]:
        risk_score += 10
        reason.append("文件读取操作存在一定信息泄露风险")

    elif tool_lower in ["write_file", "file.write"]:
        risk_score += 50
        reason.append("文件写入操作可能修改本地数据")

    else:
        risk_score += 20
        reason.append("未知工具类型，存在不确定风险")

    # 2. 文件路径风险判断
    sensitive_path_keywords = [
        "secret",
        "private",
        "password",
        "key",
        "token",
        "credential",
        "config",
        ".env"
    ]

    for keyword in sensitive_path_keywords:
        if keyword in path_lower:
            risk_score += 30
            reason.append(f"访问路径包含敏感关键词：{keyword}")

    # 3. 用户权限判断
    if user == "student" and tool_lower in ["run_code", "shell.run", "execute_command", "command.run"]:
        risk_score += 40
        reason.append("student 用户无权执行系统命令或代码")

    if user == "student" and path_lower.startswith("secret/"):
        risk_score += 40
        reason.append("student 用户无权访问 secret 目录")

    # 4. 邮件外发风险判断
    if tool_lower in ["send_email", "email.send"]:
        if not to:
            risk_score += 20
            reason.append("邮件接收人为空，存在误发风险")
        elif not to.endswith("@sdu.edu.cn"):
            risk_score += 25
            reason.append("邮件发送目标为外部邮箱，存在数据外发风险")

    # 5. 内容风险判断
    dangerous_words = [
        "ignore previous rules",
        "忽略之前的规则",
        "password",
        "secret",
        "token",
        "credential",
        "delete",
        "drop table",
        "rm -rf",
        "shutdown",
        "format"
    ]

    for word in dangerous_words:
        if word.lower() in content_lower:
            risk_score += 20
            reason.append(f"内容包含危险关键词：{word}")

    # 6. 命令风险判断
    dangerous_commands = [
        "rm -rf",
        "del ",
        "format",
        "shutdown",
        "reboot",
        "taskkill",
        "drop table",
        "curl",
        "wget",
        "nc ",
        "netcat"
    ]

    for cmd in dangerous_commands:
        if cmd in command_lower:
            risk_score += 30
            reason.append(f"命令中包含高危操作：{cmd}")

    # 7. 根据风险分做最终决策
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
        "reason": reason
    }
```

重新运行测试`/agent/simulate

测试样例：

```JSON
{
  "user": "alice",
  "user_input": "给张三发邮件，内容是明天下午三点开会"
}
```

```JSON
{
  "user": "alice",
  "user_input": "删除文件：secret/password.txt"
}
```

我们发现预期分别是：

```JSON
"decision": "deny"
```

```JSON
"executed": false
```

那么此时说明网关已经能对模拟智能体生成的工具调用进行安全拦截了。

但是我们发现：

```JSON
"tool_result": {
  "success": false,
  "result": "未知工具：file.read"
}
```

```text
fake_agent.py 生成了 file.read
gateway.py 也允许了 file.read
但是 tool_executor.py 还没有实现 file.read
```

另外还有一个小问题：

```JSON
"file_path": ": README.md"
```

这里多了一个冒号，说明 `fake_agent.py` 对“读取文件：README.md”的路径提取还不够干净。我们下一步要同时修两个地方，详见[[Task3]]。