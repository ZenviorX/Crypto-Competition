*==把项目环境建起来，并跑通一个最简单的 FastAPI 接口。==*
- 首先至少要知道什么是FastAPI 接口吧。
# 什么是FastAPI 接口？

你用 Python 写一个“网址入口”，别人访问这个入口时，你的程序会接收请求、执行逻辑、返回结果。

比如你们这个项目里，智能体想调用工具之前，可以先请求你们的授权系统：
>智能体请求：我要读取文件 read_file
>FastAPI 接口：检查权限和风险
>返回结果：允许 / 拦截 / 需要人工确认

还是太抽象了，我们举个例子：

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def hello():
    return {"message": "Hello World"}
```

>解释一下：
>```python
>app = FastAPI()
>```
>表示创建一个 FastAPI 后端应用。
>```python
>@app.get("/")
>```
>表示定义一个 **GET 请求接口**，路径是 `/`。也就是说 FastAPI 在收到访问 `/` 的 GET 请求时，调用下面这个函数。

# 那么我们正式开始项目

>主要完成了项目后端基础环境的搭建，并成功跑通了一个最简单的 FastAPI 接口。当前工作的重点不是实现完整业务逻辑，而是先验证后端服务能够正常启动、接口能够正常访问，为后续的智能体授权、安全网关、工具调用控制、日志审计等模块打基础。

## 虚拟环境搭建

>别忘了先改路径
>```python
>cd D:\信安赛\ai-agent-auth-gateway  
>```


在终端输入：

```python
python -m venv venv
```

然后激活虚拟环境：

```python
venv\Scripts\activate
```

## 安装 FastAPI

```python
pip install fastapi uvicorn
```

安装完成后，再输入：

```python
pip freeze > requirements.txt
```

这样会生成一个 `requirements.txt`，记录项目依赖。

那么目前的项目结构：

```text
你的项目文件夹/
├── backend/
│   └── main.py
├── venv/
└── requirements.txt
```

**main.py**

```python
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, List


app = FastAPI(
    title="AI Agent Auth Gateway",
    description="面向 AI 智能体工具调用的授权与安全防护系统",
    version="0.1.0"
)


class ToolCallRequest(BaseModel):
    user: str
    tool: str
    params: Dict[str, Any]


class GatewayResponse(BaseModel):
    decision: str
    risk_score: int
    reason: List[str]


@app.get("/")
def index():
    return {
        "message": "AI Agent Auth Gateway is running"
    }


@app.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(request: ToolCallRequest):
    risk_score = 0
    reason = []

    user = request.user
    tool = request.tool
    params = request.params

    # 1. 工具风险判断
    if tool == "run_code":
        risk_score += 40
        reason.append("代码执行工具风险较高")

    if tool == "send_email":
        risk_score += 20
        reason.append("邮件发送工具存在数据外发风险")

    # 2. 文件路径风险判断
    path = str(params.get("path", ""))

    if "secret" in path or "private" in path:
        risk_score += 30
        reason.append("访问路径包含敏感目录")

    if "password" in path or "key" in path:
        risk_score += 30
        reason.append("访问路径包含敏感关键词")

    # 3. 用户权限判断
    if user == "student" and tool == "run_code":
        risk_score += 40
        reason.append("student 用户无权执行代码")

    if user == "student" and path.startswith("secret/"):
        risk_score += 40
        reason.append("student 用户无权访问 secret 目录")

    # 4. 邮件外发风险判断
    to = str(params.get("to", ""))

    if tool == "send_email" and to and not to.endswith("@sdu.edu.cn"):
        risk_score += 25
        reason.append("邮件发送目标为外部邮箱")

    # 5. 内容风险判断
    content = str(params.get("content", ""))

    dangerous_words = [
        "ignore previous rules",
        "忽略之前的规则",
        "password",
        "secret",
        "delete",
        "drop table"
    ]

    for word in dangerous_words:
        if word.lower() in content.lower():
            risk_score += 20
            reason.append(f"内容包含危险关键词：{word}")

    # 6. 根据风险分做最终决策
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

运行终端：

```python
uvicorn backend.main:app --reload
```

打开网址：

```text
http://127.0.0.1:8000/docs
```

那么就可以开始测试功能了。

>给几个测试样例：
>```JSON
>{
  "user": "student",
  "tool": "read_file",
  "params": {"path": "secret/password.txt"}
}
>```
>```JSON
>{
  "user": "student",
  "tool": "read_file",
  "params": {"path": "secret/password.txt"}
}
>```

很好，你现在已经完成了项目第一个可运行版本。

那么现在把他变得更像一个“项目“：

```text
backend/
│
├── main.py          # 接口入口
├── schemas.py       # 请求和响应格式
└── gateway.py       # 网关判断逻辑
```

也就是说现在是：

```text
你的项目文件夹/
│
├── backend/
│   ├── main.py
│   ├── schemas.py
│   └── gateway.py
│
├── venv/
│
└── requirements.txt
```

**main.py**

```python
from fastapi import FastAPI
from schemas import ToolCallRequest, GatewayResponse
from gateway import check_tool_call


app = FastAPI(
    title="AI Agent Auth Gateway",
    description="面向 AI 智能体工具调用的授权与安全防护系统",
    version="0.1.0"
)


@app.get("/")
def index():
    return {
        "message": "AI Agent Auth Gateway is running"
    }


@app.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(request: ToolCallRequest):
    return check_tool_call(request)
```

**schemas.py**

```python
from pydantic import BaseModel
from typing import Dict, Any, List


class ToolCallRequest(BaseModel):
    user: str
    tool: str
    params: Dict[str, Any]


class GatewayResponse(BaseModel):
    decision: str
    risk_score: int
    reason: List[str]
```

**gateway.py**

```python
from schemas import ToolCallRequest


def check_tool_call(request: ToolCallRequest):
    risk_score = 0
    reason = []

    user = request.user
    tool = request.tool
    params = request.params

    # 1. 工具风险判断
    if tool == "run_code":
        risk_score += 40
        reason.append("代码执行工具风险较高")

    if tool == "send_email":
        risk_score += 20
        reason.append("邮件发送工具存在数据外发风险")

    # 2. 文件路径风险判断
    path = str(params.get("path", ""))

    if "secret" in path or "private" in path:
        risk_score += 30
        reason.append("访问路径包含敏感目录")

    if "password" in path or "key" in path:
        risk_score += 30
        reason.append("访问路径包含敏感关键词")

    # 3. 用户权限判断
    if user == "student" and tool == "run_code":
        risk_score += 40
        reason.append("student 用户无权执行代码")

    if user == "student" and path.startswith("secret/"):
        risk_score += 40
        reason.append("student 用户无权访问 secret 目录")

    # 4. 邮件外发风险判断
    to = str(params.get("to", ""))

    if tool == "send_email" and to and not to.endswith("@sdu.edu.cn"):
        risk_score += 25
        reason.append("邮件发送目标为外部邮箱")

    # 5. 内容风险判断
    content = str(params.get("content", ""))

    dangerous_words = [
        "ignore previous rules",
        "忽略之前的规则",
        "password",
        "secret",
        "delete",
        "drop table"
    ]

    for word in dangerous_words:
        if word.lower() in content.lower():
            risk_score += 20
            reason.append(f"内容包含危险关键词：{word}")

    # 6. 根据风险分做最终决策
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

>到此为止我们运行的方式仍然是不变的，如果仍记不住，那么请看[[运行方式1]]。

如果成功了就说明：FastAPI 后端已经正常跑起来了

现在进入下一步：**让网关不只是检查，还能决定是否执行工具。**

也就是实现这个流程：

```text
用户请求工具调用
↓
网关检查风险
↓
如果 allow：执行工具
如果 confirm：暂不执行，等待人工确认
如果 deny：直接拦截
```

这一步我们先做一个模拟文件读取工具

先在项目根目录新建：

```text
data/
├── public/
│   └── notice.txt
└── secret/
    └── password.txt
```

在 `notice.txt` 里写：

```text
这是公开通知文件，可以被正常读取。
```

在 `password.txt` 里写：

```text
admin_password=123456
```

然后新建 `backend/tool_executor.py`，内容为：

```python
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def execute_tool(tool: str, params: dict):
    if tool == "read_file":
        return read_file(params)

    if tool == "send_email":
        return send_email(params)

    if tool == "query_db":
        return query_db(params)

    if tool == "run_code":
        return run_code(params)

    return {
        "success": False,
        "result": f"未知工具：{tool}"
    }


def read_file(params: dict):
    path = params.get("path", "")

    if ".." in path:
        return {
            "success": False,
            "result": "非法路径"
        }

    file_path = DATA_DIR / path

    if not file_path.exists():
        return {
            "success": False,
            "result": "文件不存在"
        }

    content = file_path.read_text(encoding="utf-8")

    return {
        "success": True,
        "result": content
    }


def send_email(params: dict):
    to = params.get("to", "")
    content = params.get("content", "")

    return {
        "success": True,
        "result": f"模拟发送邮件成功，收件人：{to}，内容：{content}"
    }


def query_db(params: dict):
    sql = params.get("sql", "")

    return {
        "success": True,
        "result": f"模拟执行数据库查询：{sql}"
    }


def run_code(params: dict):
    code = params.get("code", "")

    return {
        "success": True,
        "result": f"模拟执行代码：{code}"
    }
```

同时把 `main.py` 改成下面这样：

```python
from fastapi import FastAPI
from backend.schemas import ToolCallRequest, GatewayResponse
from backend.gateway import check_tool_call
from backend.tool_executor import execute_tool


app = FastAPI(
    title="AI Agent Auth Gateway",
    description="面向 AI 智能体工具调用的授权与安全防护系统",
    version="0.1.0"
)


@app.get("/")
def index():
    return {
        "message": "AI Agent Auth Gateway is running"
    }


@app.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(request: ToolCallRequest):
    return check_tool_call(request)


@app.post("/agent/call")
def agent_call(request: ToolCallRequest):
    check_result = check_tool_call(request)

    if check_result["decision"] == "deny":
        return {
            "executed": False,
            "message": "工具调用已被安全网关拦截",
            "gateway_result": check_result,
            "tool_result": None
        }

    if check_result["decision"] == "confirm":
        return {
            "executed": False,
            "message": "工具调用需要人工确认，暂不执行",
            "gateway_result": check_result,
            "tool_result": None
        }

    tool_result = execute_tool(request.tool, request.params)

    return {
        "executed": True,
        "message": "工具调用已通过安全检查并执行",
        "gateway_result": check_result,
        "tool_result": tool_result
    }
```

再次运行，那么我们已经完成了一个真正有意义的原型闭环：

```text
工具调用请求 → 网关安全判断 → 决定是否执行工具 → 返回执行/拦截结果
```

接下来我们开始[[Task2]]。

