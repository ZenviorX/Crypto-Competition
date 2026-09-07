# Task15：策略规则独立化与统一配置文件改造

## 一、任务背景

在前面的 Task 中，项目已经完成了：

```text
1. Agent 自然语言规划
2. PlanGuard 计划校验
3. Gateway 风险评分与授权决策
4. TaskContract 任务授权合约
5. 多步任务链上下文风险检测
6. 前端自由自然语言输入
```

但是项目中仍然存在一个结构性问题：

> 很多安全规则仍然写死在 Python 代码里。后续如果想调整策略，就必须改代码、重新检查逻辑，维护成本较高，也不利于把项目做成可配置、可扩展的安全网关。

例如之前这些规则散落在不同文件里：

```text
PlanGuard 支持哪些工具
每种工具需要哪些参数
Agent 置信度阈值
Gateway 风险加分
危险命令关键词
提示注入关键词
敏感内容关键词
敏感路径关键词
邮件外发可信域名
上下文外发工具列表
任务合约默认拒绝工具
任务合约默认拒绝路径
任务合约路径提取正则
```

本 Task 的目标就是把这些规则统一收口到独立策略文件：

```text
config/policy.yaml
```

以后修改安全策略时，优先只改 `config/policy.yaml`，尽量不改业务代码。

---

## 二、本 Task 的核心目标

本 Task 实现的是：

```text
策略规则独立化
```

即：

```text
把写死在代码里的安全规则、风险分、工具白名单、关键词、任务合约默认策略等，统一外置到 config/policy.yaml 中。
```

改造后的核心结构为：

```text
config/policy.yaml
  ↓
backend/gateway/policy_loader.py
  ↓
PlanGuard / Gateway / ContextAnalyzer / TaskContract / LLMAgent
```

也就是说，各模块不再直接写死规则，而是通过 `policy_loader.py` 统一读取策略。

---

## 三、本次修改文件总览

本次 Task 修改了以下文件：

```text
config/policy.yaml
backend/gateway/policy_loader.py
backend/agents/plan_guard.py
backend/gateway/gateway.py
backend/task_session/context_analyzer.py
backend/task_contract/contract_builder.py
backend/agents/llm_agent.py
```

对应提交包括：

```text
policy: centralize security rules
policy: add centralized policy accessors
policy: load PlanGuard rules from policy file
policy: load gateway rules from policy file
policy: load context analyzer keywords from policy file
policy: load task contract defaults from policy file
policy: fix contract regex yaml quoting
policy: load LLM allowed tools from policy file
```

---

## 四、整体改造前后对比

### 4.1 改造前

规则散落在多个 Python 文件中：

```text
plan_guard.py:
  SUPPORTED_TOOLS
  REQUIRED_PARAMS
  MIN_AUTO_CONFIDENCE
  MIN_CONFIRM_CONFIDENCE

gateway.py:
  SUPPORTED_TOOLS
  REQUIRED_PARAMS
  低置信度阈值
  路径穿越风险分
  绝对路径风险分
  邮件外发域名
  敏感内容关键词
  SQL 高危关键词

context_analyzer.py:
  SENSITIVE_KEYWORDS
  PROMPT_INJECTION_KEYWORDS
  external_output_tools
  sensitive_path_keywords

contract_builder.py:
  文件路径提取正则
  默认拒绝工具
  默认拒绝路径
  默认风险预算

llm_agent.py:
  ALLOWED_TOOLS
  Prompt 中写死的工具列表
```

问题：

```text
1. 改策略必须改代码
2. 规则分散，不容易检查
3. 多处规则可能不一致
4. 扩展新工具时需要同时修改多个文件
5. 策略调整不适合非代码人员维护
```

---

### 4.2 改造后

统一从：

```text
config/policy.yaml
```

读取策略。

模块关系变成：

```text
config/policy.yaml
  ↓
policy_loader.py
  ↓
PlanGuard
Gateway
ContextAnalyzer
TaskContract Builder
LLMAgent
```

优势：

```text
1. 安全策略集中管理
2. 修改风险分不用改代码
3. 增删危险关键词不用改代码
4. 调整 Agent 置信度阈值不用改代码
5. 增删工具白名单不用改核心逻辑
6. 任务合约默认规则可配置
7. 更适合作为 AI Agent 安全网关项目展示
```

---

# 五、文件级改动说明

---

## 5.1 `config/policy.yaml`

### 修改目标

将项目中的主要安全策略集中到一个 YAML 文件中，作为唯一策略入口。

### 新增和整理的配置项

最终 `policy.yaml` 主要包含：

```text
version
users
supported_tools
required_params
agent_plan
internal_email_domains
tool_risk
resource_risk
decision_threshold
risk_scores
dangerous_keywords
external_output_tools
roles
task_contract
```

### 核心配置内容

```yaml
version: "2.0"

users:
  alice: teacher
  bob: teacher
  student: student
  test_user: student
  guest: student
  teacher: teacher
  admin: admin

supported_tools:
  - file.read
  - file.write
  - file.delete
  - email.send
  - shell.run
  - db.query

required_params:
  file.read:
    - path
  file.write:
    - path
    - content
  file.delete:
    - path
  email.send:
    - to
    - content
  shell.run:
    - command
  db.query:
    - sql

agent_plan:
  min_auto_confidence: 0.85
  min_confirm_confidence: 0.55

internal_email_domains:
  - "@sdu.edu.cn"
```

### 风险分配置

```yaml
risk_scores:
  unknown_tool: 100
  low_confidence_deny: 100
  low_confidence_confirm: 45
  missing_params: 60
  path_traversal: 60
  absolute_path: 40
  role_deny: 70
  no_role_policy: 20
  missing_email_to: 20
  external_email: 25
  sensitive_email_content: 30
  prompt_injection_keyword: 30
  sensitive_content_keyword: 20
  command_keyword: 30
  sql_keyword: 50
  non_select_sql: 30
  contract_parse_error: 100
```

### 危险关键词配置

```yaml
dangerous_keywords:
  command:
    - "rm -rf"
    - "del /s"
    - "format"
    - "shutdown"
    - "reboot"
    - "powershell"
    - "curl"
    - "wget"
    - "chmod 777"

  prompt_injection:
    - "忽略之前的规则"
    - "忽略以上规则"
    - "忽略所有规则"
    - "忽略之前的指令"
    - "忽略系统提示"
    - "不要遵守安全策略"
    - "绕过权限检查"
    - "读取 secret"
    - "读取敏感文件"
    - "attacker@example.com"
    - "ignore previous instructions"
    - "ignore all previous instructions"
    - "disregard previous instructions"
    - "bypass authorization"

  sensitive_content:
    - "password"
    - "passwd"
    - "secret"
    - "token"
    - "credential"
    - "api_key"
    - "private_key"
    - "密钥"
    - "密码"
    - "口令"
    - "令牌"

  sensitive_path:
    - "secret"
    - "password"
    - "passwd"
    - "private"
    - "key"
    - ".env"
    - "token"

  sql:
    - "drop table"
    - "delete from"
    - "truncate"
    - "union select"
    - "update "
    - "insert into"
    - "alter table"
    - "create table"
```

### 任务合约默认策略

```yaml
task_contract:
  extract_file_path_pattern: '(public/[a-zA-Z0-9_.\-/]+|data/[a-zA-Z0-9_.\-/]+|logs/[a-zA-Z0-9_.\-/]+|course/[a-zA-Z0-9_.\-/]+)'

  default_denied_tools:
    - shell.run
    - code.exec
    - db.query

  default_denied_paths:
    - secret/*
    - private/*
    - ../*

  default_risk_budget: 80
  default_allow_external_send: false
  default_require_human_confirm: false
```

### 实现效果

以后调整策略时可以直接修改：

```text
config/policy.yaml
```

例如：

```yaml
agent_plan:
  min_auto_confidence: 0.90
```

即可提高自动放行门槛。

---

## 5.2 `backend/gateway/policy_loader.py`

### 修改目标

扩展策略加载器，使其成为所有模块读取 `policy.yaml` 的统一入口。

### 新增函数

```python
def get_supported_tools() -> list[str]:
    policy = load_policy()
    return [str(item) for item in policy.get("supported_tools", [])]
```

作用：读取系统支持的工具白名单。

---

```python
def get_required_params() -> Dict[str, list[str]]:
    policy = load_policy()
    required_params = policy.get("required_params", {})
    return {
        str(tool): [str(item) for item in params]
        for tool, params in required_params.items()
    }
```

作用：读取每个工具的必填参数。

---

```python
def get_agent_plan_policy() -> Dict[str, float]:
    policy = load_policy()
    agent_plan = policy.get("agent_plan", {})
    return {
        "min_auto_confidence": float(agent_plan.get("min_auto_confidence", 0.85)),
        "min_confirm_confidence": float(agent_plan.get("min_confirm_confidence", 0.55)),
    }
```

作用：读取 Agent 计划置信度阈值。

---

```python
def get_internal_email_domains() -> list[str]:
    policy = load_policy()
    return [str(item).lower() for item in policy.get("internal_email_domains", [])]
```

作用：读取内部可信邮箱域名。

---

```python
def get_risk_score(name: str, default: int = 0) -> int:
    policy = load_policy()
    risk_scores = policy.get("risk_scores", {})
    return int(risk_scores.get(name, default))
```

作用：读取细粒度风险加分。

---

```python
def get_external_output_tools() -> set[str]:
    policy = load_policy()
    return {str(item) for item in policy.get("external_output_tools", [])}
```

作用：读取可能造成数据外发或副作用的工具列表。

---

```python
def get_task_contract_policy() -> Dict[str, Any]:
    policy = load_policy()
    contract_policy = policy.get("task_contract", {})
    return {
        "extract_file_path_pattern": str(
            contract_policy.get(
                "extract_file_path_pattern",
                r"(public/[a-zA-Z0-9_.\-/]+|data/[a-zA-Z0-9_.\-/]+|logs/[a-zA-Z0-9_.\-/]+)",
            )
        ),
        "default_denied_tools": [
            str(item) for item in contract_policy.get("default_denied_tools", [])
        ],
        "default_denied_paths": [
            str(item) for item in contract_policy.get("default_denied_paths", [])
        ],
        "default_risk_budget": int(contract_policy.get("default_risk_budget", 80)),
        "default_allow_external_send": bool(
            contract_policy.get("default_allow_external_send", False)
        ),
        "default_require_human_confirm": bool(
            contract_policy.get("default_require_human_confirm", False)
        ),
    }
```

作用：读取任务授权合约默认配置。

### 实现效果

其他模块不需要自己解析 YAML，只需要调用 `policy_loader.py` 的统一方法。

---

## 5.3 `backend/agents/plan_guard.py`

### 修改目标

把 PlanGuard 中写死的规则改为从策略文件读取。

### 改造前

PlanGuard 中原本写死：

```python
SUPPORTED_TOOLS = {
    "file.read",
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "db.query",
}

REQUIRED_PARAMS = {
    "file.read": ["path"],
    "file.write": ["path", "content"],
    "file.delete": ["path"],
    "email.send": ["to", "content"],
    "shell.run": ["command"],
    "db.query": ["sql"],
}

MIN_AUTO_CONFIDENCE = 0.85
MIN_CONFIRM_CONFIDENCE = 0.55
```

### 改造后

新增导入：

```python
from backend.gateway.policy_loader import (
    get_supported_tools,
    get_required_params,
    get_agent_plan_policy,
    get_risk_score,
)
```

在 `find_missing_params()` 中读取必填参数：

```python
def find_missing_params(tool: str, params: Dict[str, Any]) -> List[str]:
    required_params = get_required_params()
    required = required_params.get(tool, [])
    missing = []

    for name in required:
        if _is_empty_value(params.get(name)):
            missing.append(name)

    return missing
```

在 `inspect_agent_plan()` 中读取工具白名单和置信度阈值：

```python
plan_policy = get_agent_plan_policy()
min_auto_confidence = plan_policy["min_auto_confidence"]
min_confirm_confidence = plan_policy["min_confirm_confidence"]
supported_tools = set(get_supported_tools())
```

未知工具风险分从策略读取：

```python
"risk_score": get_risk_score("unknown_tool", 100)
```

低置信度风险分从策略读取：

```python
"risk_score": get_risk_score("low_confidence_deny", 100)
```

缺参风险分从策略读取：

```python
"risk_score": get_risk_score("missing_params", 60)
```

### 实现效果

以后修改 PlanGuard 策略，只需要改：

```yaml
supported_tools:
required_params:
agent_plan:
risk_scores:
```

---

## 5.4 `backend/gateway/gateway.py`

### 修改目标

把 Gateway 中写死的工具列表、必填参数、置信度阈值、风险加分、内部邮箱域名、敏感关键词、SQL 关键词等改为从策略文件读取。

### 新增导入

```python
from backend.gateway.policy_loader import (
    get_tool_risk,
    get_decision_threshold,
    get_user_role,
    match_role_policy,
    get_resource_risk,
    get_dangerous_keywords,
    match_keywords,
    get_supported_tools,
    get_required_params,
    get_agent_plan_policy,
    get_risk_score,
    get_internal_email_domains,
)
```

### 工具白名单外置

改造后：

```python
supported_tools = set(get_supported_tools())

if tool not in supported_tools:
    return {
        "decision": "deny",
        "risk_score": get_risk_score("unknown_tool", 100),
        "reason": [
            f"工具 {tool} 不在系统支持列表中。",
            "未知工具不能自动执行，已按失败关闭原则拒绝。",
        ],
        "user": user,
        "role": role,
        "normalized_tool": tool,
        "normalized_params": params,
    }
```

### 置信度阈值外置

```python
agent_plan_policy = get_agent_plan_policy()
min_confirm_confidence = agent_plan_policy["min_confirm_confidence"]
min_auto_confidence = agent_plan_policy["min_auto_confidence"]
```

判断逻辑：

```python
if confidence < min_confirm_confidence:
    return {
        "decision": "deny",
        "risk_score": get_risk_score("low_confidence_deny", 100),
        ...
    }

if confidence < min_auto_confidence:
    risk_score += get_risk_score("low_confidence_confirm", 45)
    low_confidence_force_confirm = True
```

### 必填参数外置

```python
required_params = get_required_params()

for name in required_params.get(tool, []):
    value = str(params.get(name, "")).strip()
    if not value or value == "unknown":
        missing_params.append(name)
```

### 风险分外置

示例：

```python
risk_score += get_risk_score("path_traversal", 60)
risk_score += get_risk_score("absolute_path", 40)
risk_score += get_risk_score("role_deny", 70)
risk_score += get_risk_score("no_role_policy", 20)
risk_score += get_risk_score("external_email", 25)
risk_score += get_risk_score("sql_keyword", 50)
```

### 内部邮箱域名外置

```python
internal_domains = get_internal_email_domains()

elif internal_domains and not any(to.lower().endswith(domain) for domain in internal_domains):
    risk_score += get_risk_score("external_email", 25)
    reason.append("邮件发送目标不是内部可信邮箱，存在数据外发风险")
```

### 敏感内容关键词外置

```python
sensitive_content_keywords = get_dangerous_keywords("sensitive_content")
matched_sensitive_keywords = match_keywords(content, sensitive_content_keywords)
```

### SQL 高危关键词外置

```python
dangerous_sql = get_dangerous_keywords("sql")

if tool == "db.query":
    for keyword in dangerous_sql:
        if keyword in sql_lower:
            risk_score += get_risk_score("sql_keyword", 50)
            reason.append(f"SQL 语句包含高危操作：{keyword}")
```

### 实现效果

Gateway 的核心判断逻辑还在代码里，但具体策略值已经尽量外置到 YAML。

---

## 5.5 `backend/task_session/context_analyzer.py`

### 修改目标

把多步任务链上下文分析中的敏感关键词、提示注入关键词、外发工具、敏感路径关键词全部改成从策略文件读取。

### 改造前

原来写死：

```python
SENSITIVE_KEYWORDS = [...]
PROMPT_INJECTION_KEYWORDS = [...]
```

并写死：

```python
return tool in {
    "email.send",
    "shell.run",
    "db.query",
    "file.write",
}
```

以及敏感路径关键词：

```python
sensitive_path_keywords = [
    "secret",
    "password",
    "passwd",
    "private",
    "key",
    ".env",
    "token",
]
```

### 改造后

新增导入：

```python
from backend.gateway.policy_loader import (
    get_dangerous_keywords,
    get_external_output_tools,
)
```

敏感内容关键词从策略读取：

```python
sensitive_keywords = get_dangerous_keywords("sensitive_content")
```

提示注入关键词从策略读取：

```python
prompt_injection_keywords = get_dangerous_keywords("prompt_injection")
```

外发工具从策略读取：

```python
def is_external_output_tool(tool: str) -> bool:
    return tool in get_external_output_tools()
```

敏感路径关键词从策略读取：

```python
def is_sensitive_path(path: str) -> bool:
    if not path:
        return False

    lower_path = path.lower()
    sensitive_path_keywords = get_dangerous_keywords("sensitive_path")

    return any(keyword in lower_path for keyword in sensitive_path_keywords)
```

### 实现效果

以后提示注入、敏感内容、敏感路径、外发工具规则都可以在 `policy.yaml` 中改。

---

## 5.6 `backend/task_contract/contract_builder.py`

### 修改目标

把任务授权合约生成器中的默认规则外置到 `policy.yaml`。

### 改造前

原来写死：

```python
pattern = r"(public/[a-zA-Z0-9_.\-/]+|data/[a-zA-Z0-9_.\-/]+|logs/[a-zA-Z0-9_.\-/]+)"
```

以及：

```python
denied_tools=[
    "shell.run",
    "code.exec",
    "db.query"
]

denied_paths=[
    "secret/*",
    "private/*",
    "../*"
]

risk_budget=80
allow_external_send=False
require_human_confirm=False
```

### 改造后

新增导入：

```python
from backend.gateway.policy_loader import get_task_contract_policy
```

路径提取正则从策略读取：

```python
def extract_file_path(text: str) -> list[str]:
    contract_policy = get_task_contract_policy()
    pattern = contract_policy["extract_file_path_pattern"]
    return re.findall(pattern, text)
```

任务合约默认值从策略读取：

```python
contract_policy = get_task_contract_policy()
```

构造合约时使用：

```python
contract = TaskAuthContract(
    task_id=task_id,
    user=user,
    original_task=task_text,
    task_goal="根据用户原始任务生成的受限执行目标",
    allowed_tools=allowed_tools,
    denied_tools=contract_policy["default_denied_tools"],
    allowed_read_paths=file_paths,
    denied_paths=contract_policy["default_denied_paths"],
    allowed_email_to=emails,
    allow_external_send=contract_policy["default_allow_external_send"],
    risk_budget=contract_policy["default_risk_budget"],
    require_human_confirm=contract_policy["default_require_human_confirm"],
    reason=reason,
)
```

### 实现效果

任务授权合约的默认策略也不再写死。

---

## 5.7 `backend/agents/llm_agent.py`

### 修改目标

让 LLM Agent 的工具白名单和 Prompt 中的工具说明从策略文件读取。

### 改造前

LLM Agent 中存在写死工具列表：

```python
ALLOWED_TOOLS = {
    "file.read",
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "db.query",
}
```

Prompt 中也写死工具说明。

### 改造后

新增导入：

```python
from backend.gateway.policy_loader import get_supported_tools, get_required_params
```

新增工具描述生成函数：

```python
def _build_tool_description(self) -> str:
    supported_tools = get_supported_tools()
    required_params = get_required_params()
    lines = []

    for index, tool in enumerate(supported_tools, start=1):
        params = required_params.get(tool, [])
        arguments_example = {name: "..." for name in params}
        lines.append(
            f"{index}. {tool} arguments: {json.dumps(arguments_example, ensure_ascii=False)}"
        )

    return "\n".join(lines)
```

Prompt 中动态插入工具说明：

```python
def _build_system_prompt(self) -> str:
    tool_description = self._build_tool_description()

    return f"""
You are a tool-call planner, not a tool executor.

Allowed tools are loaded from the server policy file:
{tool_description}
...
"""
```

解析 LLM 输出时也从策略文件判断工具是否合法：

```python
if tool_name in set(get_supported_tools()):
    ...
else:
    status = "unsupported"
```

### 实现效果

后续如果在 `policy.yaml` 中新增工具，LLM Prompt 和解析阶段都可以同步读取到。

---

# 六、现在如何修改策略

## 6.1 新增危险命令

只改：

```yaml
dangerous_keywords:
  command:
    - "rm -rf"
    - "format"
    - "你的新危险命令"
```

---

## 6.2 修改 Agent 自动放行阈值

只改：

```yaml
agent_plan:
  min_auto_confidence: 0.90
  min_confirm_confidence: 0.60
```

---

## 6.3 新增敏感路径关键词

只改：

```yaml
dangerous_keywords:
  sensitive_path:
    - "secret"
    - "private"
    - "你的敏感目录"
```

---

## 6.4 禁止学生发送邮件

只改：

```yaml
roles:
  student:
    deny:
      - tool: email.send
        resource: "*"
```

---

## 6.5 新增工具白名单

例如新增：

```yaml
supported_tools:
  - browser.open

required_params:
  browser.open:
    - url

tool_risk:
  browser.open: 30
```

说明：新增工具时，策略文件可以先登记工具规则，但仍需要在 `ToolExecutor` 中实现对应工具执行逻辑。

---

# 七、验收方式

## 7.1 编译检查

```cmd
python -m py_compile backend\gateway\policy_loader.py backend\agents\plan_guard.py backend\gateway\gateway.py backend\task_session\context_analyzer.py backend\task_contract\contract_builder.py backend\agents\llm_agent.py
```

---

## 7.2 测试策略是否生效

启动项目：

```cmd
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

测试输入：

```text
读取文件：public/notice.txt
打开摄像头拍照
帮我发个邮件
执行命令：rm -rf /
读取文件：secret/password.txt
```

预期：

```text
公开文件：根据角色与风险策略 allow / confirm
未知工具：deny
缺少邮件参数：confirm
危险命令：deny
敏感文件：deny
```

---

## 7.3 修改策略后测试

例如将：

```yaml
agent_plan:
  min_auto_confidence: 0.99
```

然后重新启动服务，再输入原本可放行的任务，应该更容易进入 `confirm`。

---

# 八、本 Task 的最终价值

本 Task 将项目从：

```text
规则分散在代码中的安全网关
```

升级为：

```text
策略文件驱动的安全网关
```

改造前：

```text
改安全策略 = 改 Python 代码
```

改造后：

```text
改安全策略 = 优先改 config/policy.yaml
```

最终收益：

```text
1. 安全规则集中管理
2. 降低修改策略的代码风险
3. 方便比赛展示“策略可配置”能力
4. PlanGuard、Gateway、ContextAnalyzer、TaskContract 使用统一策略来源
5. 减少多个模块规则不一致的问题
6. 后续可以扩展成策略热加载、前端策略配置页、不同环境策略切换
```

一句话总结：

> Task15 的核心改进，是将 Agent 工具调用安全策略从代码中抽离出来，统一放入 `config/policy.yaml`，并通过 `policy_loader.py` 提供给 PlanGuard、Gateway、上下文分析、任务合约和 LLM Agent 使用，使项目具备更强的可配置性和可维护性。
