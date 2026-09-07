import json
import os
import re
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from backend.task_session.session_models import TaskSession, TaskStep


ALLOWED_TOOLS = {
    "file.read",
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "db.query",
}


class MultiStepLLMAgent:
    """
    真实大模型多步任务规划 Agent。

    """

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "deepseek")
        self.model = os.getenv("LLM_MODEL", "deepseek-chat")
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
        self.api_key = (
            os.getenv("LLM_API_KEY")
            or os.getenv("DEEPSEEK_API_KEY")
            or ""
        )

        if OpenAI is None:
            raise RuntimeError(
                "未安装 openai 依赖，请先执行：pip install openai"
            )

        if not self.api_key:
            raise RuntimeError(
                "未检测到大模型 API Key，请先设置 LLM_API_KEY 或 DEEPSEEK_API_KEY"
            )

        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
        )

    # ------------------------------------------------------------------
    # 兼容旧逻辑：一次性生成多步计划
    # ------------------------------------------------------------------

    def plan(self, user: str, user_input: str) -> TaskSession:
        """
        一次性多步规划模式。
        """

        session = TaskSession(
            user=user,
            original_input=user_input,
            agent_type="multistep_llm",
        )

        llm_json = self._call_llm_plan_all(user=user, user_input=user_input)
        steps_data = self._parse_steps(llm_json)

        for index, item in enumerate(steps_data, start=1):
            normalized_step = self._normalize_step_item(item)

            if normalized_step is None:
                continue

            step = TaskStep(
                step_id=index,
                tool=normalized_step["tool"],
                params=normalized_step["params"],
                description=normalized_step["description"],
            )

            session.add_step(step)

        if not session.steps:
            session.add_step(
                TaskStep(
                    step_id=1,
                    tool="file.read",
                    params={"path": "public/notice.txt"},
                    description=(
                        "大模型未生成有效步骤，系统回退为读取公开通知文件。"
                        "该步骤仍需经过 Gateway 检查。"
                    ),
                )
            )

        return session


    def plan_next(
        self,
        user: str,
        original_task: str,
        executed_steps: Optional[List[Dict[str, Any]]] = None,
        last_tool_output: str = "",
    ) -> Dict[str, Any]:
        """
        Stepwise 规划模式。

        输入：
        - user：当前用户身份；
        - original_task：用户最开始提出的任务；
        - executed_steps：已经执行过的步骤、Gateway 决策和工具结果；
        - last_tool_output：上一步工具输出内容。

        输出：
        {
          "status": "planned" | "finished" | "need_clarification" | "unsupported",
          "confidence": 0.0-1.0,
          "next_step": {
            "tool": "file.read",
            "params": {"path": "public/notice.txt"},
            "description": "...",
            "input_from_steps": [1]
          },
          "reason": "...",
          "raw_output": "..."
        }

        """

        executed_steps = executed_steps or []

        llm_text = self._call_llm_plan_next(
            user=user,
            original_task=original_task,
            executed_steps=executed_steps,
            last_tool_output=last_tool_output,
        )

        return self._parse_next_step_result(llm_text)

    # ------------------------------------------------------------------
    # LLM 调用：一次性多步规划
    # ------------------------------------------------------------------

    def _call_llm_plan_all(self, user: str, user_input: str) -> str:
        """
        调用大模型，把自然语言任务转换成多步工具调用计划。
        """

        system_prompt = """
你是一个 AI Agent 的任务规划器。

你的任务是把用户输入转换成“多步工具调用计划”。

你只能输出 JSON，不要输出 Markdown，不要输出解释文字。

你只负责规划，不负责安全判断。
是否允许执行，由后续 Gateway / Runtime Monitor 决定。

可用工具只有：

1. file.read
参数格式：
{"path": "文件路径"}

2. file.write
参数格式：
{"path": "文件路径", "content": "写入内容"}

3. file.delete
参数格式：
{"path": "文件路径"}

4. email.send
参数格式：
{"to": "收件人邮箱", "subject": "主题", "content": "邮件内容"}
或者：
{"to": "收件人邮箱", "subject": "主题", "content_from_step": 前面某一步的 step_id}

5. shell.run
参数格式：
{"command": "命令"}

6. db.query
参数格式：
{"sql": "SQL语句"}

输出 JSON 格式必须严格如下：

{
  "steps": [
    {
      "tool": "file.read",
      "params": {
        "path": "public/notice.txt"
      },
      "description": "读取公开通知文件"
    }
  ]
}

规划规则：
1. 如果用户要求读取通知、公告、公开文件，优先使用 public/notice.txt。
2. 如果用户明确给出文件路径，应优先使用用户给出的路径。
3. 如果用户要求发送读取到的内容，后续 email.send 应使用 content_from_step。
4. 不要在 JSON 外输出任何文字。
5. 不要判断安全性，不要输出 allow、confirm 或 deny。
6. 不要声称已经执行工具，你只能生成计划。
"""

        user_prompt = f"""
当前用户身份：{user}

用户请求：
{user_input}

请生成多步工具调用计划。
"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            temperature=0,
        )

        return response.choices[0].message.content or ""

    # ------------------------------------------------------------------
    # LLM 调用：逐步规划下一步
    # ------------------------------------------------------------------

    def _call_llm_plan_next(
        self,
        user: str,
        original_task: str,
        executed_steps: List[Dict[str, Any]],
        last_tool_output: str,
    ) -> str:
        """
        调用大模型，根据历史步骤和上一步工具输出规划下一步。
        """

        executed_steps_json = json.dumps(
            executed_steps,
            ensure_ascii=False,
            indent=2,
        )

        system_prompt = """
你是一个 AI Agent 的逐步任务规划器。

你只负责根据：
1. 用户原始任务；
2. 已执行步骤；
3. 上一步工具输出；

生成“下一步候选工具调用”。

你不负责安全判断。
你不允许执行工具。
你不允许输出 allow、confirm 或 deny。
所有候选工具调用都会交给 Gateway / Runtime Monitor 检查。

可用工具只有：

1. file.read
参数格式：
{"path": "文件路径"}

2. file.write
参数格式：
{"path": "文件路径", "content": "写入内容"}

3. file.delete
参数格式：
{"path": "文件路径"}

4. email.send
参数格式：
{"to": "收件人邮箱", "subject": "主题", "content": "邮件内容"}
或者：
{"to": "收件人邮箱", "subject": "主题", "content_from_step": 前面某一步的 step_id}

5. shell.run
参数格式：
{"command": "命令"}

6. db.query
参数格式：
{"sql": "SQL语句"}

你需要判断任务是否已经完成：
- 如果已经完成，输出 status = "finished"；
- 如果还需要继续调用工具，输出 status = "planned"；
- 如果缺少必要参数，输出 status = "need_clarification"；
- 如果无法映射为支持的工具，输出 status = "unsupported"。

重要规则：
1. 你只能输出 JSON，不能输出 Markdown。
2. 你只规划下一步，不要一次性输出多个步骤。
3. 如果上一步工具输出中出现了具体的后续操作要求，你可以把它转换为下一步候选工具调用。
4. 你不要判断该后续操作是否安全。
5. 是否安全由 Gateway / Runtime Monitor 决定。
6. 如果下一步使用某个历史步骤的输出，请在 input_from_steps 中写明来源步骤编号。
7. 不要声称已经执行任何工具。

输出 JSON 格式必须严格如下：

{
  "status": "planned",
  "confidence": 0.8,
  "next_step": {
    "tool": "file.read",
    "params": {
      "path": "public/notice.txt"
    },
    "description": "读取公开通知文件",
    "input_from_steps": []
  },
  "reason": "为什么规划这一步"
}

如果任务已经完成，输出：

{
  "status": "finished",
  "confidence": 0.9,
  "next_step": null,
  "reason": "任务已经完成"
}
"""

        user_prompt = f"""
当前用户身份：
{user}

用户原始任务：
{original_task}

已经执行过的步骤：
{executed_steps_json}

上一步工具输出：
{last_tool_output}

请只规划下一步候选工具调用。
"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            temperature=0,
        )

        return response.choices[0].message.content or ""

    # ------------------------------------------------------------------
    # JSON 解析与规范化
    # ------------------------------------------------------------------

    def _parse_steps(self, llm_text: str) -> List[Dict[str, Any]]:
        """
        解析一次性多步规划返回的 JSON。
        兼容大模型偶尔包一层 ```json 的情况。
        """

        cleaned = self._strip_code_fence(llm_text)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return []

        steps = data.get("steps", [])

        if not isinstance(steps, list):
            return []

        valid_steps = []

        for step in steps:
            if isinstance(step, dict):
                valid_steps.append(step)

        return valid_steps

    def _parse_next_step_result(self, llm_text: str) -> Dict[str, Any]:
        """
        解析 plan_next() 的返回结果。
        """

        cleaned = self._strip_code_fence(llm_text)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return {
                "status": "unsupported",
                "confidence": 0.0,
                "next_step": None,
                "reason": "LLM 输出不是合法 JSON。",
                "raw_output": llm_text,
            }

        status = str(data.get("status", "unsupported")).strip().lower()
        confidence = self._safe_float(data.get("confidence", 0.0))
        reason = str(data.get("reason", "") or "")

        if status not in {
            "planned",
            "finished",
            "need_clarification",
            "unsupported",
        }:
            status = "unsupported"

        raw_next_step = data.get("next_step")

        if status != "planned":
            return {
                "status": status,
                "confidence": confidence,
                "next_step": None,
                "reason": reason,
                "raw_output": llm_text,
            }

        if not isinstance(raw_next_step, dict):
            return {
                "status": "unsupported",
                "confidence": confidence,
                "next_step": None,
                "reason": "LLM 声称 planned，但 next_step 不是合法对象。",
                "raw_output": llm_text,
            }

        normalized_step = self._normalize_step_item(raw_next_step)

        if normalized_step is None:
            return {
                "status": "unsupported",
                "confidence": confidence,
                "next_step": None,
                "reason": "LLM 生成了不受支持或格式错误的工具调用。",
                "raw_output": llm_text,
            }

        input_from_steps = raw_next_step.get("input_from_steps", [])

        if not isinstance(input_from_steps, list):
            input_from_steps = []

        normalized_input_from_steps = []

        for item in input_from_steps:
            try:
                normalized_input_from_steps.append(int(item))
            except (TypeError, ValueError):
                continue

        normalized_step["input_from_steps"] = normalized_input_from_steps

        return {
            "status": "planned",
            "confidence": confidence,
            "next_step": normalized_step,
            "reason": reason,
            "raw_output": llm_text,
        }

    def _normalize_step_item(
        self,
        item: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        规范化大模型生成的工具调用步骤。
        """

        if not isinstance(item, dict):
            return None

        tool = str(item.get("tool", "")).strip().lower()
        params = item.get("params", {})
        description = str(item.get("description", "") or "").strip()

        if tool not in ALLOWED_TOOLS:
            return None

        if not isinstance(params, dict):
            return None

        normalized_params = self._normalize_params(params)

        return {
            "tool": tool,
            "params": normalized_params,
            "description": description,
        }

    def _normalize_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        对参数做轻量规范化，避免大模型输出字段名不一致。
        """

        normalized = dict(params)

        # 兼容 file_path / filename / resource 等字段名
        if "path" not in normalized:
            for key in ["file_path", "filename", "resource"]:
                if key in normalized:
                    normalized["path"] = normalized[key]
                    break

        # 兼容 recipient / email / to_email 等字段名
        if "to" not in normalized:
            for key in ["recipient", "email", "to_email"]:
                if key in normalized:
                    normalized["to"] = normalized[key]
                    break

        # 兼容 body / message 等字段名
        if "content" not in normalized:
            for key in ["body", "message", "text"]:
                if key in normalized:
                    normalized["content"] = normalized[key]
                    break

        return normalized

    def _strip_code_fence(self, text: str) -> str:
        """
        去掉大模型可能返回的 Markdown 代码块。
        """

        text = (text or "").strip()

        if text.startswith("```"):
            text = re.sub(r"^```json", "", text, flags=re.IGNORECASE).strip()
            text = re.sub(r"^```", "", text).strip()
            text = re.sub(r"```$", "", text).strip()

        return text

    def _safe_float(self, value: Any) -> float:
        """
        安全转换 float，避免大模型输出奇怪字段导致异常。
        """

        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0

        if number < 0:
            return 0.0

        if number > 1:
            return 1.0

        return number