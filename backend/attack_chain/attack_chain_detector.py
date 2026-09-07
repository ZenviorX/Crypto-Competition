from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4


PROMPT_INJECTION_KEYWORDS = [
    "忽略之前的规则",
    "忽略系统提示",
    "不要遵守安全策略",
    "绕过权限检查",
    "ignore previous instructions",
    "ignore all previous instructions",
    "bypass authorization",
    "bypass safety",
    "reveal all secrets",
]

SENSITIVE_PATH_KEYWORDS = [
    "secret",
    "password",
    "token",
    ".env",
    "private",
    "key",
]

EXTERNAL_OUTPUT_TOOLS = [
    "email.send",
    "http.post",
    "browser.open",
]

COMMAND_EXFIL_KEYWORDS = [
    "curl",
    "wget",
    "scp",
    "nc ",
    "powershell",
]


@dataclass
class ChainEvent:
    event_id: str
    step: int
    tool: str
    params: Dict[str, Any]
    decision: str
    risk_score: int
    risk_delta: int
    stage: str
    reason: List[str]


@dataclass
class AttackChainState:
    session_id: str = field(default_factory=lambda: str(uuid4()))
    events: List[ChainEvent] = field(default_factory=list)

    external_content_seen: bool = False
    prompt_injection_seen: bool = False
    sensitive_access_seen: bool = False
    external_output_seen: bool = False
    high_risk_command_seen: bool = False

    cumulative_risk: int = 0
    final_decision: str = "allow"
    summary: List[str] = field(default_factory=list)


class AttackChainDetector:
    """
    多步攻击链检测器。
    记录一个Agent任务会话中的连续行为。
    当出现“外部内容读取 -> 提示注入 -> 敏感资源访问 -> 外发/命令执行”
    这类链式风险时，自动提升风险等级。
    """

    def __init__(self, session_id: Optional[str] = None):
        self.state = AttackChainState(
            session_id=session_id or str(uuid4())
        )

    def reset(self) -> None:
        self.state = AttackChainState()

    def add_event(
        self,
        tool: str,
        params: Dict[str, Any],
        gateway_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        gateway_result = gateway_result or {}

        normalized_tool = str(tool).strip()
        normalized_params = params or {}

        base_decision = gateway_result.get("decision", "allow")
        base_risk_score = int(gateway_result.get("risk_score", 0) or 0)

        step = len(self.state.events) + 1
        risk_delta = 0
        reason: List[str] = []
        stage = "normal"

        path = str(normalized_params.get("path", "")).lower().replace("\\", "/")
        content = str(normalized_params.get("content", "")).lower()
        command = str(normalized_params.get("command", "")).lower()
        to = str(normalized_params.get("to", "")).lower()

        # 1. 外部内容读取：例如读取public里的注入公告、打开网页等
        if normalized_tool in ["file.read", "browser.open"]:
            if path.startswith("public/") or normalized_tool == "browser.open":
                self.state.external_content_seen = True
                risk_delta += 10
                stage = "external_content_read"
                reason.append("检测到Agent读取外部或低可信内容，后续工具调用需要关注间接提示注入风险。")

        # 2. 提示注入内容检测
        matched_injection_keywords = [
            keyword for keyword in PROMPT_INJECTION_KEYWORDS
            if keyword.lower() in content
        ]

        if matched_injection_keywords:
            self.state.prompt_injection_seen = True
            risk_delta += 40
            stage = "prompt_injection_detected"
            reason.append(
                "检测到提示注入内容：" + "、".join(matched_injection_keywords)
            )

        # 3. 敏感资源访问检测
        matched_sensitive_paths = [
            keyword for keyword in SENSITIVE_PATH_KEYWORDS
            if keyword.lower() in path
        ]

        if normalized_tool in ["file.read", "file.write", "file.delete"] and matched_sensitive_paths:
            self.state.sensitive_access_seen = True
            risk_delta += 45
            stage = "sensitive_resource_access"
            reason.append(
                "检测到敏感资源访问：" + "、".join(matched_sensitive_paths)
            )

        # 4. 外发行为检测
        if normalized_tool in EXTERNAL_OUTPUT_TOOLS:
            if to and not to.endswith("@sdu.edu.cn"):
                self.state.external_output_seen = True
                risk_delta += 45
                stage = "external_output"
                reason.append("检测到向外部目标发送信息，存在数据外发风险。")

        # 5. 高危命令或外传命令检测
        matched_commands = [
            keyword for keyword in COMMAND_EXFIL_KEYWORDS
            if keyword.lower() in command
        ]

        if normalized_tool == "shell.run" and matched_commands:
            self.state.high_risk_command_seen = True
            risk_delta += 50
            stage = "high_risk_command"
            reason.append(
                "检测到可能用于外传或高危执行的命令：" + "、".join(matched_commands)
            )

        # 6. 链式风险升级
        chain_escalation = self._calculate_chain_escalation()
        if chain_escalation["risk_delta"] > 0:
            risk_delta += chain_escalation["risk_delta"]
            stage = chain_escalation["stage"]
            reason.extend(chain_escalation["reason"])

        self.state.cumulative_risk += risk_delta

        decision = self._make_decision(base_decision)

        event = ChainEvent(
            event_id=str(uuid4()),
            step=step,
            tool=normalized_tool,
            params=normalized_params,
            decision=decision,
            risk_score=base_risk_score + self.state.cumulative_risk,
            risk_delta=risk_delta,
            stage=stage,
            reason=reason or ["未发现新的攻击链风险。"],
        )

        self.state.events.append(event)
        self.state.final_decision = decision
        self.state.summary = self._build_summary()

        return self.to_dict()

    def _calculate_chain_escalation(self) -> Dict[str, Any]:
        reason = []
        risk_delta = 0
        stage = "normal"

        if self.state.external_content_seen and self.state.prompt_injection_seen:
            risk_delta += 20
            stage = "indirect_prompt_injection_chain"
            reason.append("外部内容读取后出现提示注入内容，形成间接提示注入风险链。")

        if self.state.prompt_injection_seen and self.state.sensitive_access_seen:
            risk_delta += 35
            stage = "prompt_to_sensitive_access_chain"
            reason.append("提示注入后出现敏感资源访问，疑似Agent被诱导越权读取。")

        if (
            self.state.prompt_injection_seen
            and self.state.sensitive_access_seen
            and self.state.external_output_seen
        ):
            risk_delta += 60
            stage = "data_exfiltration_chain"
            reason.append("已形成提示注入、敏感访问、外部发送的完整数据外发攻击链。")

        if (
            self.state.prompt_injection_seen
            and self.state.high_risk_command_seen
        ):
            risk_delta += 50
            stage = "prompt_to_command_execution_chain"
            reason.append("提示注入后出现高危命令执行，疑似Agent被诱导执行系统操作。")

        return {
            "risk_delta": risk_delta,
            "stage": stage,
            "reason": reason,
        }

    def _make_decision(self, base_decision: str) -> str:
        if base_decision == "deny":
            return "deny"

        if self.state.cumulative_risk >= 100:
            return "deny"

        if self.state.cumulative_risk >= 50:
            return "confirm"

        if base_decision == "confirm":
            return "confirm"

        return "allow"

    def _build_summary(self) -> List[str]:
        summary = []

        if self.state.external_content_seen:
            summary.append("已观察到外部或低可信内容读取。")

        if self.state.prompt_injection_seen:
            summary.append("已观察到提示注入内容。")

        if self.state.sensitive_access_seen:
            summary.append("已观察到敏感资源访问。")

        if self.state.external_output_seen:
            summary.append("已观察到外部信息发送。")

        if self.state.high_risk_command_seen:
            summary.append("已观察到高危命令执行。")

        if not summary:
            summary.append("当前会话未形成明显攻击链。")

        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.state.session_id,
            "cumulative_risk": self.state.cumulative_risk,
            "final_decision": self.state.final_decision,
            "summary": self.state.summary,
            "events": [
                {
                    "event_id": event.event_id,
                    "step": event.step,
                    "tool": event.tool,
                    "params": event.params,
                    "decision": event.decision,
                    "risk_score": event.risk_score,
                    "risk_delta": event.risk_delta,
                    "stage": event.stage,
                    "reason": event.reason,
                }
                for event in self.state.events
            ],
        }
