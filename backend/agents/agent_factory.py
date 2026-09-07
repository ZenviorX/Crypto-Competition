from typing import Union

from backend.agents.base_agent import BaseAgent
from backend.agents.fake_agent import FakeAgent
from backend.agents.llm_agent import LLMAgent
from backend.agents.multistep_llm_agent import MultiStepLLMAgent


AgentInstance = Union[
    BaseAgent,
    MultiStepLLMAgent,
]


def get_agent(agent_type: str = "fake") -> AgentInstance:
    """
    根据 agent_type 创建 Agent 实例。

    支持模式：
    1. fake
       - 使用 FakeAgent；
       - 适合稳定复现实验；
       - 不依赖真实大模型 API Key。

    2. llm
       - 使用 LLMAgent；
       - 单步真实大模型规划；
       - 把自然语言任务转换成一个 ToolCallPlan。

    3. multistep_llm
       - 使用 MultiStepLLMAgent；
       - 多步真实大模型规划；
       - 支持 plan() 一次性规划；
       - 支持 plan_next() 基于上一步工具输出继续规划；
       - 用于后续真实 Agent 攻击链演示。

    注意：
    所有工具调用仍然必须经过 Gateway / Runtime Monitor。
    """

    normalized_type = (agent_type or "fake").strip().lower()

    if normalized_type in {
        "fake",
        "fake_agent",
        "fakeagent",
    }:
        return FakeAgent()

    if normalized_type in {
        "llm",
        "llm_agent",
        "llmagent",
        "single_llm",
        "single_step_llm",
    }:
        return LLMAgent()

    if normalized_type in {
        "multistep_llm",
        "multi_llm",
        "multi_step_llm",
        "llm_multistep",
        "stepwise_llm",
    }:
        return MultiStepLLMAgent()

    raise ValueError(f"Unsupported agent_type: {agent_type}")