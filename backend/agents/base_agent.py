from abc import ABC, abstractmethod

from backend.schemas import AgentPlanResult


class BaseAgent(ABC):
    """
    Agent interface.

    Agents may only turn natural-language input into a structured tool-call
    plan. They must not execute tools or make authorization decisions.
    """

    @abstractmethod
    def plan(self, user_input: str) -> AgentPlanResult:
        pass
