from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.capability.capability_compiler import compile_capability_contract
from backend.capability.capability_contract import CapabilityContract
from backend.capability.capability_enforcer import enforce_capability_contract


router = APIRouter(
    prefix="/capability",
    tags=["Capability Contract v2"],
)


class CapabilityCompileRequest(BaseModel):
    user: str = Field(default="user", description="发起任务的用户")
    original_task: str = Field(..., description="用户原始自然语言任务")
    max_steps: int = Field(default=5, description="任务最大工具调用步数")
    risk_budget: int = Field(default=80, description="任务风险预算")


class CapabilityEnforceRequest(BaseModel):
    contract: CapabilityContract = Field(..., description="Capability Contract v2")
    tool: str = Field(..., description="当前请求调用的工具")
    params: Dict[str, Any] = Field(default_factory=dict, description="工具调用参数")
    input_labels: List[str] = Field(default_factory=list, description="输入数据标签")
    current_step: int = Field(default=1, description="当前工具调用步数")
    used_risk: int = Field(default=0, description="当前任务已经消耗的风险预算")


@router.post("/compile")
def compile_contract(request: CapabilityCompileRequest):
    """
    将用户自然语言任务编译为 Capability Contract v2。

    示例：
    用户任务：读取 public/notice.txt 并发送给 admin@sdu.edu.cn
    输出：任务级能力合约，包括允许的工具、资源、收件人、风险预算等。
    """

    contract = compile_capability_contract(
        user=request.user,
        original_task=request.original_task,
        max_steps=request.max_steps,
        risk_budget=request.risk_budget,
    )

    return {
        "message": "Capability Contract v2 compiled successfully.",
        "contract": contract.model_dump(),
    }


@router.post("/enforce")
def enforce_contract(request: CapabilityEnforceRequest):
    """
    检查一次工具调用是否符合 Capability Contract v2。

    示例：
    contract 允许读取 public/notice.txt，
    那么 file.read public/notice.txt -> allow，
    file.read secret/password.txt -> deny。
    """

    result = enforce_capability_contract(
        contract=request.contract,
        tool=request.tool,
        params=request.params,
        input_labels=request.input_labels,
        current_step=request.current_step,
        used_risk=request.used_risk,
    )

    return {
        "message": "Capability Contract v2 checked successfully.",
        "result": result.model_dump(),
    }
