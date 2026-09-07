from pydantic import BaseModel

from fastapi import APIRouter

from backend.task_contract.contract_builder import build_task_contract


router = APIRouter(
    prefix="/task-contract",
    tags=["task-contract"]
)


class BuildTaskContractRequest(BaseModel):
    """
    生成任务授权合约的请求体。
    """

    user: str = "user"
    task_text: str


@router.post("/build")
def build_contract(request: BuildTaskContractRequest):
    """
    根据用户原始任务生成任务授权合约。
    """

    contract = build_task_contract(
        user=request.user,
        task_text=request.task_text
    )

    return {
        "message": "任务授权合约生成成功",
        "contract": contract.model_dump()
    }
