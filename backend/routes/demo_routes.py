from fastapi import APIRouter

from backend.demo import (
    list_demo_cases,
    run_demo_case,
    run_fake_agent_demo,
    run_fake_agent_plan,
)
from backend.schemas import AgentTextRequest


router = APIRouter(
    prefix="/demo",
    tags=["demo"],
)


@router.get("/cases")
def get_demo_cases():
    """
    查看所有内置演示样例。
    """
    return list_demo_cases()


@router.post("/fake-agent/plan")
def fake_agent_plan(request: AgentTextRequest):
    return run_fake_agent_plan(request)


@router.post("/fake-agent/run")
def fake_agent_run(request: AgentTextRequest):
    """
    运行完整演示链路：

    1. FakeAgent 解析自然语言；
    2. 生成 ToolCallRequest；
    3. 交给 Gateway 判断；
    4. allow 时执行工具；
    5. confirm 时进入 pending；
    6. deny 时直接拦截。
    """
    return run_fake_agent_demo(request)


@router.post("/cases/{case_id}/run")
def run_builtin_demo_case(case_id: str):
    """
    运行一个内置 demo case。

    示例：
    - /demo/cases/read_public_file/run
    - /demo/cases/read_secret_file/run
    - /demo/cases/delete_public_file/run
    - /demo/cases/send_email/run
    - /demo/cases/shell_command/run
    """
    return run_demo_case(case_id)