from typing import List, Optional
from pydantic import BaseModel, Field


class TaskAuthContract(BaseModel):
    """
    任务授权合约。
    """

    task_id: str = Field(..., description="任务编号")
    user: str = Field(..., description="发起任务的用户")
    original_task: str = Field(..., description="用户原始任务输入")

    task_goal: str = Field(..., description="抽象后的任务目标")

    allowed_tools: List[str] = Field(default_factory=list, description="本任务允许使用的工具")
    denied_tools: List[str] = Field(default_factory=list, description="本任务禁止使用的工具")

    allowed_read_paths: List[str] = Field(default_factory=list, description="本任务允许读取的文件路径")
    denied_paths: List[str] = Field(default_factory=list, description="本任务禁止访问的路径")

    allowed_email_to: List[str] = Field(default_factory=list, description="本任务允许发送邮件的收件人")
    allow_external_send: bool = Field(default=False, description="是否允许向外部发送数据")

    risk_budget: int = Field(default=80, description="本任务允许消耗的最大风险预算")
    require_human_confirm: bool = Field(default=False, description="本任务是否默认需要人工确认")

    reason: List[str] = Field(default_factory=list, description="生成该合约的原因说明")
    
class ContractCheckResult(BaseModel):
    """
    单次工具调用是否符合任务授权合约的检查结果。
    """

    decision: str = Field(..., description="检查结果：allow / deny / confirm")
    risk_score: int = Field(default=0, description="由于违反任务合约产生的额外风险分")
    reason: List[str] = Field(default_factory=list, description="检查原因说明")