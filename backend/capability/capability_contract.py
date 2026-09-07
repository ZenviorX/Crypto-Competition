from typing import List, Optional, Literal
from pydantic import BaseModel, Field


DataLabel = Literal[
    "public",              # 普通公开数据
    "internal",            # 内部数据
    "sensitive",           # 敏感数据
    "secret",              # 高敏感/密钥类数据
    "tainted",             # 被提示注入污染的数据
    "prompt_injection",    # 明确包含提示注入内容
    "unknown"              # 无法判断来源或敏感性的内容
]


CapabilityMode = Literal[
    "read",            # 读取资源
    "write",           # 写入资源
    "delete",          # 删除资源
    "external_write",  # 对外发送，例如邮件、HTTP 请求
    "execute",         # 执行命令或代码
    "query"            # 查询数据库或知识库
]


Decision = Literal["allow", "confirm", "deny"]


class CapabilityRule(BaseModel):
    """
    单条能力规则。
    """

    tool: str = Field(..., description="工具名称，例如 file.read / email.send / shell.run")
    mode: CapabilityMode = Field(..., description="能力模式，例如 read / external_write / execute")

    resource_patterns: List[str] = Field(
        default_factory=list,
        description="允许访问的资源范围，例如 data/public/*.txt"
    )

    recipients: List[str] = Field(
        default_factory=list,
        description="允许外发的目标，例如 admin@sdu.edu.cn"
    )

    allowed_input_labels: List[DataLabel] = Field(
        default_factory=list,
        description="该工具允许接收的数据标签"
    )

    output_labels: List[DataLabel] = Field(
        default_factory=list,
        description="该工具执行后产生的数据标签"
    )

    risk_cost: int = Field(
        default=0,
        description="使用该能力消耗的风险预算"
    )

    require_approval: bool = Field(
        default=False,
        description="使用该能力是否需要人工确认"
    )


class CapabilityContract(BaseModel):

    contract_version: str = Field(
        default="2.0",
        description="能力合约版本"
    )

    compiler_version: str = Field(
        default="legacy",
        description="生成该合约的 TaskSpec 编译器版本"
    )

    compilation_status: Literal[
        "compiled",
        "restricted",
        "rejected",
    ] = Field(
        default="compiled",
        description="任务编译结果：正常、受限或失败关闭"
    )

    source_task_sha256: str = Field(
        default="",
        description="用户原始任务文本的 SHA-256 摘要"
    )

    task_id: str = Field(..., description="任务编号")
    user: str = Field(..., description="发起任务的用户")
    original_task: str = Field(..., description="用户原始任务")
    task_goal: str = Field(..., description="抽象后的任务目标")

    capabilities: List[CapabilityRule] = Field(
        default_factory=list,
        description="本任务授予的能力列表"
    )

    forbidden_tools: List[str] = Field(
        default_factory=list,
        description="本任务明确禁止使用的工具"
    )

    forbidden_resources: List[str] = Field(
        default_factory=list,
        description="本任务明确禁止访问的资源"
    )

    max_steps: int = Field(
        default=5,
        description="本任务最多允许执行的工具调用步数"
    )

    risk_budget: int = Field(
        default=80,
        description="本任务总风险预算"
    )

    expires_at: Optional[str] = Field(
        default=None,
        description="合约过期时间，暂时使用字符串，后续再接 datetime"
    )

    approval_required_when: List[str] = Field(
        default_factory=list,
        description="触发人工确认的条件，例如 external_write / tainted_input / sensitive_input"
    )

    reason: List[str] = Field(
        default_factory=list,
        description="生成该能力合约的原因说明"
    )


class CapabilityCheckResult(BaseModel):
    """
    能力合约检查结果。

    """

    decision: Decision = Field(..., description="allow / confirm / deny")
    risk_score: int = Field(default=0, description="本次检查产生的风险分")
    reason: List[str] = Field(default_factory=list, description="检查原因")
