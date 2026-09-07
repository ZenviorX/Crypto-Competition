import re
import uuid

from backend.gateway.policy_loader import get_task_contract_policy
from backend.task_contract.contract_models import TaskAuthContract


def extract_email(text: str) -> list[str]:
    """
    从用户任务中提取邮箱地址。
    """
    pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    return re.findall(pattern, text)


def extract_file_path(text: str) -> list[str]:
    """
    从用户任务中提取文件路径。
    路径提取规则由 config/policy.yaml 的 task_contract.extract_file_path_pattern 控制。
    """
    contract_policy = get_task_contract_policy()
    pattern = contract_policy["extract_file_path_pattern"]
    return re.findall(pattern, text)


def build_task_contract(user: str, task_text: str) -> TaskAuthContract:
    """
    根据用户原始任务生成任务授权合约。
    默认工具、路径、风险预算等由 config/policy.yaml 控制。
    """

    task_id = str(uuid.uuid4())
    contract_policy = get_task_contract_policy()

    emails = extract_email(task_text)
    file_paths = extract_file_path(task_text)

    allowed_tools = []
    reason = []

    # 如果任务里出现了文件路径，就允许 file.read
    if file_paths:
        allowed_tools.append("file.read")
        reason.append("用户任务中明确指定了需要读取的文件路径，因此允许 file.read。")

    # 如果任务里出现了邮箱，就允许 email.send
    if emails:
        allowed_tools.append("email.send")
        reason.append("用户任务中明确指定了邮件收件人，因此允许 email.send。")

    # 如果既没有文件，也没有邮箱，先认为是普通任务
    if not allowed_tools:
        reason.append("用户任务中没有明确出现文件路径或邮箱地址，因此暂不授予高风险工具权限。")

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

    return contract
