import fnmatch
from typing import Dict, Any

from backend.task_contract.contract_models import TaskAuthContract, ContractCheckResult


def _match_any_pattern(value: str, patterns: list[str]) -> bool:
    """
    判断 value 是否匹配 patterns 中的任意一个模式。

    例如：
    value = "secret/password.txt"
    patterns = ["secret/*", "private/*"]
    则会匹配成功。
    """
    for pattern in patterns:
        if fnmatch.fnmatch(value, pattern):
            return True
    return False


def check_call_against_contract(
    contract: TaskAuthContract,
    tool: str,
    params: Dict[str, Any]
) -> ContractCheckResult:
    """
    检查某一次工具调用是否符合任务授权合约。
    """

    risk_score = 0
    reason = []

    # 1. 检查工具是否在禁止列表中
    if tool in contract.denied_tools:
        risk_score += 100
        reason.append(f"工具 {tool} 在本次任务授权合约的禁止工具列表中。")
        return ContractCheckResult(
            decision="deny",
            risk_score=risk_score,
            reason=reason
        )

    # 2. 检查工具是否超出本次任务允许范围
    if contract.allowed_tools and tool not in contract.allowed_tools:
        risk_score += 80
        reason.append(f"工具 {tool} 不在本次任务允许工具列表中。")
        return ContractCheckResult(
            decision="deny",
            risk_score=risk_score,
            reason=reason
        )

    # 3. 检查文件读取是否越界
    if tool == "file.read":
        path = str(params.get("path", ""))

        if not path:
            risk_score += 60
            reason.append("file.read 调用缺少 path 参数。")
            return ContractCheckResult(
                decision="deny",
                risk_score=risk_score,
                reason=reason
            )

        if _match_any_pattern(path, contract.denied_paths):
            risk_score += 100
            reason.append(f"读取路径 {path} 命中本次任务禁止访问范围。")
            return ContractCheckResult(
                decision="deny",
                risk_score=risk_score,
                reason=reason
            )

        if contract.allowed_read_paths and path not in contract.allowed_read_paths:
            risk_score += 90
            reason.append(f"读取路径 {path} 不在本次任务允许读取范围内。")
            return ContractCheckResult(
                decision="deny",
                risk_score=risk_score,
                reason=reason
            )

        reason.append(f"读取路径 {path} 符合本次任务授权范围。")
        return ContractCheckResult(
            decision="allow",
            risk_score=risk_score,
            reason=reason
        )

    # 4. 检查邮件发送是否越界
    if tool == "email.send":
        to = str(params.get("to", ""))

        if not to:
            risk_score += 60
            reason.append("email.send 调用缺少 to 参数。")
            return ContractCheckResult(
                decision="deny",
                risk_score=risk_score,
                reason=reason
            )

        if not contract.allow_external_send and contract.allowed_email_to:
            if to not in contract.allowed_email_to:
                risk_score += 100
                reason.append(f"邮件收件人 {to} 不在本次任务允许发送范围内。")
                return ContractCheckResult(
                    decision="deny",
                    risk_score=risk_score,
                    reason=reason
                )

        reason.append(f"邮件收件人 {to} 符合本次任务授权范围。")
        return ContractCheckResult(
            decision="allow",
            risk_score=risk_score,
            reason=reason
        )

    # 5. 其他工具暂时按合约允许结果放行
    reason.append(f"工具 {tool} 未触发任务合约违规规则。")
    return ContractCheckResult(
        decision="allow",
        risk_score=risk_score,
        reason=reason
    )