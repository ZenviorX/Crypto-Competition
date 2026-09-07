from pathlib import Path
from typing import Any, Dict, Tuple
from fnmatch import fnmatch
from functools import lru_cache

import yaml


@lru_cache(maxsize=1)
def load_policy() -> Dict[str, Any]:
    """
    读取 config/policy.yaml 策略配置文件。

    返回值：
        Python 字典形式的策略内容
    """
    project_root = Path(__file__).resolve().parents[2]
    policy_path = project_root / "config" / "policy.yaml"

    if not policy_path.exists():
        raise FileNotFoundError(f"策略文件不存在: {policy_path}")

    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)

    if not isinstance(policy, dict):
        raise ValueError("策略文件格式错误：policy.yaml 顶层必须是字典结构")

    return policy


def clear_policy_cache():
    """
    清空策略缓存，便于测试或运行时手动重新加载配置。
    """
    load_policy.cache_clear()


def get_user_role(user: str) -> str:
    """
    根据用户名获取角色。
    如果用户没有配置，默认按普通 user 处理。
    """
    policy = load_policy()
    users = policy.get("users", {})
    return users.get(user, "user")


def get_supported_tools() -> list[str]:
    """
    获取系统支持的标准工具列表。
    """
    policy = load_policy()
    return [str(item) for item in policy.get("supported_tools", [])]


def get_required_params() -> Dict[str, list[str]]:
    """
    获取每个工具的必要参数配置。
    """
    policy = load_policy()
    required_params = policy.get("required_params", {})
    return {
        str(tool): [str(item) for item in params]
        for tool, params in required_params.items()
    }


def get_agent_plan_policy() -> Dict[str, float]:
    """
    获取 Agent 计划质量阈值。
    """
    policy = load_policy()
    agent_plan = policy.get("agent_plan", {})
    return {
        "min_auto_confidence": float(agent_plan.get("min_auto_confidence", 0.85)),
        "min_confirm_confidence": float(agent_plan.get("min_confirm_confidence", 0.55)),
    }


def get_internal_email_domains() -> list[str]:
    """
    获取内部可信邮箱域名后缀。
    """
    policy = load_policy()
    return [str(item).lower() for item in policy.get("internal_email_domains", [])]


def get_risk_score(name: str, default: int = 0) -> int:
    """
    获取某个风险项的分值。
    """
    policy = load_policy()
    risk_scores = policy.get("risk_scores", {})
    return int(risk_scores.get(name, default))


def get_tool_risk(tool: str) -> int:
    """
    获取工具基础风险分。
    如果工具没有配置，默认给 50 分。
    """
    policy = load_policy()
    tool_risk = policy.get("tool_risk", {})
    return int(tool_risk.get(tool, 50))


def get_decision_threshold() -> Dict[str, int]:
    """
    获取风险分决策阈值。
    """
    policy = load_policy()
    return policy.get(
        "decision_threshold",
        {
            "allow_max": 39,
            "confirm_max": 69,
            "deny_min": 70,
        },
    )


def get_role_policy(role: str) -> Dict[str, Any]:
    """
    获取指定角色的权限策略。
    如果角色不存在，默认使用普通 user 策略。
    """
    policy = load_policy()
    roles = policy.get("roles", {})
    return roles.get(role, roles.get("user", {}))


def _match_tool(rule_tool: str, tool: str) -> bool:
    """
    判断策略中的工具名是否匹配当前工具。
    支持 * 通配符。
    """
    return rule_tool == "*" or rule_tool == tool


def _match_resource(rule_resource: str, resource: str) -> bool:
    """
    判断策略中的资源规则是否匹配当前资源。
    支持 public/*、secret/*、* 这类写法。
    """
    if not rule_resource:
        return True

    if rule_resource == "*":
        return True

    return fnmatch(resource, rule_resource)


def _match_rule(rule: Dict[str, Any], tool: str, resource: str) -> bool:
    """
    判断单条策略规则是否命中。
    """
    rule_tool = str(rule.get("tool", ""))
    rule_resource = str(rule.get("resource", ""))

    if not _match_tool(rule_tool, tool):
        return False

    if rule_resource:
        return _match_resource(rule_resource, resource)

    return True


def match_role_policy(role: str, tool: str, resource: str) -> Tuple[str, str]:
    """
    根据角色、工具名和资源路径匹配权限策略。

    返回：
        policy_decision: allow / confirm / deny / none
        policy_reason: 命中的策略说明

    策略优先级：
        deny > confirm > allow
    """
    role_policy = get_role_policy(role)

    for rule in role_policy.get("deny", []):
        if _match_rule(rule, tool, resource):
            return "deny", f"命中 {role} 角色 deny 策略"

    for rule in role_policy.get("confirm", []):
        if _match_rule(rule, tool, resource):
            return "confirm", f"命中 {role} 角色 confirm 策略"

    for rule in role_policy.get("allow", []):
        if _match_rule(rule, tool, resource):
            return "allow", f"命中 {role} 角色 allow 策略"

    return "none", f"未命中 {role} 角色的显式权限策略"


def get_resource_risk_rules() -> Dict[str, int]:
    """
    获取资源路径风险规则。
    """
    policy = load_policy()
    resource_risk = policy.get("resource_risk", {})

    result = {}
    for keyword, score in resource_risk.items():
        result[str(keyword).lower()] = int(score)

    return result


def get_resource_risk(path: str) -> tuple[int, list[str]]:
    """
    根据资源路径计算资源风险分。

    返回：
        risk_score: 资源路径带来的风险分
        reasons: 风险原因列表
    """
    path_lower = str(path).lower().replace("\\", "/")
    rules = get_resource_risk_rules()

    risk_score = 0
    reasons = []

    for keyword, score in rules.items():
        if keyword and keyword in path_lower and score > 0:
            risk_score += score
            reasons.append(f"访问路径命中资源风险规则：{keyword}，风险分 +{score}")

    return risk_score, reasons


def get_dangerous_keywords(category: str) -> list[str]:
    """
    获取指定类别的危险关键词。

    category 可选：
        path              路径风险关键词
        command           命令风险关键词
        prompt_injection  提示注入关键词
        sensitive_content 敏感内容关键词
        sensitive_path    敏感路径关键词
        sql               SQL 高危关键词
    """
    policy = load_policy()
    dangerous_keywords = policy.get("dangerous_keywords", {})
    keywords = dangerous_keywords.get(category, [])

    return [str(item).lower() for item in keywords]


def get_external_output_tools() -> set[str]:
    """
    获取可能造成数据外发或副作用的工具列表。
    """
    policy = load_policy()
    return {str(item) for item in policy.get("external_output_tools", [])}


def get_task_contract_policy() -> Dict[str, Any]:
    """
    获取任务授权合约默认策略。
    """
    policy = load_policy()
    contract_policy = policy.get("task_contract", {})
    return {
        "extract_file_path_pattern": str(
            contract_policy.get(
                "extract_file_path_pattern",
                r"(public/[a-zA-Z0-9_.\-/]+|data/[a-zA-Z0-9_.\-/]+|logs/[a-zA-Z0-9_.\-/]+)",
            )
        ),
        "default_denied_tools": [
            str(item) for item in contract_policy.get("default_denied_tools", [])
        ],
        "default_denied_paths": [
            str(item) for item in contract_policy.get("default_denied_paths", [])
        ],
        "default_risk_budget": int(contract_policy.get("default_risk_budget", 80)),
        "default_allow_external_send": bool(
            contract_policy.get("default_allow_external_send", False)
        ),
        "default_require_human_confirm": bool(
            contract_policy.get("default_require_human_confirm", False)
        ),
    }


def match_keywords(text: str, keywords: list[str]) -> list[str]:
    """
    检查文本中命中了哪些关键词。
    """
    text_lower = str(text).lower()
    matched = []

    for keyword in keywords:
        keyword_lower = str(keyword).lower()
        if keyword_lower and keyword_lower in text_lower:
            matched.append(keyword)

    return matched
