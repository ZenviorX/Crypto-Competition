import re
from typing import Dict, List

from backend.gateway.policy_loader import (
    get_dangerous_keywords,
    get_external_output_tools,
)


SECRET_VALUE_PATTERNS = [
    r"\bpassword\s*[:=]\s*\S+",
    r"\bpasswd\s*[:=]\s*\S+",
    r"\bapi_key\s*[:=]\s*\S+",
    r"\bapikey\s*[:=]\s*\S+",
    r"\baccess_key\s*[:=]\s*\S+",
    r"\bprivate_key\s*[:=]\s*\S+",
    r"\btoken\s*[:=]\s*\S+",
    r"\bcredential\s*[:=]\s*\S+",
    r"密钥\s*[:：=]\s*\S+",
    r"密码\s*[:：=]\s*\S+",
    r"令牌\s*[:：=]\s*\S+",
]


SENSITIVE_DATA_KEYWORDS = [
    "身份证",
    "手机号",
    "银行卡",
    "住址",
    "家庭住址",
    "id_card",
    "phone_number",
    "bank_card",
    "credential=",
    "password=",
    "passwd=",
    "token=",
    "api_key=",
    "apikey=",
    "private_key=",
]


PROMPT_INJECTION_PATH_PATTERNS = [
    "secret/",
    "private/",
    "../",
    "secret\\",
    "private\\",
]


def _matches_secret_value(text: str) -> bool:
    """
    判断文本里是否真的包含 secret/password/token 等敏感值。

    注意：
    这里区分两种情况：

    1. secret/password.txt
       这只是一个路径诱导，不应该直接算敏感数据泄露；
       应该更偏向 tainted / prompt_injection。

    2. password=xxx / token=xxx / api_key=xxx
       这才是真正的敏感值，应标记 sensitive。
    """

    for pattern in SECRET_VALUE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True

    return False


def _contains_sensitive_data_keyword(text: str) -> bool:
    """
    判断文本是否包含真正的数据型敏感关键词。
    """

    lower_text = text.lower()

    for keyword in SENSITIVE_DATA_KEYWORDS:
        if keyword.lower() in lower_text:
            return True

    return False


def _contains_prompt_injection_path(text: str) -> bool:
    """
    判断文本是否包含诱导访问敏感路径的内容。
    """

    lower_text = text.lower()

    for pattern in PROMPT_INJECTION_PATH_PATTERNS:
        if pattern in lower_text:
            return True

    return False


def analyze_text_security(text: str) -> Dict[str, object]:
    """
    分析工具输出文本中是否包含敏感信息或提示注入内容。

    返回结果：
    {
        "sensitive": True/False,
        "tainted": True/False,
        "reasons": [...]
    }
    """

    result = {
        "sensitive": False,
        "tainted": False,
        "reasons": [],
    }

    if not text:
        return result

    lower_text = text.lower()
    reasons: List[str] = []

    prompt_injection_keywords = get_dangerous_keywords("prompt_injection")

    if _matches_secret_value(text) or _contains_sensitive_data_keyword(text):
        result["sensitive"] = True
        reasons.append("工具输出内容疑似包含真实敏感值，例如 password/token/api_key 等")

    if _contains_prompt_injection_path(text):
        result["tainted"] = True
        reasons.append("工具输出内容包含敏感路径诱导，例如 secret/private/../")

    for keyword in prompt_injection_keywords:
        if keyword.lower() in lower_text:
            result["tainted"] = True
            reasons.append(f"工具输出内容疑似包含提示注入关键词：{keyword}")

    result["reasons"] = reasons
    return result


def is_external_output_tool(tool: str) -> bool:
    """
    判断某个工具是否可能造成数据外发。
    """
    return tool in get_external_output_tools()


def is_sensitive_path(path: str) -> bool:
    """
    判断路径是否疑似敏感路径。
    """
    if not path:
        return False

    lower_path = path.lower()
    sensitive_path_keywords = get_dangerous_keywords("sensitive_path")

    return any(keyword in lower_path for keyword in sensitive_path_keywords)