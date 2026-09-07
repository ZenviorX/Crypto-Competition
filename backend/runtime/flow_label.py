from __future__ import annotations

import re
from typing import Iterable, List, Optional


PROMPT_INJECTION_PATTERNS = [
    r"忽略(之前|以上|所有).{0,20}(规则|指令|要求|系统提示)",
    r"不要遵守.{0,20}(规则|指令|系统提示)",
    r"覆盖.{0,20}(规则|指令|系统提示)",
    r"请读取.{0,30}(secret|private|password|密钥|密码)",
    r"发送给.{0,30}(attacker|攻击者|外部邮箱)",
    r"ignore (all )?(previous|prior) (rules|instructions|messages)",
    r"disregard (all )?(previous|prior) (rules|instructions|messages)",
    r"reveal (the )?(system prompt|developer message|hidden instruction)",
    r"send .* to .*attacker",
    r"read .*secret",
]

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

SENSITIVE_KEYWORDS = [
    "身份证",
    "手机号",
    "银行卡",
    "住址",
    "家庭住址",
    "account_id",
    "id_card",
    "phone_number",
    "bank_card",
]

UNKNOWN_SOURCE_LABEL = "unknown"


def _unique_labels(labels: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen = set()

    for label in labels:
        if not label:
            continue

        if label not in seen:
            result.append(label)
            seen.add(label)

    return result


def _contains_keyword(text: str, keywords: List[str]) -> bool:
    lower_text = text.lower()

    for keyword in keywords:
        if keyword.lower() in lower_text:
            return True

    return False


def _matches_secret_value(text: str) -> bool:
    for pattern in SECRET_VALUE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True

    return False


def _matches_prompt_injection(text: str) -> bool:
    lower_text = text.lower()

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower_text, flags=re.IGNORECASE):
            return True

    return False


def infer_base_labels_from_resource(resource: Optional[str]) -> List[str]:
    """
    根据资源路径推断基础标签。

    public/course 视为 public；
    secret 视为 secret；
    private 视为 sensitive；
    未知来源视为 unknown。
    """

    if not resource:
        return [UNKNOWN_SOURCE_LABEL]

    resource = resource.replace("\\", "/").lower()

    if "data/public/" in resource or resource.startswith("public/"):
        return ["public"]

    if "data/course/" in resource or resource.startswith("course/"):
        return ["public"]

    if "data/secret/" in resource or resource.startswith("secret/"):
        return ["secret"]

    if "data/private/" in resource or resource.startswith("private/"):
        return ["sensitive"]

    if resource.startswith("../"):
        return ["sensitive"]

    return [UNKNOWN_SOURCE_LABEL]


def analyze_output_labels(
    content: Optional[str],
    base_labels: Optional[List[str]] = None,
    resource: Optional[str] = None,
) -> List[str]:
    """
    根据工具输出内容生成数据标签。

    输入：
    - content：工具输出内容，例如文件内容、查询结果、网页返回内容
    - base_labels：已有基础标签，例如 ["public"]
    - resource：资源路径，例如 data/public/injected_notice.txt

    输出：
    - public / sensitive / secret / tainted / prompt_injection / unknown 等标签
    """

    labels: List[str] = []

    if base_labels:
        labels.extend(base_labels)
    else:
        labels.extend(infer_base_labels_from_resource(resource))

    text = content or ""

    if _matches_secret_value(text):
        labels.append("sensitive")
        labels.append("secret")

    if _contains_keyword(text, SENSITIVE_KEYWORDS):
        labels.append("sensitive")

    if _matches_prompt_injection(text):
        labels.append("prompt_injection")
        labels.append("tainted")

    # 如果文本中同时出现 secret/private 路径，也认为它有越权诱导风险
    lower_text = text.lower()
    if "secret/" in lower_text or "private/" in lower_text or "../" in lower_text:
        labels.append("tainted")

    return _unique_labels(labels)


def is_tainted(labels: List[str]) -> bool:
    return bool(set(labels) & {"tainted", "prompt_injection", "unknown"})


def is_sensitive(labels: List[str]) -> bool:
    return bool(set(labels) & {"sensitive", "secret"})
