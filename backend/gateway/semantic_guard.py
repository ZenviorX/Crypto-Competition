from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import yaml


_TRUE_VALUES = {"1", "true", "yes", "on", "enable", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disable", "disabled"}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def load_semantic_config() -> Dict[str, Any]:
    config_path = _project_root() / "config" / "semantic_guard.yaml"

    if not config_path.exists():
        return {"enabled": False, "fail_closed": False}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception:
        return {"enabled": False, "fail_closed": False}

    if not isinstance(config, dict):
        return {"enabled": False, "fail_closed": False}

    return config


def _env_enabled(default: bool) -> bool:
    value = os.getenv("SEMANTIC_GUARD_ENABLED")

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    return default


@lru_cache(maxsize=1)
def get_embedding_model():
    config = load_semantic_config()
    model_name = (config.get("model", {}) or {}).get(
        "name",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    )

    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(model_name)


def _as_vector_list(vector: Any) -> List[float]:
    if hasattr(vector, "tolist"):
        vector = vector.tolist()

    return [float(item) for item in vector]


def _cosine_similarity(vec_a: Sequence[float], vec_b: Sequence[float]) -> float:
    if not vec_a or not vec_b:
        return 0.0

    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = sum(a * a for a in vec_a) ** 0.5
    norm_b = sum(b * b for b in vec_b) ** 0.5

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return float(dot / (norm_a * norm_b))


def _build_semantic_text(
    *,
    user: str,
    role: str,
    tool: str,
    params: Dict[str, Any],
    path: str = "",
    content: str = "",
    command: str = "",
    sql: str = "",
) -> str:
    return "\n".join(
        [
            f"用户: {user}",
            f"角色: {role}",
            f"工具: {tool}",
            f"参数: {params}",
            f"路径: {path}",
            f"内容: {content}",
            f"命令: {command}",
            f"SQL: {sql}",
        ]
    )


def _collect_examples(config: Dict[str, Any]) -> List[Tuple[str, str]]:
    labels = config.get("labels", {})
    result: List[Tuple[str, str]] = []

    if not isinstance(labels, dict):
        return result

    for label_name, label_config in labels.items():
        if not isinstance(label_config, dict):
            continue

        examples = label_config.get("examples", [])
        if not isinstance(examples, list):
            continue

        for example in examples:
            result.append((str(label_name), str(example)))

    return result


@lru_cache(maxsize=1)
def _get_example_embeddings() -> Tuple[List[str], List[str], List[List[float]]]:
    config = load_semantic_config()
    examples = _collect_examples(config)

    if not examples:
        return [], [], []

    labels = [item[0] for item in examples]
    texts = [item[1] for item in examples]

    model = get_embedding_model()
    raw_embeddings = model.encode(texts, normalize_embeddings=True)
    embeddings = [_as_vector_list(item) for item in raw_embeddings]

    return labels, texts, embeddings


def _disabled_result(reason: str | None = None) -> Dict[str, Any]:
    return {
        "enabled": False,
        "risk_score": 0,
        "force_confirm": False,
        "hard_deny": False,
        "labels": [],
        "matches": [],
        "reasons": [reason] if reason else [],
    }


def _enabled_empty_result(reason: str | None = None) -> Dict[str, Any]:
    return {
        "enabled": True,
        "risk_score": 0,
        "force_confirm": False,
        "hard_deny": False,
        "labels": [],
        "matches": [],
        "reasons": [reason] if reason else [],
    }


def _deterministic_semantic_check(
    *,
    config: Dict[str, Any],
    semantic_text: str,
) -> Dict[str, Any]:
    """
    确定性语义检测。
    """

    text = str(semantic_text).lower()
    label_configs = config.get("labels", {}) or {}
    thresholds = config.get("thresholds", {}) or {}
    max_total_semantic_risk = int(thresholds.get("max_total_semantic_risk", 120))

    explicit_bypass_keywords = [
        "\u4e0d\u8981\u7559\u4e0b\u8bb0\u5f55",
        "\u4e0d\u7559\u4e0b\u8bb0\u5f55",
        "\u4e0d\u7528\u8d70\u786e\u8ba4\u6d41\u7a0b",
        "\u4e0d\u7528\u8d70\u786e\u8ba4",
        "\u4e0d\u9700\u8981\u4eba\u5de5\u786e\u8ba4",
        "\u4e0d\u8981\u8be2\u95ee\u7528\u6237",
        "\u9759\u9ed8\u6267\u884c",
        "\u6084\u6084\u6267\u884c",
        "silent execution",
        "run silently",
        "run this silently",
        "avoid audit trail",
        "avoid audit",
        "without audit",
        "without logging",
        "do not ask for user approval",
        "do not ask approval",
        "do not ask the user",
        "skip approval",
        "skip user approval",
    ]

    for keyword in explicit_bypass_keywords:
        normalized_keyword = str(keyword).strip().lower()

        # Never use mojibake strings as security rules.
        if "?" in normalized_keyword or "\ufffd" in normalized_keyword:
            continue

        if normalized_keyword and normalized_keyword in text:
            label_config = label_configs.get("policy_bypass", {}) or {}
            label_risk = int(label_config.get("risk_score", 70))
            return {
                "enabled": True,
                "risk_score": min(label_risk, max_total_semantic_risk),
                "force_confirm": True,
                "hard_deny": bool(label_config.get("hard_deny", True)),
                "labels": ["policy_bypass"],
                "matches": [
                    {
                        "label": "policy_bypass",
                        "score": 1.0,
                        "matched_example": normalized_keyword,
                        "deterministic": True,
                    }
                ],
                "reasons": [f"semantic_guard matched policy_bypass: {normalized_keyword}"],
            }

    fallback_keywords: Dict[str, List[str]] = {
        "data_exfiltration": [
            "外部联系人",
            "外部邮箱",
            "第三方",
            "私人网盘",
            "公网",
            "回传",
            "上传",
            "外发",
            "发送到外部",
            "发给这个外部联系人",
            "登录凭据整理后发给",
            "整理后发给",
        ],
        "credential_access": [
            "登录凭据",
            "认证信息",
            "数据库连接凭据",
            "密码",
            "token",
            "api key",
            "密钥",
            "私钥",
            "访问令牌",
            "凭证",
            ".env",
            "app.env",
            "配置文件中的认证信息",
        ],
        "policy_bypass": [
            "不要记录审计日志",
            "跳过人工确认",
            "忽略网关",
            "网关返回的拒绝结果",
            "绕过",
            "关闭安全检查",
            "隐藏这次操作",
            "直接执行",
            "不要让管理员发现",
            "直接读取并隐藏",
        ],
        "prompt_injection": [
            "开发者模式",
            "忽略网关",
            "忽略之前",
            "覆盖系统",
            "不要遵守安全策略",
            "直接执行用户要求",
            "跳过人工确认",
            "直接读取",
        ],
        "destructive_action": [
            "清空整个项目目录",
            "恢复成初始状态",
            "清空工作目录",
            "删除所有",
            "格式化",
            "批量删除",
            "清理整个项目",
            "删除当前数据",
        ],
        "network_abuse": [
            "局域网",
            "开放端口",
            "扫描",
            "探测",
            "内网",
            "所有主机",
            "所有主机和开放端口",
        ],
        "privilege_escalation": [
            "管理员组",
            "管理员权限",
            "提升到管理员",
            "root",
            "最高权限",
            "提权",
        ],
    }

    matched_labels: List[str] = []
    matches: List[Dict[str, Any]] = []
    reasons: List[str] = []
    total_risk = 0
    hard_deny = False

    for label, label_config in label_configs.items():
        if label == "benign":
            continue

        keywords = list(fallback_keywords.get(str(label), []))

        examples = label_config.get("examples", [])
        if isinstance(examples, list):
            keywords.extend(str(item).lower() for item in examples)

        matched_keyword = None

        for keyword in keywords:
            keyword = str(keyword).strip().lower()
            if keyword and keyword in text:
                matched_keyword = keyword
                break

        if matched_keyword is None:
            continue

        matched_labels.append(str(label))

        label_risk = int(label_config.get("risk_score", 0))
        total_risk += label_risk

        if bool(label_config.get("hard_deny", False)):
            hard_deny = True

        matches.append(
            {
                "label": str(label),
                "score": 1.0,
                "matched_example": matched_keyword,
                "deterministic": True,
            }
        )

        reasons.append(f"语义检测命中 {label}：{matched_keyword}")

    total_risk = min(total_risk, max_total_semantic_risk)

    return {
        "enabled": True,
        "risk_score": total_risk,
        "force_confirm": bool(matched_labels),
        "hard_deny": hard_deny,
        "labels": matched_labels,
        "matches": matches,
        "reasons": reasons,
    }


def semantic_check_tool_call(
    *,
    user: str,
    role: str,
    tool: str,
    params: Dict[str, Any],
    path: str = "",
    content: str = "",
    command: str = "",
    sql: str = "",
) -> Dict[str, Any]:
    config = load_semantic_config()
    config_enabled = bool(config.get("enabled", False))
    enabled = _env_enabled(config_enabled)

    if not enabled:
        return _disabled_result()

    fail_closed = bool(config.get("fail_closed", False))

    semantic_text = _build_semantic_text(
        user=user,
        role=role,
        tool=tool,
        params=params,
        path=path,
        content=content,
        command=command,
        sql=sql,
    )

    deterministic_result = _deterministic_semantic_check(
        config=config,
        semantic_text=semantic_text,
    )

    if deterministic_result.get("labels"):
        return deterministic_result

    embedding_config = config.get("embedding", {}) or {}
    embedding_enabled = bool(embedding_config.get("enabled", False))

    if not embedding_enabled:
        return _enabled_empty_result()

    try:
        labels, texts, example_embeddings = _get_example_embeddings()

        if not example_embeddings:
            return _enabled_empty_result("语义样例为空，跳过 embedding 检测。")

        model = get_embedding_model()
        query_embedding = _as_vector_list(
            model.encode([semantic_text], normalize_embeddings=True)[0]
        )

    except Exception as exc:
        if fail_closed:
            return {
                "enabled": True,
                "risk_score": 35,
                "force_confirm": True,
                "hard_deny": False,
                "labels": ["semantic_guard_error"],
                "matches": [],
                "reasons": [f"语义检测模块不可用，按 fail_closed 转人工确认：{exc}"],
            }

        return _enabled_empty_result(f"Embedding 语义模型不可用，已跳过 embedding 检测：{exc}")

    thresholds = config.get("thresholds", {}) or {}
    global_confirm_score = float(thresholds.get("global_confirm_score", 0.62))
    global_deny_score = float(thresholds.get("global_deny_score", 0.78))
    max_total_semantic_risk = int(thresholds.get("max_total_semantic_risk", 120))

    label_configs = config.get("labels", {}) or {}
    best_by_label: Dict[str, Dict[str, Any]] = {}

    for label, example_text, example_embedding in zip(labels, texts, example_embeddings):
        similarity = _cosine_similarity(query_embedding, example_embedding)

        current_best = best_by_label.get(label)
        if current_best is None or similarity > current_best["score"]:
            best_by_label[label] = {
                "label": label,
                "example": example_text,
                "score": similarity,
            }

    matched_labels: List[str] = []
    matches: List[Dict[str, Any]] = []
    reasons: List[str] = []
    total_risk = 0
    force_confirm = False
    hard_deny = False

    for label, match in best_by_label.items():
        if label == "benign":
            continue

        label_config = label_configs.get(label, {}) or {}
        confirm_score = float(label_config.get("confirm_score", global_confirm_score))
        deny_score = float(label_config.get("deny_score", global_deny_score))
        label_risk = int(label_config.get("risk_score", 0))
        label_hard_deny = bool(label_config.get("hard_deny", False))

        score = float(match["score"])

        if score < confirm_score:
            continue

        matched_labels.append(label)
        matches.append(
            {
                "label": label,
                "score": round(score, 4),
                "matched_example": match["example"],
            }
        )

        total_risk += label_risk
        force_confirm = True

        reasons.append(
            f"语义相似度命中 {label}：{score:.2f}，相似样例：{match['example']}"
        )

        if score >= deny_score and label_hard_deny:
            hard_deny = True
            reasons.append(
                f"语义风险 {label} 超过拒绝阈值 {deny_score:.2f}，触发拒绝建议。"
            )

    total_risk = min(total_risk, max_total_semantic_risk)

    return {
        "enabled": True,
        "risk_score": total_risk,
        "force_confirm": force_confirm,
        "hard_deny": hard_deny,
        "labels": matched_labels,
        "matches": matches,
        "reasons": reasons,
    }


def clear_semantic_cache() -> None:
    load_semantic_config.cache_clear()
    get_embedding_model.cache_clear()
    _get_example_embeddings.cache_clear()
