from __future__ import annotations

import copy
import json
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


import backend.gateway.gateway as gateway

from backend.gateway.policy_loader import (
    get_dangerous_keywords,
)

from backend.proxy.oauth_profile import (
    get_required_scopes,
)

from backend.schemas import ToolCallRequest


CASE_DIR = ROOT / "test" / "cases"

OUT_DIR = ROOT / "docs" / "evaluation"

JSON_OUT = (
    OUT_DIR
    / "submission_key_eval_summary.json"
)

MD_OUT = (
    OUT_DIR
    / "submission_key_eval_report.md"
)

VALID_DECISIONS = {
    "allow",
    "confirm",
    "deny",
}


def load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    files = sorted(
        CASE_DIR.glob(
            "gateway_cases*.json"
        )
    )

    if not files:
        raise RuntimeError(
            "没有找到 gateway_cases*.json"
        )

    for path in files:
        data = json.loads(
            path.read_text(
                encoding="utf-8-sig"
            )
        )

        if isinstance(data, dict):
            items = data.get(
                "cases",
                [],
            )
        else:
            items = data

        if not isinstance(items, list):
            raise ValueError(
                f"{path.name} 顶层不是用例数组"
            )

        for item in items:
            if not isinstance(item, dict):
                raise ValueError(
                    f"{path.name} 中存在无效用例"
                )

            expected = str(
                item.get(
                    "expected_decision",
                    "",
                )
            ).strip().lower()

            if expected not in VALID_DECISIONS:
                raise ValueError(
                    f"{path.name} / "
                    f"{item.get('id')} "
                    "缺少唯一 expected_decision"
                )

            case = copy.deepcopy(item)

            case["_source_file"] = (
                path.name
            )

            cases.append(case)

    return cases


def unpack_result(
    result: Any,
) -> dict[str, Any]:

    if isinstance(result, dict):
        decision = result.get(
            "decision",
            "error",
        )

        risk_score = result.get(
            "risk_score",
            0,
        )

        reason = result.get(
            "reason",
            "",
        )

    else:
        decision = getattr(
            result,
            "decision",
            "error",
        )

        risk_score = getattr(
            result,
            "risk_score",
            0,
        )

        reason = getattr(
            result,
            "reason",
            "",
        )

    if isinstance(reason, list):
        reason = " | ".join(
            str(item)
            for item in reason
        )

    return {
        "decision": str(
            decision
        ).strip().lower(),
        "risk_score": risk_score,
        "reason": str(reason or ""),
    }


# ============================================================
# 1. 无任何防护
# ============================================================

def no_guard(
    case: dict[str, Any],
) -> dict[str, Any]:

    return {
        "decision": "allow",
        "risk_score": 0,
        "reason": (
            "不执行任何安全检查，"
            "所有工具调用直接放行。"
        ),
    }


# ============================================================
# 2. 仅 OAuth Scope
# ============================================================

def oauth_only(
    case: dict[str, Any],
) -> dict[str, Any]:

    request = case["request"]

    tool = str(
        request.get(
            "tool",
            "",
        )
    )

    params = request.get(
        "params",
        {},
    )

    required_scopes = (
        get_required_scopes(
            tool,
            params,
        )
    )

    # 假设调用方已经持有此次调用
    # 所需的全部粗粒度 Scope。
    #
    # 这样可以单独观察：
    # OAuth 能证明工具权限，
    # 但不能分析参数内容和任务意图。
    return {
        "decision": "allow",
        "risk_score": 0,
        "reason": (
            "OAuth Scope 已满足："
            + ", ".join(
                required_scopes
            )
        ),
    }


# ============================================================
# 3. 仅关键词检测
# ============================================================

KEYWORD_GROUPS = (
    "path",
    "sensitive_path",
    "command",
    "prompt_injection",
    "sensitive_content",
    "sql",
)


def build_keyword_list() -> list[str]:
    keywords: set[str] = set()

    for group in KEYWORD_GROUPS:
        group_keywords = (
            get_dangerous_keywords(
                group
            )
        )

        for item in group_keywords:
            word = str(
                item
            ).strip().lower()

            if word:
                keywords.add(word)

    return sorted(keywords)


KEYWORDS = build_keyword_list()


def keyword_only(
    case: dict[str, Any],
) -> dict[str, Any]:

    request = case["request"]

    blob = json.dumps(
        {
            "tool": request.get(
                "tool"
            ),
            "params": request.get(
                "params",
                {},
            ),
            "original_input": (
                request.get(
                    "original_input"
                )
            ),
        },
        ensure_ascii=False,
        sort_keys=True,
    ).lower()

    hits = [
        keyword
        for keyword in KEYWORDS
        if keyword in blob
    ]

    if hits:
        return {
            "decision": "deny",
            "risk_score": 80,
            "reason": (
                "关键词命中："
                + ", ".join(
                    hits[:10]
                )
            ),
        }

    return {
        "decision": "allow",
        "risk_score": 0,
        "reason": (
            "未命中危险关键词，"
            "直接放行。"
        ),
    }


# ============================================================
# 4. AgentGuard 消融配置
# ============================================================

def disabled_semantic(
    **kwargs: Any,
) -> dict[str, Any]:

    return {
        "enabled": False,
        "risk_score": 0,
        "labels": [],
        "reasons": [],
        "force_confirm": False,
        "hard_deny": False,
    }


def call_gateway(
    case: dict[str, Any],
    *,
    semantic_enabled: bool,
    contract_enabled: bool,
) -> dict[str, Any]:

    request_data = copy.deepcopy(
        case["request"]
    )

    if not contract_enabled:
        for key in (
            "task_contract",
            "input_labels",
            "current_step",
            "used_risk",
        ):
            request_data.pop(
                key,
                None,
            )

    request = ToolCallRequest(
        **request_data
    )

    original_semantic = (
        gateway.semantic_check_tool_call
    )

    if not semantic_enabled:
        gateway.semantic_check_tool_call = (
            disabled_semantic
        )

    try:
        result = gateway.check_tool_call(
            request
        )

    finally:
        gateway.semantic_check_tool_call = (
            original_semantic
        )

    return unpack_result(result)


def rules_only(
    case: dict[str, Any],
) -> dict[str, Any]:

    return call_gateway(
        case,
        semantic_enabled=False,
        contract_enabled=False,
    )


def agentguard_no_semantic(
    case: dict[str, Any],
) -> dict[str, Any]:

    return call_gateway(
        case,
        semantic_enabled=False,
        contract_enabled=True,
    )


def agentguard_no_contract(
    case: dict[str, Any],
) -> dict[str, Any]:

    return call_gateway(
        case,
        semantic_enabled=True,
        contract_enabled=False,
    )


def agentguard_full(
    case: dict[str, Any],
) -> dict[str, Any]:

    return call_gateway(
        case,
        semantic_enabled=True,
        contract_enabled=True,
    )


STRATEGIES: list[
    tuple[
        str,
        str,
        Callable[
            [dict[str, Any]],
            dict[str, Any],
        ],
    ]
] = [
    (
        "NoGuard",
        "无任何防护",
        no_guard,
    ),
    (
        "OAuth-only",
        "只验证粗粒度 Scope",
        oauth_only,
    ),
    (
        "Keyword-only",
        "只扫描危险关键词",
        keyword_only,
    ),
    (
        "Rules-only",
        "关闭语义检测与任务合约",
        rules_only,
    ),
    (
        "AgentGuard-no-semantic",
        "保留任务合约，关闭语义检测",
        agentguard_no_semantic,
    ),
    (
        "AgentGuard-no-contract",
        "保留语义检测，移除任务合约",
        agentguard_no_contract,
    ),
    (
        "AgentGuard-full",
        "完整授权决策链",
        agentguard_full,
    ),
]


def rate(
    numerator: int,
    denominator: int,
) -> float:

    if denominator == 0:
        return 0.0

    return round(
        numerator / denominator,
        6,
    )


def evaluate_strategy(
    cases: list[dict[str, Any]],
    strategy_name: str,
    description: str,
    strategy: Callable[
        [dict[str, Any]],
        dict[str, Any],
    ],
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:

    rows: list[dict[str, Any]] = []

    for case in cases:
        started = time.perf_counter()

        error = ""

        try:
            result = strategy(case)

        except Exception as exc:
            result = {
                "decision": "error",
                "risk_score": 0,
                "reason": "",
            }

            error = (
                f"{type(exc).__name__}: "
                f"{exc}"
            )

        expected = str(
            case["expected_decision"]
        ).lower()

        actual = str(
            result.get(
                "decision",
                "error",
            )
        ).lower()

        latency_ms = (
            time.perf_counter()
            - started
        ) * 1000

        rows.append(
            {
                "case_id": case.get(
                    "id"
                ),
                "source_file": case.get(
                    "_source_file"
                ),
                "category": case.get(
                    "category"
                ),
                "tool": (
                    case["request"].get(
                        "tool"
                    )
                ),
                "strategy": strategy_name,
                "expected": expected,
                "actual": actual,
                "correct": (
                    actual == expected
                ),
                "risk_score": (
                    result.get(
                        "risk_score",
                        0,
                    )
                ),
                "latency_ms": round(
                    latency_ms,
                    4,
                ),
                "reason": result.get(
                    "reason",
                    "",
                ),
                "error": error,
            }
        )

    allow_rows = [
        row
        for row in rows
        if row["expected"] == "allow"
    ]

    confirm_rows = [
        row
        for row in rows
        if row["expected"] == "confirm"
    ]

    deny_rows = [
        row
        for row in rows
        if row["expected"] == "deny"
    ]

    correct = sum(
        bool(row["correct"])
        for row in rows
    )

    allow_correct = sum(
        row["actual"] == "allow"
        for row in allow_rows
    )

    confirm_correct = sum(
        row["actual"] == "confirm"
        for row in confirm_rows
    )

    deny_correct = sum(
        row["actual"] == "deny"
        for row in deny_rows
    )

    unsafe_allow = sum(
        row["actual"] == "allow"
        for row in deny_rows
    )

    return (
        {
            "name": strategy_name,
            "description": description,
            "total": len(rows),
            "correct": correct,
            "exact_accuracy": rate(
                correct,
                len(rows),
            ),

            "expected_allow": len(
                allow_rows
            ),
            "allow_correct": (
                allow_correct
            ),
            "safe_auto_allow_rate": (
                rate(
                    allow_correct,
                    len(allow_rows),
                )
            ),
            "false_confirm": sum(
                row["actual"] == "confirm"
                for row in allow_rows
            ),
            "false_deny": sum(
                row["actual"] == "deny"
                for row in allow_rows
            ),

            "expected_confirm": len(
                confirm_rows
            ),
            "confirm_correct": (
                confirm_correct
            ),
            "approval_accuracy": rate(
                confirm_correct,
                len(confirm_rows),
            ),
            "approval_bypass": sum(
                row["actual"] == "allow"
                for row in confirm_rows
            ),
            "approval_overblock": sum(
                row["actual"] == "deny"
                for row in confirm_rows
            ),

            "expected_deny": len(
                deny_rows
            ),
            "deny_correct": deny_correct,
            "attack_deny_rate": rate(
                deny_correct,
                len(deny_rows),
            ),
            "unsafe_allow": unsafe_allow,
            "unsafe_allow_rate": rate(
                unsafe_allow,
                len(deny_rows),
            ),
            "attack_underblocked": sum(
                row["actual"] == "confirm"
                for row in deny_rows
            ),

            "decision_distribution": dict(
                sorted(
                    Counter(
                        row["actual"]
                        for row in rows
                    ).items()
                )
            ),

            "avg_latency_ms": round(
                sum(
                    row["latency_ms"]
                    for row in rows
                )
                / len(rows),
                4,
            ),

            "failed_case_ids": [
                str(row["case_id"])
                for row in rows
                if not row["correct"]
            ],
        },
        rows,
    )


def percentage(
    value: float,
) -> str:

    return f"{value * 100:.2f}%"


def build_markdown(
    payload: dict[str, Any],
) -> str:

    summary = payload["summary"]

    strategies = summary[
        "strategies"
    ]

    lines = [
        "# AgentGuard 授权决策消融实验",
        "",
        f"- 生成时间："
        f"{summary['generated_at']}",
        f"- 严格测试用例："
        f"{summary['total_cases']} 个",
        "- 每个用例只有一个正确决策："
        "`allow`、`confirm` 或 `deny`。",
        "",
        "## 一、实验配置",
        "",
        "| 方法 | 配置 |",
        "|---|---|",
    ]

    for item in strategies:
        lines.append(
            f"| {item['name']} "
            f"| {item['description']} |"
        )

    lines.extend(
        [
            "",
            "## 二、核心结果",
            "",
            "| 方法 | 精确准确率 "
            "| 攻击直接拒绝率 "
            "| 攻击误放行率 "
            "| 审批命中率 "
            "| 正常自动放行率 "
            "| 平均延迟(ms) |",

            "|---|---:|---:|---:|"
            "---:|---:|---:|",
        ]
    )

    for item in strategies:
        lines.append(
            f"| {item['name']} "
            f"| {percentage(item['exact_accuracy'])} "
            f"| {percentage(item['attack_deny_rate'])} "
            f"| {percentage(item['unsafe_allow_rate'])} "
            f"| {percentage(item['approval_accuracy'])} "
            f"| {percentage(item['safe_auto_allow_rate'])} "
            f"| {item['avg_latency_ms']:.4f} |"
        )

    full_result = next(
        item
        for item in strategies
        if item["name"]
        == "AgentGuard-full"
    )

    lines.extend(
        [
            "",
            "## 三、完整系统结果",
            "",
            f"- 精确通过："
            f"{full_result['correct']}/"
            f"{full_result['total']}",

            f"- 攻击直接拒绝："
            f"{full_result['deny_correct']}/"
            f"{full_result['expected_deny']}",

            f"- 攻击误放行："
            f"{full_result['unsafe_allow']}",

            f"- 审批操作正确进入确认："
            f"{full_result['confirm_correct']}/"
            f"{full_result['expected_confirm']}",

            f"- 正常操作正确自动放行："
            f"{full_result['allow_correct']}/"
            f"{full_result['expected_allow']}",

            "",
            "## 四、结论",
            "",
            "OAuth 只能证明调用方持有某类工具的"
            "粗粒度权限，不能理解参数内容、"
            "提示注入、敏感数据外发和任务偏离。",

            "",
            "关键词过滤能够识别显式特征，"
            "但无法稳定区分自动放行、"
            "人工确认和直接拒绝。",

            "",
            "通过关闭语义检测、移除任务合约，"
            "以及同时关闭二者，可以量化不同"
            "防护层对最终结果的独立贡献。",

            "",
            "完整 AgentGuard 使用唯一决策标准，"
            "避免多个可接受答案人为抬高准确率。",
        ]
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    cases = load_cases()

    summaries: list[
        dict[str, Any]
    ] = []

    all_rows: list[
        dict[str, Any]
    ] = []

    started = time.perf_counter()

    for (
        strategy_name,
        description,
        strategy,
    ) in STRATEGIES:

        strategy_summary, rows = (
            evaluate_strategy(
                cases,
                strategy_name,
                description,
                strategy,
            )
        )

        summaries.append(
            strategy_summary
        )

        all_rows.extend(rows)

    payload = {
        "summary": {
            "schema": (
                "agentguard_"
                "ablation_eval.v2"
            ),

            "generated_at": (
                datetime.now()
                .astimezone()
                .isoformat(
                    timespec="seconds"
                )
            ),

            "total_cases": len(cases),

            "strategy_count": len(
                STRATEGIES
            ),

            "elapsed_ms": round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                3,
            ),

            "strategies": summaries,
        },

        "rows": all_rows,
    }

    OUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    JSON_OUT.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    MD_OUT.write_text(
        build_markdown(payload),
        encoding="utf-8",
    )

    print()
    print(
        "============================================================"
    )

    print(
        "方法                         "
        "准确率    攻击拒绝率  "
        "误放行率  审批命中率"
    )

    print(
        "------------------------------------------------------------"
    )

    for item in summaries:
        print(
            f"{item['name']:<28}"
            f"{percentage(item['exact_accuracy']):>9}"
            f"{percentage(item['attack_deny_rate']):>12}"
            f"{percentage(item['unsafe_allow_rate']):>10}"
            f"{percentage(item['approval_accuracy']):>12}"
        )

    print(
        "============================================================"
    )

    print(
        f"JSON：{JSON_OUT}"
    )

    print(
        f"报告：{MD_OUT}"
    )

    full_result = next(
        item
        for item in summaries
        if item["name"]
        == "AgentGuard-full"
    )

    if (
        full_result["correct"]
        != full_result["total"]
    ):
        print()
        print(
            "完整 AgentGuard 剩余失败："
        )

        for case_id in full_result[
            "failed_case_ids"
        ]:
            print(
                f"- {case_id}"
            )

        return 1

    print()
    print(
        "消融实验完成：完整 AgentGuard "
        "严格通过全部 131 个用例。"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
