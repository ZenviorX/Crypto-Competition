from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

QUEUE_FILE = (
    PROJECT_ROOT
    / "research"
    / "dataset"
    / "generated_annotation_queue.json"
)


SAFE_FAMILIES = {
    "safe_public_read",
    "safe_workspace_write",
    "safe_internal_email",
    "external_email_normal_content",
    "prompt_injection_resisted",
    "safe_shell",
    "safe_database_query",
    "authorized_sensitive_read",
}


UNSAFE_FAMILIES = {
    "sensitive_external_email",
    "credential_read",
    "prompt_injection_induced_action",
    "destructive_shell",
    "dangerous_database",
    "unrequested_sensitive_read",
}


HARD_FAMILIES = {
    "hard_path_escape",
}


def expected_class(
    family: str,
) -> str:
    """
    注意：
    这里只用于检查生成器设计是否均衡，
    不是正式 Ground Truth，
    也不会进入模型训练。
    """

    if family in SAFE_FAMILIES:
        return "safe"

    if family in UNSAFE_FAMILIES:
        return "unsafe"

    if family in HARD_FAMILIES:
        return "hard"

    return "unknown"


def main():

    with open(
        QUEUE_FILE,
        "r",
        encoding="utf-8-sig",
    ) as f:
        cases = json.load(f)

    print()
    print(
        "===== Dataset Quality Audit ====="
    )

    print(
        f"Total candidates: {len(cases)}"
    )

    # =========================================================
    # 1. 场景族数量
    # =========================================================
    family_counter = Counter(
        str(
            case.get(
                "scenario_family",
                "unknown",
            )
        )
        for case in cases
    )

    print()
    print(
        "[1] Scenario family distribution"
    )

    for family, count in sorted(
        family_counter.items()
    ):
        print(
            f"  {family}: {count}"
        )

    # =========================================================
    # 2. 预期 safe / unsafe / hard 分布
    # =========================================================
    class_counter = Counter()

    for case in cases:
        family = str(
            case.get(
                "scenario_family",
                "unknown",
            )
        )

        class_counter[
            expected_class(family)
        ] += 1

    print()
    print(
        "[2] Design-level class balance"
    )

    for name in [
        "safe",
        "unsafe",
        "hard",
        "unknown",
    ]:
        print(
            f"  {name}: "
            f"{class_counter.get(name, 0)}"
        )

    # =========================================================
    # 3. 每种工具是否同时存在 safe / unsafe
    # =========================================================
    tool_classes = defaultdict(
        Counter
    )

    for case in cases:
        tool = str(
            case.get(
                "tool",
                "unknown",
            )
        )

        family = str(
            case.get(
                "scenario_family",
                "unknown",
            )
        )

        cls = expected_class(
            family
        )

        tool_classes[
            tool
        ][cls] += 1

    print()
    print(
        "[3] Safe / unsafe coverage by tool"
    )

    weak_tools = []

    for tool, counts in sorted(
        tool_classes.items()
    ):

        safe_count = counts.get(
            "safe",
            0,
        )

        unsafe_count = counts.get(
            "unsafe",
            0,
        )

        hard_count = counts.get(
            "hard",
            0,
        )

        print(
            f"  {tool}: "
            f"safe={safe_count}, "
            f"unsafe={unsafe_count}, "
            f"hard={hard_count}"
        )

        if (
            safe_count == 0
            or unsafe_count == 0
        ):
            weak_tools.append(
                tool
            )

    # =========================================================
    # 4. 检查关键对照样本
    # =========================================================
    required_contrasts = [
        (
            "external_email_normal_content",
            "sensitive_external_email",
            "外部邮件：普通内容 vs 敏感内容",
        ),
        (
            "safe_shell",
            "destructive_shell",
            "Shell：正常命令 vs 破坏命令",
        ),
        (
            "safe_database_query",
            "dangerous_database",
            "SQL：查询 vs 危险修改",
        ),
        (
            "prompt_injection_resisted",
            "prompt_injection_induced_action",
            "提示注入：抵抗成功 vs 被诱导",
        ),
        (
            "authorized_sensitive_read",
            "unrequested_sensitive_read",
            "敏感读取：明确授权 vs 偏离任务",
        ),
    ]

    print()
    print(
        "[4] Contrastive pair coverage"
    )

    missing_contrasts = []

    for (
        safe_family,
        unsafe_family,
        description,
    ) in required_contrasts:

        safe_count = (
            family_counter.get(
                safe_family,
                0,
            )
        )

        unsafe_count = (
            family_counter.get(
                unsafe_family,
                0,
            )
        )

        ok = (
            safe_count > 0
            and unsafe_count > 0
        )

        status = (
            "OK"
            if ok
            else "WARNING"
        )

        print(
            f"  {status} {description}: "
            f"{safe_count} vs "
            f"{unsafe_count}"
        )

        if not ok:
            missing_contrasts.append(
                description
            )

    # =========================================================
    # 5. 检查 scenario_family 是否过于整齐
    # =========================================================
    print()
    print(
        "[5] Template-size check"
    )

    for family, count in sorted(
        family_counter.items()
    ):
        if count < 4:
            print(
                f"  WARNING {family}: "
                f"only {count} cases"
            )

    # =========================================================
    # 总结
    # =========================================================
    print()
    print(
        "===== Summary ====="
    )

    if weak_tools:
        print(
            "WARNING: 以下工具没有同时覆盖 "
            "safe / unsafe："
        )

        for tool in weak_tools:
            print(
                f"  - {tool}"
            )
    else:
        print(
            "OK: 所有工具都有安全和危险对照样本。"
        )

    if missing_contrasts:
        print(
            "WARNING: 部分关键对照组缺失。"
        )
    else:
        print(
            "OK: 关键对照组均已覆盖。"
        )

    print()
    print(
        "说明：这里的 safe/unsafe 只是生成器设计检查，"
        "不能替代后续正式人工 Ground Truth 标注。"
    )


if __name__ == "__main__":
    main()
