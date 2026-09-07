from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

QUEUE_FILE = (
    PROJECT_ROOT
    / "research"
    / "dataset"
    / "generated_annotation_queue.json"
)


def main():
    with open(
        QUEUE_FILE,
        "r",
        encoding="utf-8-sig",
    ) as f:
        cases = json.load(f)

    family_labels = defaultdict(list)
    history_cases = []
    direct_label_cases = []

    suspicious_labels = {
        "sensitive",
        "secret",
        "prompt_injection",
        "tainted",
    }

    for case in cases:
        family = str(
            case.get(
                "scenario_family",
                "unknown",
            )
        )

        labels = tuple(
            sorted(
                str(x)
                for x in case.get(
                    "input_labels",
                    [],
                )
            )
        )

        family_labels[
            family
        ].append(labels)

        if case.get("history"):
            history_cases.append(
                case.get(
                    "candidate_id"
                )
            )

        if (
            set(labels)
            & suspicious_labels
        ):
            direct_label_cases.append(
                (
                    case.get(
                        "candidate_id"
                    ),
                    family,
                    labels,
                )
            )

    print()
    print(
        "===== Dataset Leakage Audit ====="
    )

    print(
        f"Total candidates: {len(cases)}"
    )

    print()
    print(
        "[1] Constant input_labels by scenario family"
    )

    constant_families = 0

    for family, labels_list in (
        family_labels.items()
    ):
        unique = set(
            labels_list
        )

        if (
            len(unique) == 1
            and next(
                iter(unique)
            )
        ):
            constant_families += 1

            print(
                f"  WARNING  {family}: "
                f"{next(iter(unique))}"
            )

    print()
    print(
        "[2] Candidates containing "
        "highly informative runtime labels"
    )

    print(
        f"  Count: {len(direct_label_cases)}"
    )

    for (
        candidate_id,
        family,
        labels,
    ) in direct_label_cases[:20]:

        print(
            f"  {candidate_id} "
            f"{family} "
            f"{labels}"
        )

    print()
    print(
        "[3] Candidates whose important context "
        "is stored in history"
    )

    print(
        f"  Count: {len(history_cases)}"
    )

    for candidate_id in history_cases:
        print(
            f"  {candidate_id}"
        )

    print()
    print(
        "===== Interpretation ====="
    )

    if constant_families:
        print(
            "WARNING: 某些场景族与 input_labels "
            "存在固定对应关系。"
        )

        print(
            "模型可能不用理解工具调用，"
            "只看标签就能猜答案。"
        )

    if history_cases:
        print(
            "WARNING: 部分攻击信息位于 history 中，"
            "而当前 feature_extractor 尚未显式提取 "
            "history 行为特征。"
        )

    print()
    print(
        "建议：先修复这些问题，再继续大量标注和训练。"
    )


if __name__ == "__main__":
    main()
