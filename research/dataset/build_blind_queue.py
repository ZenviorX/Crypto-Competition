from __future__ import annotations

import json
import random
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_DIR = (
    PROJECT_ROOT
    / "research"
    / "dataset"
)

SOURCE_FILE = (
    DATASET_DIR
    / "generated_annotation_queue.json"
)

OUTPUT_FILE = (
    DATASET_DIR
    / "blind_annotation_queue.json"
)

RANDOM_SEED = 20260907


def main():

    with open(
        SOURCE_FILE,
        "r",
        encoding="utf-8-sig",
    ) as f:
        original_cases = json.load(f)

    cases = []

    for item in original_cases:

        # -----------------------------------------------------
        # 保留真正的 candidate_id 和 scenario_family，
        # 但放进内部字段，不在标注界面展示。
        #
        # 后面实验仍然可以按 scenario_family 分组，
        # 但标注者看不到它。
        # -----------------------------------------------------
        blind_item = dict(item)

        blind_item[
            "_original_candidate_id"
        ] = item.get(
            "candidate_id"
        )

        blind_item[
            "_scenario_family"
        ] = item.get(
            "scenario_family"
        )

        blind_item.pop(
            "scenario_family",
            None,
        )

        cases.append(
            blind_item
        )

    # ---------------------------------------------------------
    # 固定随机种子：
    # 每次生成顺序一致，方便复现实验。
    # ---------------------------------------------------------
    rng = random.Random(
        RANDOM_SEED
    )

    rng.shuffle(cases)

    # ---------------------------------------------------------
    # 给标注者显示完全新的 blind_id
    # ---------------------------------------------------------
    for index, item in enumerate(
        cases,
        start=1,
    ):
        item[
            "candidate_id"
        ] = (
            f"blind_{index:04d}"
        )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            cases,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(
        "Blind annotation queue created."
    )

    print(
        f"Total candidates: {len(cases)}"
    )

    print(
        f"Random seed: {RANDOM_SEED}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print()
    print(
        "scenario_family is hidden from annotators."
    )

    print(
        "candidate order has been shuffled."
    )


if __name__ == "__main__":
    main()
