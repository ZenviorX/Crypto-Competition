from __future__ import annotations

import json
import random
from collections import defaultdict
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
    / "gold_annotation_queue.json"
)

RANDOM_SEED = 20260907
PER_FAMILY = 2


def main():

    with open(
        SOURCE_FILE,
        "r",
        encoding="utf-8-sig",
    ) as f:
        cases = json.load(f)

    grouped = defaultdict(list)

    for item in cases:
        family = str(
            item.get(
                "scenario_family",
                "unknown",
            )
        )

        grouped[family].append(item)

    rng = random.Random(
        RANDOM_SEED
    )

    selected = []

    for family in sorted(grouped):

        family_cases = list(
            grouped[family]
        )

        if len(family_cases) < PER_FAMILY:
            raise RuntimeError(
                f"{family} 样本不足 "
                f"{PER_FAMILY} 条"
            )

        picked = rng.sample(
            family_cases,
            PER_FAMILY,
        )

        for item in picked:

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

            # 标注者不能看到场景族
            blind_item.pop(
                "scenario_family",
                None,
            )

            selected.append(
                blind_item
            )

    # 再整体打乱一次
    rng.shuffle(selected)

    for index, item in enumerate(
        selected,
        start=1,
    ):
        item[
            "candidate_id"
        ] = (
            f"gold_{index:04d}"
        )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            selected,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(
        "Gold annotation set created."
    )

    print(
        f"Scenario families: "
        f"{len(grouped)}"
    )

    print(
        f"Samples per family: "
        f"{PER_FAMILY}"
    )

    print(
        f"Total Gold samples: "
        f"{len(selected)}"
    )

    print(
        f"Random seed: "
        f"{RANDOM_SEED}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
