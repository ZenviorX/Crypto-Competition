from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List

from backend.schemas import ToolCallRequest
from backend.decision.feature_extractor import extract_risk_features
from research.dataset.schema import AuthorizationSample


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_DIR = (
    PROJECT_ROOT
    / "research"
    / "dataset"
)

OUTPUT_DIR = (
    DATASET_DIR
    / "derived"
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "training_features.csv"
)


def load_samples() -> List[AuthorizationSample]:
    """
    加载所有 sample_*.json。
    """

    samples: List[AuthorizationSample] = []

    for path in sorted(
        DATASET_DIR.glob(
            "sample_*.json"
        )
    ):
        with open(
            path,
            "r",
            encoding="utf-8-sig",
        ) as f:
            raw = json.load(f)

        samples.append(
            AuthorizationSample(
                **raw
            )
        )

    return samples


def sample_to_request(
    sample: AuthorizationSample,
) -> ToolCallRequest:
    """
    将人工标注样本转换成现有特征提取器所需的请求格式。
    """

    return ToolCallRequest(
        user=sample.user,
        tool=sample.tool,
        params=sample.params,
        original_input=sample.original_task,
        task_contract=sample.task_contract,
        input_labels=sample.input_labels,
        current_step=sample.current_step,
        history=sample.history,
    )


def build_training_rows():
    samples = load_samples()

    rows: List[Dict[str, object]] = []

    excluded_hard = 0

    for sample in samples:

        # -----------------------------------------------------
        # 硬约束违规样本不能进入概率模型训练
        # -----------------------------------------------------
        if sample.hard_constraint_violation:
            excluded_hard += 1

            print(
                f"[EXCLUDED HARD] "
                f"{sample.sample_id} "
                f"{sample.hard_constraint_type}"
            )

            continue

        request = sample_to_request(
            sample
        )

        features = extract_risk_features(
            request
        )

        row: Dict[str, object] = {
            "sample_id": sample.sample_id,
            "y_unsafe": (
                1
                if sample.is_unsafe
                else 0
            ),
            "security_event_type":
                sample.security_event_type,
            "severity":
                sample.severity,
            "human_reviewable": (
                1
                if sample.human_reviewable
                else 0
            ),
        }

        row.update(features)

        rows.append(row)

    return (
        rows,
        excluded_hard,
        len(samples),
    )


def write_csv(
    rows: List[
        Dict[str, object]
    ],
) -> None:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not rows:
        raise RuntimeError(
            "没有可用于概率模型训练的样本。"
        )

    # 所有特征提取器输出的字段顺序保持一致
    fieldnames = list(
        rows[0].keys()
    )

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def main():
    (
        rows,
        excluded_hard,
        total_samples,
    ) = build_training_rows()

    write_csv(rows)

    print()
    print(
        "Dataset conversion finished."
    )

    print(
        f"Total samples: "
        f"{total_samples}"
    )

    print(
        f"Training samples: "
        f"{len(rows)}"
    )

    print(
        f"Hard-constraint samples excluded: "
        f"{excluded_hard}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print()

    for row in rows:
        print(
            row["sample_id"],
            "y_unsafe=",
            row["y_unsafe"],
        )


if __name__ == "__main__":
    main()

