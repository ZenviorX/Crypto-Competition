from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SOURCE_FILE = (
    PROJECT_ROOT
    / "test"
    / "cases"
    / "gateway_cases_v5_submission.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "research"
    / "dataset"
    / "annotation_queue.json"
)


def main():
    with open(
        SOURCE_FILE,
        "r",
        encoding="utf-8-sig",
    ) as f:
        old_cases = json.load(f)

    queue = []

    for index, case in enumerate(
        old_cases,
        start=1,
    ):
        request = case.get(
            "request",
            {},
        )

        # -----------------------------------------------------
        # 注意：
        # 故意不读取 expected_decision。
        #
        # 旧系统认为 allow / confirm / deny，
        # 不能作为新数据集的 Ground Truth。
        # -----------------------------------------------------

        original_task = str(
            request.get(
                "original_input",
                "",
            )
            or case.get(
                "description",
                "",
            )
        )

        candidate = {
            "candidate_id":
                f"candidate_{index:04d}",

            "source":
                "gateway_cases_v5_submission",

            "original_case_id":
                case.get("id"),

            "old_category":
                case.get("category"),

            "description":
                case.get("description"),

            "user":
                request.get(
                    "user",
                    "user",
                ),

            "original_task":
                original_task,

            "tool":
                request.get(
                    "tool",
                    "",
                ),

            "params":
                request.get(
                    "params",
                    {},
                ),

            "oauth_scopes": [],

            "input_labels": [],

            "current_step": 1,

            "history": [],

            # -------------------------------------------------
            # 以下全部留空，等待新标准重新标注
            # -------------------------------------------------

            "hard_constraint_violation":
                None,

            "hard_constraint_type":
                None,

            "is_unsafe":
                None,

            "security_event_type":
                None,

            "severity":
                None,

            "human_reviewable":
                None,

            "annotation_reason":
                None,
        }

        queue.append(candidate)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            queue,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(
        "Annotation queue created."
    )

    print(
        f"Source cases: {len(old_cases)}"
    )

    print(
        f"Candidates: {len(queue)}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print()
    print(
        "IMPORTANT: old expected_decision "
        "was NOT copied."
    )


if __name__ == "__main__":
    main()
