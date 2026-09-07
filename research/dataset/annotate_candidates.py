from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set

from research.dataset.schema import AuthorizationSample


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_DIR = (
    PROJECT_ROOT
    / "research"
    / "dataset"
)


EVENT_TYPES = [
    "unauthorized",
    "data_exfiltration",
    "credential_access",
    "prompt_injection",
    "destructive_action",
    "privilege_escalation",
    "network_abuse",
    "other",
]

SEVERITIES = [
    "low",
    "medium",
    "high",
    "critical",
]

HARD_TYPES = [
    "unknown_tool",
    "missing_required_parameter",
    "path_traversal",
    "encoded_path_bypass",
    "absolute_path_escape",
    "invalid_plan_state",
    "contract_violation",
    "other_hard_constraint",
]


def load_json(path: Path):
    with open(
        path,
        "r",
        encoding="utf-8-sig",
    ) as f:
        return json.load(f)


def save_json(
    path: Path,
    data: Dict[str, Any],
):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2,
        )


def get_existing_samples():
    samples = []

    for path in DATASET_DIR.glob(
        "sample_*.json"
    ):
        try:
            raw = load_json(path)

            samples.append(raw)

        except Exception:
            continue

    return samples


def get_next_sample_number() -> int:
    numbers = []

    for path in DATASET_DIR.glob(
        "sample_*.json"
    ):
        match = re.search(
            r"sample_(\d+)",
            path.stem,
        )

        if match:
            numbers.append(
                int(match.group(1))
            )

    if not numbers:
        return 1

    return max(numbers) + 1


def get_finished_candidates() -> Set[str]:
    finished: Set[str] = set()

    for sample in get_existing_samples():
        candidate_id = sample.get(
            "source_candidate_id"
        )

        if candidate_id:
            finished.add(
                str(candidate_id)
            )

    return finished


def choose(
    title: str,
    options: List[str],
) -> str:

    print()
    print(title)

    for index, value in enumerate(
        options,
        start=1,
    ):
        print(
            f"  {index}. {value}"
        )

    while True:
        answer = input(
            "请输入编号: "
        ).strip()

        try:
            index = int(answer)

            if (
                1
                <= index
                <= len(options)
            ):
                return options[
                    index - 1
                ]

        except ValueError:
            pass

        print(
            "输入无效，请重新输入编号。"
        )


def yes_no(
    question: str,
) -> bool:

    while True:
        answer = input(
            question
            + " [y/n]: "
        ).strip().lower()

        if answer in {
            "y",
            "yes",
            "1",
        }:
            return True

        if answer in {
            "n",
            "no",
            "0",
        }:
            return False

        print(
            "请输入 y 或 n。"
        )


def print_candidate(
    item: Dict[str, Any],
):
    print()
    print("=" * 70)
    print(
        "候选编号:",
        item.get(
            "candidate_id"
        ),
    )

    print(
        "场景族:",
        item.get(
            "scenario_family"
        ),
    )

    print(
        "任务:",
        item.get(
            "original_task"
        ),
    )

    print(
        "工具:",
        item.get(
            "tool"
        ),
    )

    print(
        "参数:"
    )

    print(
        json.dumps(
            item.get(
                "params",
                {},
            ),
            ensure_ascii=False,
            indent=2,
        )
    )

    if item.get(
        "input_labels"
    ):
        print(
            "输入标签:",
            item.get(
                "input_labels"
            ),
        )

    if item.get(
        "history"
    ):
        print(
            "历史上下文:"
        )

        print(
            json.dumps(
                item.get(
                    "history"
                ),
                ensure_ascii=False,
                indent=2,
            )
        )

    print("=" * 70)


def annotate(
    item: Dict[str, Any],
    sample_number: int,
) -> AuthorizationSample:

    hard = yes_no(
        "是否属于确定性的硬约束违规？"
    )

    hard_type = None

    if hard:
        hard_type = choose(
            "选择硬约束类型：",
            HARD_TYPES,
        )

        is_unsafe = True

        event_type = choose(
            "选择主要安全事件类型：",
            EVENT_TYPES,
        )

        severity = choose(
            "选择严重程度：",
            SEVERITIES,
        )

        # 硬约束不应该交给人工确认兜底
        human_reviewable = False

    else:
        is_unsafe = yes_no(
            "这次工具调用本身是否不安全？"
        )

        if is_unsafe:
            event_type = choose(
                "选择主要安全事件类型：",
                EVENT_TYPES,
            )

            severity = choose(
                "选择严重程度：",
                SEVERITIES,
            )

            human_reviewable = yes_no(
                "如果给用户展示完整上下文，人工审核是否有能力正确判断？"
            )

        else:
            event_type = "safe"
            severity = "none"

            human_reviewable = yes_no(
                "如果展示该请求，普通授权用户是否能够理解并正确判断？"
            )

    print()

    reason = input(
        "请用一句话写清楚标注理由: "
    ).strip()

    while not reason:
        print(
            "标注理由不能为空。"
        )

        reason = input(
            "请重新输入标注理由: "
        ).strip()

    return AuthorizationSample(
        sample_id=(
            f"sample_{sample_number:04d}"
        ),

        source=item.get(
            "source"
        ),

        scenario_family=item.get(
            "scenario_family"
        ),

        source_candidate_id=item.get(
            "candidate_id"
        ),

        original_case_id=item.get(
            "original_case_id"
        ),

        description=item.get(
            "description"
        ),

        user=item.get(
            "user",
            "user",
        ),

        original_task=item.get(
            "original_task",
            "",
        ),

        tool=item.get(
            "tool",
            "",
        ),

        params=item.get(
            "params",
            {},
        ),

        oauth_scopes=item.get(
            "oauth_scopes",
            [],
        ),

        task_contract=item.get(
            "task_contract"
        ),

        input_labels=item.get(
            "input_labels",
            [],
        ),

        current_step=item.get(
            "current_step",
            1,
        ),

        history=item.get(
            "history",
            [],
        ),

        hard_constraint_violation=hard,

        hard_constraint_type=hard_type,

        is_unsafe=is_unsafe,

        security_event_type=event_type,

        severity=severity,

        human_reviewable=human_reviewable,

        annotation_reason=reason,

        annotator="team_manual",

        annotation_version="v1",
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--queue",
        choices=[
            "generated",
            "legacy",
        ],
        default="generated",
    )

    args = parser.parse_args()

    if args.queue == "generated":
        queue_file = (
            DATASET_DIR
            / "generated_annotation_queue.json"
        )

    else:
        queue_file = (
            DATASET_DIR
            / "annotation_queue.json"
        )

    if not queue_file.exists():
        raise FileNotFoundError(
            f"找不到候选文件: {queue_file}"
        )

    queue = load_json(
        queue_file
    )

    finished = (
        get_finished_candidates()
    )

    remaining = [
        item
        for item in queue
        if str(
            item.get(
                "candidate_id"
            )
        )
        not in finished
    ]

    print()
    print(
        f"候选总数: {len(queue)}"
    )

    print(
        f"已经标注: "
        f"{len(queue) - len(remaining)}"
    )

    print(
        f"剩余: {len(remaining)}"
    )

    if not remaining:
        print(
            "这个队列已经全部标注完成。"
        )
        return

    sample_number = (
        get_next_sample_number()
    )

    for item in remaining:

        print_candidate(item)

        action = input(
            "开始标注请输入 Enter；跳过输入 s；退出输入 q: "
        ).strip().lower()

        if action == "q":
            print(
                "已退出，之前保存的标注不会丢失。"
            )
            break

        if action == "s":
            continue

        sample = annotate(
            item,
            sample_number,
        )

        output_path = (
            DATASET_DIR
            / (
                f"sample_"
                f"{sample_number:04d}"
                f".json"
            )
        )

        if hasattr(
            sample,
            "model_dump",
        ):
            data = sample.model_dump()

        else:
            data = sample.dict()

        save_json(
            output_path,
            data,
        )

        print()
        print(
            f"[SAVED] {output_path.name}"
        )

        sample_number += 1


if __name__ == "__main__":
    main()
