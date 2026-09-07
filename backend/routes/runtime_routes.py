from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.capability.capability_compiler import compile_capability_contract
from backend.runtime.runtime_monitor import (
    build_runtime_security_graph,
    create_runtime_state,
    get_step_output_labels,
    run_runtime_step,
)
from backend.runtime.runtime_store import (
    get_runtime_state,
    list_runtime_states,
    save_runtime_state,
)
from backend.runtime.evidence_package import (
    build_runtime_evidence_package,
    save_runtime_evidence_package,
)
from backend.tools.tool_executor import (
    DB_PATH,
    OUTBOX_DIR,
    PRIVATE_DIR,
    PUBLIC_DIR,
    SANDBOX_DIR,
    SECRET_DIR,
    ensure_sandbox_ready,
    execute_tool,
)


router = APIRouter(
    prefix="/runtime",
    tags=["Agent Runtime Monitor"],
)


class RuntimeStartRequest(BaseModel):
    user: str = Field(default="user", description="发起任务的用户")
    original_task: str = Field(..., description="用户原始任务")
    max_steps: int = Field(default=5, description="任务最大步骤数")
    risk_budget: int = Field(default=80, description="任务风险预算")


class RuntimeStepRequest(BaseModel):
    tool: str = Field(..., description="当前调用的工具")
    params: Dict[str, Any] = Field(default_factory=dict, description="工具调用参数")

    input_labels: List[str] = Field(
        default_factory=list,
        description="手动传入的输入标签",
    )

    input_from_steps: List[int] = Field(
        default_factory=list,
        description="继承哪些历史步骤的输出标签",
    )

    output_content: Optional[str] = Field(
        default=None,
        description="工具实际输出内容，用于自动分析 taint / sensitive 标签",
    )


@router.post("/start")
def start_runtime_task(request: RuntimeStartRequest):
    """
    启动一个运行时任务。

    系统会自动：
    1. 编译 Capability Contract v2；
    2. 创建 RuntimeTaskState；
    3. 保存到内存状态表。
    """

    contract = compile_capability_contract(
        user=request.user,
        original_task=request.original_task,
        max_steps=request.max_steps,
        risk_budget=request.risk_budget,
    )

    state = create_runtime_state(contract)
    save_runtime_state(state)

    return {
        "message": "Runtime task started successfully.",
        "task_id": state.task_id,
        "contract": contract.model_dump(),
        "state": state.model_dump(),
    }


@router.post("/{task_id}/step")
def run_step(task_id: str, request: RuntimeStepRequest):
    """
    在指定任务中执行一步工具调用检查。

    如果 input_from_steps=[1]，
    系统会自动把第 1 步的 output_labels 作为本步骤的 input_labels。
    """

    state = get_runtime_state(task_id)

    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Runtime task {task_id} not found.",
        )

    merged_input_labels = list(request.input_labels)

    for step_index in request.input_from_steps:
        inherited_labels = get_step_output_labels(state, step_index)

        for label in inherited_labels:
            if label not in merged_input_labels:
                merged_input_labels.append(label)

    result = run_runtime_step(
        state=state,
        tool=request.tool,
        params=request.params,
        input_labels=merged_input_labels,
        output_content=request.output_content,
        input_from_steps=request.input_from_steps,
    )

    save_runtime_state(state)

    return {
        "message": "Runtime step checked successfully.",
        "task_id": task_id,
        "result": result.model_dump(),
        "state": state.model_dump(),
        "security_graph": build_runtime_security_graph(state),
    }



@router.get("/{task_id}/graph")
def read_runtime_security_graph(task_id: str):
    """
    读取指定 Runtime 任务的数据流安全图谱。
    """
    state = get_runtime_state(task_id)

    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Runtime task {task_id} not found.",
        )

    return {
        "message": "Runtime security graph loaded successfully.",
        "task_id": task_id,
        "security_graph": build_runtime_security_graph(state),
    }



@router.get("/{task_id}/evidence")
def read_runtime_evidence_package(task_id: str):
    """
    读取指定 Runtime 任务的证据包。
    包含：
    1. Capability Contract；
    2. 每一步工具调用记录；
    3. data_lineage_edges 数据流边；
    4. Runtime Security Graph；
    5. 高风险数据流；
    6. SHA256 完整性哈希。
    """
    state = get_runtime_state(task_id)

    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Runtime task {task_id} not found.",
        )

    return {
        "message": "Runtime evidence package built successfully.",
        "task_id": task_id,
        "evidence_package": build_runtime_evidence_package(state),
    }


@router.post("/{task_id}/evidence/export")
def export_runtime_evidence_package(task_id: str):
    """
    导出指定 Runtime 任务的证据包到 runtime_workspace/evidence。
    """
    state = get_runtime_state(task_id)

    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Runtime task {task_id} not found.",
        )

    result = save_runtime_evidence_package(state)

    return {
        "message": "Runtime evidence package exported successfully.",
        "task_id": task_id,
        "evidence_id": result["evidence_id"],
        "path": result["path"],
        "evidence_package": result["package"],
    }


@router.get("/sandbox/status")
def read_sandbox_status():
    """
    查看安全沙箱整体状态。

    1. 沙箱目录是否存在；
    2. public/private/secret/outbox 是否初始化；
    3. outbox 中是否有沙箱邮件；
    4. SQLite 演示数据库是否存在。
    """

    ensure_sandbox_ready()

    return {
        "message": "Sandbox status loaded successfully.",
        "sandbox": {
            "enabled": True,
            "root": str(SANDBOX_DIR),
            "public_dir": str(PUBLIC_DIR),
            "private_dir": str(PRIVATE_DIR),
            "secret_dir": str(SECRET_DIR),
            "outbox_dir": str(OUTBOX_DIR),
            "database": str(DB_PATH),
        },
        "exists": {
            "root": SANDBOX_DIR.exists(),
            "public_dir": PUBLIC_DIR.exists(),
            "private_dir": PRIVATE_DIR.exists(),
            "secret_dir": SECRET_DIR.exists(),
            "outbox_dir": OUTBOX_DIR.exists(),
            "database": DB_PATH.exists(),
        },
        "counts": {
            "public_files": _count_files(PUBLIC_DIR),
            "private_files": _count_files(PRIVATE_DIR),
            "secret_files": _count_files(SECRET_DIR),
            "outbox_emails": _count_files(OUTBOX_DIR),
        },
    }


@router.get("/sandbox/files")
def list_sandbox_files():
    """
    查看沙箱中的文件列表。
    """

    ensure_sandbox_ready()

    return {
        "message": "Sandbox files loaded successfully.",
        "public": _list_files(PUBLIC_DIR),
        "private": _list_files(PRIVATE_DIR),
        "secret": _list_files(SECRET_DIR),
        "outbox": _list_files(OUTBOX_DIR),
    }


@router.get("/sandbox/outbox")
def list_sandbox_outbox():
    """
    查看沙箱邮件 outbox。

    email.send 不会真实外发，而是写入 runtime_workspace/outbox。
    这个接口用于展示被沙箱记录下来的邮件。
    """

    ensure_sandbox_ready()

    emails = []

    for file_path in sorted(OUTBOX_DIR.glob("*.json")):
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))

        except json.JSONDecodeError:
            data = {
                "error": "Invalid JSON mail record.",
            }

        emails.append(
            {
                "file": str(file_path.relative_to(SANDBOX_DIR)),
                "size": file_path.stat().st_size,
                "data": data,
            }
        )

    return {
        "message": "Sandbox outbox loaded successfully.",
        "count": len(emails),
        "emails": emails,
    }


@router.get("/sandbox/database")
def read_sandbox_database():
    """
    查看沙箱数据库中的演示数据。
    只读取 notices 表，不执行用户输入 SQL。
    """

    ensure_sandbox_ready()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            """
            SELECT id, title, content, visibility
            FROM notices
            ORDER BY id
            """
        ).fetchall()

        notices = [dict(row) for row in rows]

    finally:
        conn.close()

    return {
        "message": "Sandbox database loaded successfully.",
        "database": str(DB_PATH),
        "table": "notices",
        "row_count": len(notices),
        "rows": notices,
    }


@router.get("/sandbox/demo-run")
def run_sandbox_demo():
    """
    一键生成沙箱运行痕迹。
    """

    ensure_sandbox_ready()

    now = datetime.now().isoformat(timespec="seconds")

    demo_content = (
        "AgentGuard 沙箱演示记录\n"
        f"生成时间：{now}\n"
        "说明：该文件由 /runtime/sandbox/demo-run 接口生成，"
        "用于证明工具调用已经进入真实沙箱执行。\n"
    )

    steps = []

    steps.append(
        {
            "name": "写入公开文件",
            "tool": "file.write",
            "params": {
                "path": "public/runtime_demo_note.txt",
                "content": demo_content,
            },
            "result": execute_tool(
                "file.write",
                {
                    "path": "public/runtime_demo_note.txt",
                    "content": demo_content,
                },
            ),
        }
    )

    steps.append(
        {
            "name": "读取公开文件",
            "tool": "file.read",
            "params": {
                "path": "public/runtime_demo_note.txt",
            },
            "result": execute_tool(
                "file.read",
                {
                    "path": "public/runtime_demo_note.txt",
                },
            ),
        }
    )

    steps.append(
        {
            "name": "沙箱邮件落盘",
            "tool": "email.send",
            "params": {
                "to": "internal@example.com",
                "subject": "AgentGuard 沙箱演示邮件",
                "content": "这是一封沙箱邮件，不会真实外发，只会写入 runtime_workspace/outbox。",
            },
            "result": execute_tool(
                "email.send",
                {
                    "to": "internal@example.com",
                    "subject": "AgentGuard 沙箱演示邮件",
                    "content": "这是一封沙箱邮件，不会真实外发，只会写入 runtime_workspace/outbox。",
                },
            ),
        }
    )

    steps.append(
        {
            "name": "查询沙箱数据库",
            "tool": "db.query",
            "params": {
                "sql": "SELECT id, title, visibility FROM notices",
            },
            "result": execute_tool(
                "db.query",
                {
                    "sql": "SELECT id, title, visibility FROM notices",
                },
            ),
        }
    )

    steps.append(
        {
            "name": "执行安全命令",
            "tool": "shell.run",
            "params": {
                "command": "echo AgentGuard sandbox demo",
            },
            "result": execute_tool(
                "shell.run",
                {
                    "command": "echo AgentGuard sandbox demo",
                },
            ),
        }
    )

    steps.append(
        {
            "name": "路径穿越拦截测试",
            "tool": "file.read",
            "params": {
                "path": "../secret/password.txt",
            },
            "result": execute_tool(
                "file.read",
                {
                    "path": "../secret/password.txt",
                },
            ),
        }
    )

    success_count = sum(
        1
        for step in steps
        if step["result"].get("success") is True
    )

    blocked_count = sum(
        1
        for step in steps
        if step["result"].get("success") is False
    )

    return {
        "message": "Sandbox demo executed successfully.",
        "sandbox": {
            "root": str(SANDBOX_DIR),
            "outbox_dir": str(OUTBOX_DIR),
            "database": str(DB_PATH),
        },
        "summary": {
            "total_steps": len(steps),
            "success_steps": success_count,
            "blocked_steps": blocked_count,
            "note": "blocked_steps 中包含故意设计的路径穿越拦截测试。",
        },
        "steps": steps,
    }


@router.get("/{task_id}/state")
def read_runtime_state(task_id: str):
    """
    查看指定任务的运行时状态。
    """

    state = get_runtime_state(task_id)

    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Runtime task {task_id} not found.",
        )

    return {
        "message": "Runtime task state loaded successfully.",
        "state": state.model_dump(),
    }


@router.get("")
def list_runtime_tasks():
    """
    查看当前内存中的全部运行时任务。
    """

    states = list_runtime_states()

    return {
        "message": "Runtime task list loaded successfully.",
        "count": len(states),
        "tasks": {
            task_id: state.model_dump()
            for task_id, state in states.items()
        },
    }


def _count_files(directory: Path) -> int:
    if not directory.exists():
        return 0

    return sum(1 for item in directory.iterdir() if item.is_file())


def _list_files(directory: Path):
    if not directory.exists():
        return []

    files = []

    for file_path in sorted(directory.iterdir()):
        if not file_path.is_file():
            continue

        files.append(
            {
                "name": file_path.name,
                "relative_path": str(file_path.relative_to(SANDBOX_DIR)),
                "size": file_path.stat().st_size,
            }
        )

    return files
