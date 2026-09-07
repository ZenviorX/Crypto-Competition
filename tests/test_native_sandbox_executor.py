from pathlib import Path

from backend.sandbox.native_sandbox_executor import execute_tool_in_native_sandbox
from backend.tools.tool_executor import ensure_sandbox_ready


def test_native_sandbox_can_read_public_file():
    ensure_sandbox_ready()
    result = execute_tool_in_native_sandbox(
        tool="file.read",
        params={"path": "public/notice.txt"},
        profile_name="local_readonly",
    )

    assert result["success"] is True, result
    assert result["sandbox_evidence"]["sandbox_type"] == "native_subprocess"
    assert result["sandbox_evidence"]["tool_result"]["success"] is True


def test_native_sandbox_blocks_secret_file_under_strict_profile():
    ensure_sandbox_ready()
    result = execute_tool_in_native_sandbox(
        tool="file.read",
        params={"path": "secret/password.txt"},
        profile_name="strict",
    )

    assert result["success"] is False
    assert result["sandbox_evidence"]["sandbox_type"] == "native_subprocess"
    assert "outside allowed native sandbox prefixes" in str(result["result"])


def test_native_sandbox_allows_outbox_write_only_for_safe_write_profile():
    ensure_sandbox_ready()
    result = execute_tool_in_native_sandbox(
        tool="file.write",
        params={"path": "outbox/native_demo.txt", "content": "hello native sandbox"},
        profile_name="local_safe_write",
    )

    assert result["success"] is True, result
    assert result["sandbox_evidence"]["tool_result"]["success"] is True



def test_native_sandbox_can_query_database_read_only():
    result = (
        execute_tool_in_native_sandbox(
            tool="db.query",
            params={
                "sql": (
                    "SELECT id, title, "
                    "content, visibility "
                    "FROM notices "
                    "ORDER BY id"
                )
            },
            profile_name=(
                "local_readonly"
            ),
        )
    )

    assert result["success"] is True, result

    query_result = (
        result["tool_result"][
            "result"
        ]
    )

    assert (
        query_result["data_scope"]
        == "public"
    )

    assert (
        query_result["row_count"]
        >= 1
    )

    assert (
        len(query_result["rows"])
        >= 1
    )

    assert (
        query_result["rows"][0][
            "visibility"
        ]
        == "public"
    )

    serialized = str(
        query_result
    ).lower()

    assert "course" not in serialized
    assert "secret" not in serialized
    assert "敏感记录" not in serialized



def test_native_sandbox_rejects_database_write():
    ensure_sandbox_ready()

    result = execute_tool_in_native_sandbox(
        tool="db.query",
        params={
            "sql": (
                "DELETE FROM notices"
            )
        },
        profile_name="local_readonly",
    )

    assert result["success"] is False

    assert (
        "only permits SELECT"
        in str(result["result"])
        or "modification" in str(
            result["result"]
        ).lower()
    )


def test_native_sandbox_can_delete_outbox_file():
    ensure_sandbox_ready()

    relative_path = (
        "outbox/"
        "native_delete_test.txt"
    )

    write_result = (
        execute_tool_in_native_sandbox(
            tool="file.write",
            params={
                "path": relative_path,
                "content": (
                    "temporary delete test"
                ),
            },
            profile_name=(
                "local_safe_write"
            ),
        )
    )

    assert write_result["success"] is True

    delete_result = (
        execute_tool_in_native_sandbox(
            tool="file.delete",
            params={
                "path": relative_path
            },
            profile_name=(
                "local_safe_write"
            ),
        )
    )

    assert (
        delete_result["success"]
        is True
    )

    assert not (
        Path("runtime_workspace")
        / relative_path
    ).exists()



def test_direct_db_query_returns_only_public_rows():
    from backend.tools.tool_executor import (
        execute_tool,
    )

    result = execute_tool(
        "db.query",
        {
            "sql": (
                "SELECT * "
                "FROM notices "
                "ORDER BY id"
            )
        },
    )

    assert result["success"] is True, result

    query_result = result["result"]

    assert (
        query_result["data_scope"]
        == "public"
    )

    assert (
        query_result["row_count"]
        >= 1
    )

    assert all(
        row["visibility"] == "public"
        for row in query_result["rows"]
    )


def test_docker_runner_db_query_returns_only_public_rows(
    monkeypatch,
):
    from backend.sandbox.runner import (
        sandbox_tool,
    )

    from backend.tools.tool_executor import (
        DB_PATH,
        ensure_sandbox_ready,
    )

    ensure_sandbox_ready()

    monkeypatch.setattr(
        sandbox_tool,
        "DATABASE_PATH",
        DB_PATH,
    )

    result = sandbox_tool._query_database(
        {
            "sql": (
                "SELECT id, title, "
                "content, visibility "
                "FROM notices "
                "ORDER BY id"
            )
        }
    )

    assert result["success"] is True, result

    query_result = result["result"]

    assert (
        query_result["data_scope"]
        == "public"
    )

    assert query_result["row_count"] >= 1

    assert all(
        row["visibility"] == "public"
        for row in query_result["rows"]
    )

    serialized = str(
        query_result
    ).lower()

    assert "course" not in serialized
    assert "secret" not in serialized
