from backend.mcp.tool_registry import (
    all_tool_definitions,
    supported_oauth_scopes,
    tool_definitions_for_scopes,
)


def _names(tools):
    return [tool["name"] for tool in tools]


def test_tool_registry_is_deterministic():
    names = _names(all_tool_definitions())
    assert names == sorted(names)
    assert names == [
        "db.query",
        "email.send",
        "file.delete",
        "file.read",
        "file.write",
        "shell.run",
    ]


def test_tools_list_is_filtered_by_oauth_scopes():
    tools = tool_definitions_for_scopes(
        [
            "mcp:tools:list",
            "tool:file:read",
        ]
    )

    assert _names(tools) == ["file.read"]


def test_side_effect_tool_requires_side_effect_scope():
    missing_side_effect = tool_definitions_for_scopes(
        [
            "mcp:tools:list",
            "tool:file:write",
        ]
    )
    with_side_effect = tool_definitions_for_scopes(
        [
            "mcp:tools:list",
            "tool:file:write",
            "sink:side-effect",
        ]
    )

    assert "file.write" not in _names(missing_side_effect)
    assert "file.write" in _names(with_side_effect)


def test_supported_scopes_cover_mcp_and_dynamic_resource_scopes():
    scopes = supported_oauth_scopes()
    assert "mcp:tools:list" in scopes
    assert "sink:external-email" in scopes
    assert "source:sensitive-file" in scopes
