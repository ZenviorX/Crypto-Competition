from __future__ import annotations

from typing import Any, Dict, Optional

from backend.sandbox.docker_sandbox_executor import docker_available, execute_tool_in_docker_sandbox
from backend.sandbox.native_sandbox_executor import execute_tool_in_native_sandbox


def execute_tool_in_real_sandbox(
    tool: str,
    params: Optional[Dict[str, Any]],
    profile_name: Optional[str] = "default",
    prefer: str = "auto",
) -> Dict[str, Any]:
    """
    Hybrid execution sandbox.

    - prefer=docker: use Docker, return Docker unavailable error if missing.
    - prefer=native: always use no-install native subprocess sandbox.
    - prefer=auto: use Docker when available, otherwise fall back to native.
    """

    selected = str(prefer or "auto").lower()

    if selected == "docker":
        result = execute_tool_in_docker_sandbox(tool=tool, params=params, profile_name=profile_name)
        result["sandbox_engine"] = "docker"
        return result

    if selected == "native":
        result = execute_tool_in_native_sandbox(tool=tool, params=params, profile_name=profile_name)
        result["sandbox_engine"] = "native_subprocess"
        return result

    if docker_available():
        result = execute_tool_in_docker_sandbox(tool=tool, params=params, profile_name=profile_name)
        result["sandbox_engine"] = "docker"
        result["fallback_used"] = False
        return result

    result = execute_tool_in_native_sandbox(tool=tool, params=params, profile_name=profile_name)
    result["sandbox_engine"] = "native_subprocess"
    result["fallback_used"] = True
    return result
