from __future__ import annotations

from typing import Any, Dict, List, Optional


SIDE_EFFECT_TOOLS = {
    "file.write",
    "file.delete",
    "email.send",
    "shell.run",
    "http.post",
    "db.write",
}

FILE_TOOLS = {
    "file.read",
    "file.write",
    "file.delete",
}

DANGEROUS_SHELL_KEYWORDS = [
    "rm -rf",
    "del /s",
    "format",
    "shutdown",
    "reboot",
    "curl",
    "wget",
    "powershell",
    "cmd.exe",
    "certutil",
    "bitsadmin",
    "nc ",
    "netcat",
    "ssh ",
    "scp ",
    "ftp ",
    "python -c",
    "bash -c",
    "sh -c",
]

SENSITIVE_PATH_MARKERS = [
    "secret/",
    "private/",
    "../",
    "..\\",
    ".env",
    "password",
    "token",
    "credential",
]


SANDBOX_PROFILES: Dict[str, Dict[str, Any]] = {
    "default": {
        "description": "Default observation sandbox. It records sandbox context but does not add extra blocking.",
        "allowed_tools": ["*"],
        "denied_tools": [],
        "allowed_path_prefixes": ["*"],
        "denied_path_markers": [],
        "filesystem": "project_scoped",
        "network": "restricted",
        "shell_enabled": True,
        "side_effects": "runtime_controlled",
    },
    "local_readonly": {
        "description": "Read-only local sandbox. Only public/course read-like tools are expected.",
        "allowed_tools": ["file.read", "db.query"],
        "denied_tools": ["file.write", "file.delete", "email.send", "shell.run", "http.post"],
        "allowed_path_prefixes": ["public/", "course/"],
        "denied_path_markers": SENSITIVE_PATH_MARKERS,
        "filesystem": "read_only_public_course",
        "network": "disabled",
        "shell_enabled": False,
        "side_effects": "blocked",
    },
    "local_safe_write": {
        "description": "Safe local write sandbox. Limited side effects may continue to Runtime Monitor and human approval.",
        "allowed_tools": ["file.read", "file.write", "db.query", "email.send"],
        "denied_tools": ["file.delete", "shell.run", "http.post"],
        "allowed_path_prefixes": ["public/", "course/", "outbox/"],
        "denied_path_markers": SENSITIVE_PATH_MARKERS,
        "filesystem": "project_scoped_write",
        "network": "email_only_with_runtime_approval",
        "shell_enabled": False,
        "side_effects": "approval_required",
    },
    "no_shell": {
        "description": "Sandbox that allows normal tool calls but forbids shell execution.",
        "allowed_tools": ["*"],
        "denied_tools": ["shell.run"],
        "allowed_path_prefixes": ["*"],
        "denied_path_markers": SENSITIVE_PATH_MARKERS,
        "filesystem": "project_scoped",
        "network": "restricted",
        "shell_enabled": False,
        "side_effects": "runtime_controlled",
    },
    "strict": {
        "description": "Strict sandbox. Only read-only public tools are allowed; side-effect tools are blocked.",
        "allowed_tools": ["file.read", "db.query"],
        "denied_tools": ["file.write", "file.delete", "email.send", "shell.run", "http.post"],
        "allowed_path_prefixes": ["public/"],
        "denied_path_markers": SENSITIVE_PATH_MARKERS,
        "filesystem": "read_only_public_only",
        "network": "disabled",
        "shell_enabled": False,
        "side_effects": "blocked",
    },
}


def normalize_sandbox_profile(profile_name: Optional[str]) -> str:
    if not profile_name:
        return "default"

    normalized = str(profile_name).strip().lower()

    if normalized in SANDBOX_PROFILES:
        return normalized

    return "default"


def _contains_dangerous_shell_keyword(command: str) -> bool:
    lowered = command.lower()
    return any(keyword in lowered for keyword in DANGEROUS_SHELL_KEYWORDS)


def _normalize_path(params: Dict[str, Any]) -> str:
    raw = (
        params.get("path")
        or params.get("file_path")
        or params.get("resource")
        or params.get("filename")
        or ""
    )

    path = str(raw).strip().replace("\\", "/")

    while path.startswith("./"):
        path = path[2:]

    return path.lower()


def _is_absolute_or_drive_path(path: str) -> bool:
    if not path:
        return False

    first_part = path.split("/")[0]
    return path.startswith("/") or ":" in first_part


def _matches_allowed_prefix(path: str, allowed_prefixes: List[str]) -> bool:
    if "*" in allowed_prefixes:
        return True

    normalized = path.strip("/")

    for prefix in allowed_prefixes:
        prefix = str(prefix).strip().lower().strip("/")

        if normalized == prefix:
            return True

        if normalized.startswith(prefix + "/"):
            return True

    return False


def _evaluate_file_path_policy(
    profile_name: str,
    profile: Dict[str, Any],
    tool: str,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    if tool not in FILE_TOOLS:
        return {
            "decision": "allow",
            "risk_delta": 0,
            "reason": [],
        }

    path = _normalize_path(params)

    if not path:
        return {
            "decision": "deny",
            "risk_delta": 100,
            "reason": ["File tool call has an empty path."],
        }

    if _is_absolute_or_drive_path(path):
        return {
            "decision": "deny",
            "risk_delta": 100,
            "reason": ["Sandbox policy denied absolute path or drive-letter path."],
        }

    denied_markers = list(profile.get("denied_path_markers") or [])

    for marker in denied_markers:
        marker = str(marker).lower().replace("\\", "/")
        if marker in path:
            return {
                "decision": "deny",
                "risk_delta": 100,
                "reason": [
                    f"Sandbox profile {profile_name} denied sensitive or unsafe path marker: {marker}"
                ],
            }

    allowed_prefixes = list(profile.get("allowed_path_prefixes") or ["*"])

    if not _matches_allowed_prefix(path, allowed_prefixes):
        return {
            "decision": "deny",
            "risk_delta": 100,
            "reason": [
                f"Sandbox profile {profile_name} only allows file paths under: {allowed_prefixes}"
            ],
        }

    return {
        "decision": "allow",
        "risk_delta": 0,
        "reason": [
            f"Sandbox path policy allowed file path: {path}"
        ],
    }


def evaluate_sandbox_policy(
    profile_name: Optional[str],
    tool: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    params = params or {}
    normalized_profile = normalize_sandbox_profile(profile_name)
    profile = SANDBOX_PROFILES[normalized_profile]

    allowed_tools: List[str] = list(profile["allowed_tools"])
    denied_tools: List[str] = list(profile["denied_tools"])

    reasons: List[str] = [
        f"Sandbox profile={normalized_profile}.",
        str(profile["description"]),
    ]

    decision = "allow"
    risk_delta = 0

    if tool in denied_tools:
        decision = "deny"
        risk_delta = 100
        reasons.append(f"Tool {tool} is denied by sandbox profile {normalized_profile}.")

    elif "*" not in allowed_tools and tool not in allowed_tools:
        decision = "deny"
        risk_delta = 100
        reasons.append(f"Tool {tool} is not in allowed_tools of sandbox profile {normalized_profile}.")

    path_policy = _evaluate_file_path_policy(
        profile_name=normalized_profile,
        profile=profile,
        tool=tool,
        params=params,
    )

    reasons.extend(path_policy.get("reason", []))

    if path_policy.get("decision") == "deny":
        decision = "deny"
        risk_delta = max(risk_delta, int(path_policy.get("risk_delta") or 0))

    if tool == "shell.run":
        command = str(params.get("command") or params.get("cmd") or "")

        if not profile.get("shell_enabled", False):
            decision = "deny"
            risk_delta = 100
            reasons.append(f"Shell execution is disabled by sandbox profile {normalized_profile}.")

        if _contains_dangerous_shell_keyword(command):
            decision = "deny"
            risk_delta = 100
            reasons.append("Dangerous shell keyword detected by sandbox policy.")

    if normalized_profile in {"local_readonly", "strict"} and tool in SIDE_EFFECT_TOOLS:
        decision = "deny"
        risk_delta = 100
        reasons.append(f"Side-effect tool {tool} is blocked in {normalized_profile} sandbox.")

    return {
        "profile": normalized_profile,
        "decision": decision,
        "risk_delta": risk_delta,
        "reason": reasons,
        "policy": {
            "allowed_tools": allowed_tools,
            "denied_tools": denied_tools,
            "allowed_path_prefixes": profile.get("allowed_path_prefixes", ["*"]),
            "denied_path_markers": profile.get("denied_path_markers", []),
            "filesystem": profile["filesystem"],
            "network": profile["network"],
            "shell_enabled": profile["shell_enabled"],
            "side_effects": profile["side_effects"],
        },
    }
