"""
Small security detector helpers used by the Gateway.

These functions are intentionally pure and configuration-independent. They
classify already-matched keywords into higher-level hard-risk categories.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import unquote


@dataclass(frozen=True)
class PathRiskAnalysis:
    """
    Normalized view of a user supplied resource path.

    The gateway still keeps policy decisions configuration-driven, but this
    object makes path risk signals explicit and explainable.
    """

    original: str
    decoded: str
    normalized: str
    is_absolute: bool
    has_traversal: bool
    has_encoded_bypass: bool
    reasons: tuple[str, ...]


def _decode_repeated(value: str, *, max_rounds: int = 3) -> str:
    """
    Decode URL-encoded path text a few times to catch double-encoding.
    """

    current = str(value)

    for _ in range(max_rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded

    return current


def _collapse_path(path: str) -> tuple[str, bool]:
    """
    Collapse "." and ".." segments without touching the filesystem.
    """

    normalized = str(path).replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")

    has_traversal = False
    parts: list[str] = []

    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            has_traversal = True
            if parts:
                parts.pop()
            continue
        parts.append(part)

    return "/".join(parts), has_traversal


def analyze_resource_path(path: str) -> PathRiskAnalysis:
    """
    Decode and normalize a resource path for gateway risk checks.
    """

    original = str(path or "").strip().replace("\x00", "")
    decoded = _decode_repeated(original).strip().replace("\x00", "")
    decoded_slash = decoded.replace("\\", "/")
    collapsed, has_traversal = _collapse_path(decoded_slash)

    is_unix_absolute = decoded_slash.startswith("/")
    is_windows_absolute = bool(re.match(r"^[a-zA-Z]:/", decoded_slash))
    is_unc_path = original.startswith("\\\\") or decoded_slash.startswith("//")
    is_absolute = is_unix_absolute or is_windows_absolute or is_unc_path

    decoded_changed = decoded != original
    has_encoded_bypass = decoded_changed and (
        ".." in decoded_slash
        or decoded_slash.startswith("/")
        or bool(re.match(r"^[a-zA-Z]:/", decoded_slash))
        or "//" in decoded_slash
    )

    reasons: list[str] = []
    if decoded_changed:
        reasons.append("检测到 URL 编码路径，已进行重复解码。")
    if has_encoded_bypass:
        reasons.append("URL 编码解码后存在路径绕过特征。")
    if has_traversal:
        reasons.append("路径包含目录穿越片段。")
    if is_absolute:
        reasons.append("路径是绝对路径或 UNC 路径。")
    if "\\" in original:
        reasons.append("检测到 Windows 反斜杠路径分隔符，已按 / 归一化。")

    return PathRiskAnalysis(
        original=original,
        decoded=decoded_slash,
        normalized=collapsed,
        is_absolute=is_absolute,
        has_traversal=has_traversal,
        has_encoded_bypass=has_encoded_bypass,
        reasons=tuple(reasons),
    )


def is_path_bypass_keyword(keyword: str) -> bool:
    """
    Return True if a matched path keyword indicates traversal or encoded bypass.
    """

    normalized = str(keyword).lower().replace("\\", "/")
    bypass_markers = (
        "../",
        "%2e%2e",
        "%252e%252e",
        "%2f",
        "%5c",
        "%252f",
        "%255c",
        "....//",
        "..././",
    )
    return any(marker in normalized for marker in bypass_markers)


def is_destructive_sql_keyword(keyword: str) -> bool:
    """
    Return True if a SQL keyword represents destructive or privilege-changing SQL.
    """

    normalized = str(keyword).lower().strip()
    destructive_markers = (
        "drop",
        "truncate",
        "delete",
        "update",
        "insert",
        "alter",
        "grant",
        "revoke",
        "xp_cmdshell",
        "outfile",
        "load_file",
        "load_extension",
    )
    return any(marker in normalized for marker in destructive_markers)


_is_path_bypass_keyword = is_path_bypass_keyword
_is_destructive_sql_keyword = is_destructive_sql_keyword
