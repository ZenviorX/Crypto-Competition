from backend.sandbox.sandbox_policy import evaluate_sandbox_policy


def _decision(profile: str, tool: str, path: str) -> str:
    return evaluate_sandbox_policy(
        profile,
        tool,
        {"path": path},
    )["decision"]


def test_local_readonly_allows_public_read():
    assert _decision("local_readonly", "file.read", "public/notice.txt") == "allow"


def test_local_readonly_denies_secret_read():
    assert _decision("local_readonly", "file.read", "secret/password.txt") == "deny"


def test_local_readonly_denies_private_read():
    assert _decision("local_readonly", "file.read", "private/course_plan.txt") == "deny"


def test_local_readonly_denies_path_traversal():
    assert _decision("local_readonly", "file.read", "../secret/password.txt") == "deny"


def test_local_readonly_denies_windows_drive_path():
    assert _decision("local_readonly", "file.read", "C:/Users/admin/.env") == "deny"


def test_strict_only_allows_public_path():
    assert _decision("strict", "file.read", "public/notice.txt") == "allow"
    assert _decision("strict", "file.read", "course/notice.txt") == "deny"


def test_local_safe_write_allows_public_write_but_denies_secret_write():
    assert _decision("local_safe_write", "file.write", "public/output.txt") == "allow"
    assert _decision("local_safe_write", "file.write", "secret/output.txt") == "deny"


def test_no_shell_profile_still_denies_sensitive_file_path():
    assert _decision("no_shell", "file.read", "secret/password.txt") == "deny"


def test_unknown_profile_falls_back_to_default():
    assert _decision("unknown_profile", "file.read", "secret/password.txt") == "allow"
