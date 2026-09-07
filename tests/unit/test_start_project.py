import os
import signal

import pytest

import start_project


def test_oauth_starts_by_default() -> None:
    args = start_project.parser().parse_args([])

    assert args.with_oauth is True


def test_oauth_can_be_disabled_explicitly() -> None:
    assert start_project.parser().parse_args(["--without-oauth"]).with_oauth is False
    assert start_project.parser().parse_args(["--no-oauth"]).with_oauth is False


def test_legacy_with_oauth_flag_remains_compatible() -> None:
    args = start_project.parser().parse_args(["--with-oauth"])

    assert args.with_oauth is True


def test_signal_handlers_include_ctrl_c(monkeypatch) -> None:
    installed: list[int] = []
    monkeypatch.setattr(
        start_project.signal,
        "signal",
        lambda value, handler: installed.append(value),
    )

    start_project.install_signal_handlers()

    assert signal.SIGINT in installed
    assert signal.SIGTERM in installed


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups are unavailable on Windows")
def test_posix_kill_tree_targets_service_process_group(monkeypatch) -> None:
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(start_project, "is_windows", lambda: False)
    monkeypatch.setattr(start_project, "pid_alive", lambda pid: True)
    monkeypatch.setattr(start_project.os, "getpid", lambda: 1)
    monkeypatch.setattr(start_project.os, "getppid", lambda: 2)
    monkeypatch.setattr(start_project.os, "getpgid", lambda pid: 9001)
    monkeypatch.setattr(start_project.os, "getpgrp", lambda: 8001)
    monkeypatch.setattr(
        start_project.os,
        "killpg",
        lambda pgid, value: sent.append((pgid, value)),
    )
    monkeypatch.setattr(
        start_project,
        "wait_process_group_exit",
        lambda pgid, seconds, leader_pid=0: True,
    )

    start_project.kill_tree(1234)

    assert sent == [(9001, signal.SIGTERM)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups are unavailable on Windows")
def test_posix_kill_tree_forces_group_after_timeout(monkeypatch) -> None:
    sent: list[tuple[int, int]] = []
    waits = iter([False, True])
    monkeypatch.setattr(start_project, "is_windows", lambda: False)
    monkeypatch.setattr(start_project, "pid_alive", lambda pid: True)
    monkeypatch.setattr(start_project.os, "getpid", lambda: 1)
    monkeypatch.setattr(start_project.os, "getppid", lambda: 2)
    monkeypatch.setattr(start_project.os, "getpgid", lambda pid: 9001)
    monkeypatch.setattr(start_project.os, "getpgrp", lambda: 8001)
    monkeypatch.setattr(
        start_project.os,
        "killpg",
        lambda pgid, value: sent.append((pgid, value)),
    )
    monkeypatch.setattr(
        start_project,
        "wait_process_group_exit",
        lambda *args, **kwargs: next(waits),
    )

    start_project.kill_tree(1234)

    assert sent == [
        (9001, signal.SIGTERM),
        (9001, signal.SIGKILL),
    ]


def test_windows_kill_tree_falls_back_to_taskkill(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(start_project, "is_windows", lambda: True)
    monkeypatch.setattr(start_project, "pid_alive", lambda pid: True)
    monkeypatch.setattr(start_project.os, "getpid", lambda: 1)
    monkeypatch.setattr(start_project.os, "getppid", lambda: 2)
    monkeypatch.setattr(
        start_project.os,
        "kill",
        lambda pid, value: (_ for _ in ()).throw(OSError()),
    )
    monkeypatch.setattr(
        start_project.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command),
    )
    monkeypatch.setattr(start_project, "wait_pid_exit", lambda pid, seconds: True)

    start_project.kill_tree(1234)

    assert calls == [["taskkill", "/PID", "1234", "/T", "/F"]]


def test_stop_managed_attempts_every_service_after_one_failure(monkeypatch) -> None:
    called: list[str] = []
    state = {"services": {"backend": {}, "frontend": {}, "oauth": {}}}

    def stop(name: str, current_state: dict) -> None:
        called.append(name)
        if name == "oauth":
            raise start_project.LaunchError("oauth failed")

    monkeypatch.setattr(start_project, "stop_service", stop)
    monkeypatch.setattr(start_project, "save_state", lambda current_state: None)

    start_project.stop_managed(
        [{"name": "backend"}, {"name": "frontend"}, {"name": "oauth"}],
        state,
    )

    assert called == ["oauth", "frontend", "backend"]
    assert state["services"] == {}
