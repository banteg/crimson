from __future__ import annotations

from pathlib import Path
from unittest.mock import call

import pytest

from crimson.original import diagnostics_daemon
from crimson.original.diagnostics_cache import DaemonResponse


def test_run_tool_request_starts_daemon_on_first_connect_failure(monkeypatch, mocker, tmp_path: Path) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_SOCKET", str(tmp_path / "cache" / "daemon.sock"))

    sequence = mocker.Mock()

    def fake_send(*args, **kwargs):
        sequence("send")
        if sequence.call_count == 1:
            raise OSError("connect failed")
        return DaemonResponse(exit_code=0, stdout="ok", stderr="")

    def fake_start() -> None:
        sequence("start")

    def fake_wait(*, timeout_seconds: float) -> bool:
        sequence(f"wait:{timeout_seconds}")
        return True

    mocker.patch.object(diagnostics_daemon, "_send_request_once", side_effect=fake_send)
    mocker.patch.object(diagnostics_daemon, "_start_daemon_background", side_effect=fake_start)
    mocker.patch.object(diagnostics_daemon, "_wait_for_daemon_ready", side_effect=fake_wait)

    response = diagnostics_daemon.run_tool_request(
        tool="_ping",
        args=[],
        cwd=Path.cwd(),
    )

    assert response.exit_code == 0
    assert response.stdout == "ok"
    assert sequence.call_args_list == [
        call("send"),
        call("start"),
        call(f"wait:{diagnostics_daemon._DAEMON_BOOT_TIMEOUT_SECONDS}"),
        call("send"),
    ]


def test_run_tool_request_raises_when_daemon_does_not_boot(monkeypatch, mocker, tmp_path: Path) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_SOCKET", str(tmp_path / "cache" / "daemon.sock"))

    mocker.patch.object(
        diagnostics_daemon,
        "_send_request_once",
        side_effect=lambda *a, **k: (_ for _ in ()).throw(OSError("fail")),
    )
    mocker.patch.object(diagnostics_daemon, "_start_daemon_background", side_effect=lambda: None)
    mocker.patch.object(diagnostics_daemon, "_wait_for_daemon_ready", side_effect=lambda **kwargs: False)

    with pytest.raises(RuntimeError, match="failed to start"):
        diagnostics_daemon.run_tool_request(tool="_ping", args=[], cwd=Path.cwd())


def test_run_tool_handles_help_without_daemon_frame_abort() -> None:
    response = diagnostics_daemon._run_tool(
        tool="divergence-report",
        args=["--help"],
        registry=diagnostics_daemon.SessionRegistry(),
        cwd=Path.cwd(),
    )

    assert response.exit_code == 0
    assert "usage: crimson" in response.stdout
