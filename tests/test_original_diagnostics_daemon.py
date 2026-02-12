from __future__ import annotations

from pathlib import Path

from crimson.original import diagnostics_daemon
from crimson.original.diagnostics_cache import DaemonResponse


def test_run_tool_request_starts_daemon_on_first_connect_failure(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_SOCKET", str(tmp_path / "cache" / "daemon.sock"))

    calls: list[str] = []

    def fake_send(*args, **kwargs):
        calls.append("send")
        if len(calls) == 1:
            raise OSError("connect failed")
        return DaemonResponse(exit_code=0, stdout="ok", stderr="")

    def fake_start() -> None:
        calls.append("start")

    def fake_wait(*, timeout_seconds: float) -> bool:
        calls.append(f"wait:{timeout_seconds}")
        return True

    monkeypatch.setattr(diagnostics_daemon, "_send_request_once", fake_send)
    monkeypatch.setattr(diagnostics_daemon, "_start_daemon_background", fake_start)
    monkeypatch.setattr(diagnostics_daemon, "_wait_for_daemon_ready", fake_wait)

    response = diagnostics_daemon.run_tool_request(
        tool="_ping",
        args=[],
        cwd=Path.cwd(),
    )

    assert response.exit_code == 0
    assert response.stdout == "ok"
    assert calls == ["send", "start", f"wait:{diagnostics_daemon._DAEMON_BOOT_TIMEOUT_SECONDS}", "send"]


def test_run_tool_request_raises_when_daemon_does_not_boot(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_SOCKET", str(tmp_path / "cache" / "daemon.sock"))

    monkeypatch.setattr(diagnostics_daemon, "_send_request_once", lambda *a, **k: (_ for _ in ()).throw(OSError("fail")))
    monkeypatch.setattr(diagnostics_daemon, "_start_daemon_background", lambda: None)
    monkeypatch.setattr(diagnostics_daemon, "_wait_for_daemon_ready", lambda **kwargs: False)

    try:
        diagnostics_daemon.run_tool_request(tool="_ping", args=[], cwd=Path.cwd())
    except RuntimeError as exc:
        assert "failed to start" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")


def test_run_tool_handles_help_without_daemon_frame_abort() -> None:
    response = diagnostics_daemon._run_tool(
        tool="divergence-report",
        args=["--help"],
        registry=diagnostics_daemon.SessionRegistry(),
        cwd=Path.cwd(),
    )

    assert response.exit_code == 0
    assert "usage: crimson" in response.stdout
