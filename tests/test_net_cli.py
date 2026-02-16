from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from crimson.cli import app


def test_net_host_command_builds_pending_network_session(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_game(config):  # noqa: ANN001
        captured["config"] = config

    monkeypatch.setattr("crimson.game.run_game", _fake_run_game)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "host",
            "--mode",
            "rush",
            "--players",
            "3",
            "--relay-host",
            "203.0.113.10",
            "--relay-port",
            "32011",
            "--room-code",
            "ab12cd",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    pending = config.pending_net_session
    assert pending is not None
    assert config.pending_lan_session is pending
    assert pending.role == "host"
    assert pending.auto_start is True
    assert pending.config.mode == "rush"
    assert pending.config.player_count == 3
    assert pending.config.relay_host == "203.0.113.10"
    assert pending.config.relay_port == 32011
    assert pending.config.room_code == "AB12CD"
    assert pending.config.netcode_mode == "rollback"


def test_net_host_quests_requires_quest_level(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("crimson.game.run_game", lambda _config: None)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "host",
            "--mode",
            "quests",
            "--players",
            "2",
            "--base-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert "quest level is required" in result.output


def test_net_join_command_builds_pending_join_session_with_legacy_fallback(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_game(config):  # noqa: ANN001
        captured["config"] = config

    monkeypatch.setattr("crimson.game.run_game", _fake_run_game)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "join",
            "--code",
            "room42",
            "--relay-host",
            "198.51.100.15",
            "--relay-port",
            "31999",
            "--netcode",
            "lockstep",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    pending = config.pending_net_session
    assert pending is not None
    assert config.pending_lan_session is pending
    assert pending.role == "join"
    assert pending.auto_start is True
    assert pending.config.room_code == "ROOM42"
    assert pending.config.relay_host == "198.51.100.15"
    assert pending.config.relay_port == 31999
    assert pending.config.netcode_mode == "lockstep_legacy"


def test_relay_serve_command_constructs_relay_server(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class _FakeRelayServer:
        def __init__(self, cfg) -> None:  # noqa: ANN001
            captured["cfg"] = cfg

        def serve_forever(self, *, tick_ms: int) -> None:
            captured["tick_ms"] = int(tick_ms)

    monkeypatch.setattr("crimson.net.relay_service.RelayServer", _FakeRelayServer)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "relay",
            "serve",
            "--bind",
            "127.0.0.1",
            "--port",
            "32021",
            "--tick-ms",
            "11",
        ],
    )

    assert result.exit_code == 0, result.output
    cfg = captured["cfg"]
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.bind_port == 32021
    assert captured["tick_ms"] == 11
