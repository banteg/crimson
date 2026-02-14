from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from crimson.cli import app


def test_lan_host_command_builds_pending_session_and_runs_game(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_game(config):  # noqa: ANN001
        captured["config"] = config

    monkeypatch.setattr("crimson.game.run_game", _fake_run_game)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "lan",
            "host",
            "--mode",
            "rush",
            "--players",
            "3",
            "--bind",
            "127.0.0.1",
            "--port",
            "32001",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    pending = config.pending_lan_session
    assert pending is not None
    assert pending.role == "host"
    assert pending.auto_start is True
    assert pending.config.mode == "rush"
    assert pending.config.player_count == 3
    assert pending.config.bind_host == "127.0.0.1"
    assert pending.config.port == 32001
    assert pending.config.preserve_bugs is False


def test_lan_host_quests_requires_quest_level(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("crimson.game.run_game", lambda _config: None)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "lan",
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


def test_lan_join_command_builds_pending_join_session(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_game(config):  # noqa: ANN001
        captured["config"] = config

    monkeypatch.setattr("crimson.game.run_game", _fake_run_game)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "lan",
            "join",
            "--host",
            "192.168.1.42",
            "--port",
            "31993",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    pending = config.pending_lan_session
    assert pending is not None
    assert pending.role == "join"
    assert pending.auto_start is True
    assert pending.config.mode == "survival"
    assert pending.config.host_ip == "192.168.1.42"
    assert pending.config.port == 31993


def test_lan_join_loopback_host_autostarts_session(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_game(config):  # noqa: ANN001
        captured["config"] = config

    monkeypatch.setattr("crimson.game.run_game", _fake_run_game)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "lan",
            "join",
            "--host",
            "127.0.0.1",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    pending = config.pending_lan_session
    assert pending is not None
    assert pending.role == "join"
    assert pending.auto_start is True
    assert pending.config.host_ip == "127.0.0.1"
