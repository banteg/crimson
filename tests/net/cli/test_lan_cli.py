from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from crimson import game
from crimson.cli import app


def test_lan_command_is_removed() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["lan", "host", "--mode", "survival", "--players", "1"])

    assert result.exit_code == 2
    assert "No such command 'lan'" in result.output


def test_net_host_lockstep_builds_pending_session_and_runs_game(mocker, tmp_path: Path) -> None:
    run_game = mocker.patch.object(game, "run_game")

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
            "--netcode",
            "lockstep",
            "--bind",
            "127.0.0.1",
            "--host",
            "192.168.1.10",
            "--port",
            "32001",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_game.assert_called_once()
    config = run_game.call_args.args[0]
    pending = config.pending_network_session
    assert pending is not None
    assert pending.role == "host"
    assert pending.auto_start is True
    assert pending.config.mode == "rush"
    assert pending.config.player_count == 3
    assert pending.config.netcode_mode == "lockstep"
    endpoint = pending.config.endpoint
    assert endpoint.bind_host == "127.0.0.1"
    assert endpoint.host == "192.168.1.10"
    assert endpoint.port == 32001
    assert pending.config.preserve_bugs is False


def test_net_host_lockstep_quests_requires_quest_level(mocker, tmp_path: Path) -> None:
    mocker.patch.object(game, "run_game", side_effect=lambda _config: None)
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
            "--netcode",
            "lockstep",
            "--base-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert "quest level is required" in result.output


def test_net_join_lockstep_builds_pending_join_session(mocker, tmp_path: Path) -> None:
    run_game = mocker.patch.object(game, "run_game")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "join",
            "--netcode",
            "lockstep",
            "--host",
            "192.168.1.42",
            "--port",
            "31993",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_game.assert_called_once()
    config = run_game.call_args.args[0]
    pending = config.pending_network_session
    assert pending is not None
    assert pending.role == "join"
    assert pending.auto_start is True
    assert pending.config.mode == "survival"
    assert pending.config.netcode_mode == "lockstep"
    endpoint = pending.config.endpoint
    assert endpoint.host == "192.168.1.42"
    assert endpoint.port == 31993


def test_net_host_lockstep_rtx_flag_enables_rtx_mode(mocker, tmp_path: Path) -> None:
    run_game = mocker.patch.object(game, "run_game")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "host",
            "--mode",
            "survival",
            "--players",
            "1",
            "--netcode",
            "lockstep",
            "--rtx",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_game.assert_called_once()
    config = run_game.call_args.args[0]
    assert config.rtx is True
