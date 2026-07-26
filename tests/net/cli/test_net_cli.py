from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import crimson.logging as game_logging
from crimson import game
from crimson.cli import app
from crimson.net import relay_service


def test_net_host_command_builds_pending_network_session(mocker, tmp_path: Path) -> None:
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
            "--relay-host",
            "203.0.113.10",
            "--relay-port",
            "32011",
            "--room-code",
            "ab12",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_game.assert_called_once()
    config = run_game.call_args.args[0]
    pending = config.pending_network_session
    assert pending is not None
    assert config.pending_network_session is pending
    assert pending.role == "host"
    assert pending.auto_start is True
    assert pending.config.mode == "rush"
    assert pending.config.player_count == 3
    assert pending.config.netcode_mode == "rollback"
    endpoint = pending.config.endpoint
    assert endpoint.relay_host == "203.0.113.10"
    assert endpoint.relay_port == 32011
    assert endpoint.room_code == "ab12"


def test_net_host_quests_requires_quest_level(mocker, tmp_path: Path) -> None:
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
            "--base-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert "quest level is required" in result.output


def test_net_join_command_builds_pending_join_session(mocker, tmp_path: Path) -> None:
    run_game = mocker.patch.object(game, "run_game")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "join",
            "--code",
            "rm42",
            "--relay-host",
            "198.51.100.15",
            "--relay-port",
            "31999",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_game.assert_called_once()
    config = run_game.call_args.args[0]
    pending = config.pending_network_session
    assert pending is not None
    assert config.pending_network_session is pending
    assert pending.role == "join"
    assert pending.auto_start is True
    assert pending.config.netcode_mode == "rollback"
    endpoint = pending.config.endpoint
    assert endpoint.room_code == "rm42"
    assert endpoint.relay_host == "198.51.100.15"
    assert endpoint.relay_port == 31999


def test_net_join_lockstep_requires_host(mocker, tmp_path: Path) -> None:
    mocker.patch.object(game, "run_game", side_effect=lambda _config: None)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "net",
            "join",
            "--code",
            "rm42",
            "--netcode",
            "lockstep",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 2
    assert "host is required in lockstep mode" in result.output


def test_net_host_rtx_flag_enables_rtx_mode(mocker, tmp_path: Path) -> None:
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
            "--rtx",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_game.assert_called_once()
    config = run_game.call_args.args[0]
    assert config.rtx is True


def test_relay_serve_command_constructs_relay_server(mocker, tmp_path: Path) -> None:
    default_log = tmp_path / "logs" / "relay" / "auto.log"
    explicit_log = tmp_path / "logs" / "relay" / "relay.log"

    mocker.patch.object(game_logging, "default_component_log_path", side_effect=lambda **_kwargs: default_log)
    configure_component_logging = mocker.patch.object(
        game_logging,
        "configure_component_logging",
        side_effect=lambda *, logger_name, component, log_file, level: Path(log_file),
    )
    relay_server = mocker.Mock()
    relay_server_cls = mocker.Mock(return_value=relay_server)
    mocker.patch.object(relay_service, "RelayServer", relay_server_cls)

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
            "--log-level",
            "info",
            "--log-file",
            str(explicit_log),
        ],
    )

    assert result.exit_code == 0, result.output
    relay_server_cls.assert_called_once()
    cfg = relay_server_cls.call_args.args[0]
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.bind_port == 32021
    relay_server.serve_forever.assert_called_once_with(tick_ms=11)
    configure_component_logging.assert_called_once_with(
        logger_name="crimson.relay",
        component="relay",
        log_file=explicit_log,
        level="info",
    )
    assert str(explicit_log) in result.output


def test_relay_serve_command_rejects_invalid_log_level(mocker, tmp_path: Path) -> None:
    class _FakeRelayServer:
        def __init__(self, _cfg) -> None:
            pass

        def serve_forever(self, *, tick_ms: int) -> None:
            _ = tick_ms

    mocker.patch.object(relay_service, "RelayServer", _FakeRelayServer)

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
            "--log-level",
            "chatty",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 2
    assert "unsupported log level" in result.output
