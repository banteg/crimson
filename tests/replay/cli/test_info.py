from __future__ import annotations

import json
from pathlib import Path

import msgspec
from click import unstyle
from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand, RngBurnOperation
from crimson.weapons import WeaponId

from ._helpers import build_replay, inject_tick_commands, write_replay


def test_replay_info_human_success_outputs_timeline_header(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "info", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output
    assert f"replay={replay_path}" in result.output
    assert "mode=survival" in result.output
    assert "ticks=3" in result.output
    assert "events=" in result.output


def test_replay_info_json_output_payload_ok_schema_v2(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "info", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 2
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert payload["summary"]["game_mode_id"] == int(GameMode.SURVIVAL)
    assert payload["summary"]["tick_rate"] == 60
    assert payload["summary"]["ticks_simulated"] == 2
    assert payload["summary"]["elapsed_ms"] >= 0
    assert payload["summary"]["player_count"] == 1
    assert payload["summary"]["event_count"] >= 0
    assert isinstance(payload["summary"]["event_counts_by_kind"], dict)
    assert isinstance(payload["timeline"], list)


def test_replay_info_json_out_works_for_human_and_json(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    human_out = tmp_path / "replay-info-human.json"
    json_out = tmp_path / "replay-info-json.json"

    human_result = runner.invoke(
        app,
        [
            "replay",
            "info",
            str(replay_path),
            "--json-out",
            str(human_out),
        ],
    )
    assert human_result.exit_code == 0, human_result.output
    assert "json_report=" in human_result.output
    assert json.loads(human_out.read_text(encoding="utf-8"))["status"] == "ok"

    json_result = runner.invoke(
        app,
        [
            "replay",
            "info",
            str(replay_path),
            "--format",
            "json",
            "--json-out",
            str(json_out),
        ],
    )
    assert json_result.exit_code == 0, json_result.output
    stdout_payload = json.loads(json_result.output)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert stdout_payload["status"] == "ok"
    assert file_payload == stdout_payload


def test_replay_info_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "info", str(replay_path)])

    assert result.exit_code == 0


def test_replay_info_reports_snapshot_diff_events(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_info as replay_info_mod

    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    real_step_tick = replay_info_mod.PlaybackDriver.step_tick

    def _step_tick_with_weapon_change(self, tick_index: int):
        self.world.players[0].weapon.weapon_id = WeaponId.ASSAULT_RIFLE
        return real_step_tick(self, tick_index)

    mocker.patch.object(
        replay_info_mod.PlaybackDriver,
        "step_tick",
        autospec=True,
        side_effect=_step_tick_with_weapon_change,
    )

    result = runner.invoke(app, ["replay", "info", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert any(event["kind"] == "weapon_change" for event in payload["timeline"])


def test_replay_info_rejects_removed_lenient_events_option(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "info", str(replay_path), "--lenient-events"])

    assert result.exit_code == 2
    output = unstyle(result.output)
    assert "No such option" in output
    assert "--lenient-events" in output


def test_replay_info_supports_survival_rush_quest_modes(tmp_path: Path) -> None:
    survival = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    rush = build_replay(mode=GameMode.RUSH, ticks=2)
    quest = build_replay(mode=GameMode.QUESTS, ticks=2, seed=101, quest_level="1.1")
    runner = CliRunner()

    cases = [
        ("survival.crd", survival, int(GameMode.SURVIVAL)),
        ("rush.crd", rush, int(GameMode.RUSH)),
        ("quest.crd", quest, int(GameMode.QUESTS)),
    ]
    for filename, replay, mode_id in cases:
        replay_path = write_replay(tmp_path, replay=replay, name=filename)
        result = runner.invoke(app, ["replay", "info", str(replay_path), "--format", "json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "ok"
        assert payload["summary"]["game_mode_id"] == mode_id
        assert payload["summary"]["ticks_simulated"] == 2


def test_replay_info_player_index_filter_limits_events(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1, player_count=2)
    inject_tick_commands(replay, 0, [PerkMenuOpenCommand(player_index=0), PerkMenuOpenCommand(player_index=1)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "info",
            str(replay_path),
            "--format",
            "json",
            "--verbose",
            "--player-index",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    player_events = [event for event in payload["timeline"] if event["player_index"] is not None]
    assert player_events
    assert all(int(event["player_index"]) == 1 for event in player_events)


def test_replay_info_default_excludes_extra_kinds_and_verbose_includes(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkMenuOpenCommand(player_index=0)])
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        prelude=[RngBurnOperation(draws=2), *replay.ticks[0].prelude],
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    default_result = runner.invoke(
        app,
        [
            "replay",
            "info",
            str(replay_path),
            "--format",
            "json",
        ],
    )
    assert default_result.exit_code == 0, default_result.output
    default_payload = json.loads(default_result.output)
    default_kinds = {event["kind"] for event in default_payload["timeline"]}
    assert "perk_menu_open" not in default_kinds
    assert "rng_burn" not in default_kinds

    verbose_result = runner.invoke(
        app,
        [
            "replay",
            "info",
            str(replay_path),
            "--format",
            "json",
            "--verbose",
        ],
    )
    assert verbose_result.exit_code == 0, verbose_result.output
    verbose_payload = json.loads(verbose_result.output)
    verbose_kinds = {event["kind"] for event in verbose_payload["timeline"]}
    assert "perk_menu_open" in verbose_kinds
    assert "rng_burn" in verbose_kinds
    rng_event = next(event for event in verbose_payload["timeline"] if event["kind"] == "rng_burn")
    assert rng_event["data"] == {"draws": 2}
