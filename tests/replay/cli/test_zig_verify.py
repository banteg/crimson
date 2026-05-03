from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import msgspec
import zstandard as zstd
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot, dump_replay
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand
from crimson.weapons import WeaponId

from ._helpers import (
    build_replay,
    build_typo_submit_replay,
    inject_tick_commands,
    write_current_bad_claimed_stats_replay,
    write_current_bad_tick_player_count_replay,
    write_current_missing_perk_choice_replay,
    write_current_missing_quest_level_replay,
    write_current_mode_player_count_replay,
    write_current_string_quest_level_replay,
    write_current_typo_event_replay,
    write_legacy_out_of_order_event_replay,
    write_replay,
)


def test_zig_replay_verify_respects_max_ticks_partial_run_contract(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_full_payload_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_human_output_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_result = _run_python_replay_verify_process([str(replay_path)])
    zig_result = _run_zig_replay_verify_process([str(replay_path)])

    assert python_result.exit_code == 0, python_result.output
    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == python_result.output


def test_zig_replay_verify_matches_python_full_payload_on_quest_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=3, quest_level="1.1")
    replay_path = write_replay(tmp_path, replay=replay, name="quest.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_accepts_current_string_quest_level(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=2, quest_level="1.1")
    replay_path = write_current_string_quest_level_replay(
        tmp_path,
        replay=replay,
        name="quest-string-level.crd",
        quest_level="1.1",
    )

    zig_payload = _run_zig_replay_verify([str(replay_path), "--format", "json"])

    assert zig_payload["status"] == "ok"
    run_result = cast("dict[str, object]", zig_payload["run_result"])
    assert run_result["game_mode_id"] == int(GameMode.QUESTS)
    assert run_result["ticks"] == 2


def test_zig_replay_verify_matches_python_rush_spawn_boundary(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.RUSH, ticks=16)
    replay_path = write_replay(tmp_path, replay=replay, name="rush.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_ignores_rush_stale_perk_pick_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.RUSH, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="rush-stale-perk-pick.crd")

    python_payload = _run_python_replay_verify([str(replay_path), "--format", "json"])
    zig_payload = _run_zig_replay_verify([str(replay_path), "--format", "json"])

    assert zig_payload == python_payload


def test_zig_replay_verify_accepts_rush_perk_menu_open_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.RUSH, ticks=1)
    inject_tick_commands(replay, 0, [PerkMenuOpenCommand(player_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="rush-perk-menu-open.crd")

    python_payload = _run_python_replay_verify([str(replay_path), "--format", "json"])
    zig_payload = _run_zig_replay_verify([str(replay_path), "--format", "json"])

    assert zig_payload == python_payload


def test_zig_replay_verify_counts_typo_submit_stats_like_python(tmp_path: Path) -> None:
    replay = build_typo_submit_replay(word="reload")
    replay_path = write_replay(tmp_path, replay=replay, name="typo-submit.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    python_run_result = cast("dict[str, object]", python_payload["run_result"])
    assert python_run_result["shots_fired"] == 1
    assert python_run_result["shots_hit"] == 0
    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_partial_typo_rng_state(tmp_path: Path) -> None:
    replay = build_typo_submit_replay(word="reload")
    replay_path = write_replay(tmp_path, replay=replay, name="typo-submit.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "1"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "1"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_writes_json_out_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    json_out = tmp_path / "reports" / "verify.json"

    result = _run_zig_replay_verify_process(
        [str(replay_path), "--format", "json", "--json-out", str(json_out)],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    stdout_payload = json.loads(result.stdout)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert file_payload == stdout_payload


def test_zig_replay_verify_reports_header_claim_mismatch_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=2,
                elapsed_ms=1,
                score_xp=999,
                kills=4,
                most_used_weapon_id=WeaponId.PISTOL,
                shots_fired=2,
                shots_hit=1,
            ),
        ),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-claimed-bad.crd")

    python_result = _run_python_replay_verify_process([str(replay_path), "--format", "json"])
    zig_result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert python_result.exit_code == 3, python_result.output
    assert zig_result.returncode == 3, dbg_record._command_detail(zig_result)
    assert json.loads(zig_result.stdout) == json.loads(python_result.output)


def test_zig_replay_verify_reports_header_claim_mismatch_human_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=2,
                elapsed_ms=1,
                score_xp=999,
                kills=4,
                most_used_weapon_id=WeaponId.PISTOL,
                shots_fired=2,
                shots_hit=1,
            ),
        ),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-claimed-bad.crd")

    python_result = _run_python_replay_verify_process([str(replay_path)])
    zig_result = _run_zig_replay_verify_process([str(replay_path)])

    assert python_result.exit_code == 3, python_result.output
    assert zig_result.returncode == 3, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == python_result.output


def test_zig_replay_verify_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify([str(replay_path), "--format", "json"])
    zig_payload = _run_zig_replay_verify([str(replay_path), "--format", "json"])

    assert zig_payload == python_payload


def test_zig_replay_verify_rejects_non_crd_extension(tmp_path: Path) -> None:
    replay_path = tmp_path / "survival.txt"
    replay_path.write_bytes(b"not checked before extension validation")

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay file must use .crd extension" in result.stderr


def test_zig_replay_verify_reports_old_format_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(replay.header, replay_format_version=10),
    )
    replay_path = tmp_path / "old-format.crd"
    replay_path.write_bytes(msgspec.msgpack.encode(replay))

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay format version is not supported" in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_reports_legacy_json_as_replay_failure(tmp_path: Path) -> None:
    replay_path = tmp_path / "legacy-json.crd"
    replay_path.write_bytes(b' \n{"header":{"game_mode_id":1,"seed":1}}')

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: legacy JSON replay format is unsupported; regenerate the replay"
        in result.stderr
    )
    assert "msgpack" not in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_reports_invalid_claimed_stats_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_bad_claimed_stats_replay(
        tmp_path,
        replay=replay,
        name="bad-claimed-stats.crd",
    )

    python_result = _run_python_replay_verify_process([str(replay_path), "--format", "json"])
    zig_result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert python_result.exit_code == 1, python_result.output
    assert zig_result.returncode == 1, dbg_record._command_detail(zig_result)
    assert (
        "replay verification failed: replay header claimed_stats.shots_hit must be <= "
        "claimed_stats.shots_fired"
    ) in zig_result.stderr
    assert zig_result.stderr == python_result.output
    assert "native runtime limitation" not in zig_result.stderr


def test_zig_replay_verify_reports_tick_player_count_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_bad_tick_player_count_replay(
        tmp_path,
        replay=replay,
        name="bad-tick-player-count.crd",
    )

    python_result = _run_python_replay_verify_process([str(replay_path), "--format", "json"])
    zig_result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert python_result.exit_code == 1, python_result.output
    assert zig_result.returncode == 1, dbg_record._command_detail(zig_result)
    assert "replay verification failed: replay tick 0 has 0 players, expected 1" in zig_result.stderr
    assert zig_result.stderr == python_result.output
    assert "canonical wire shape" not in zig_result.stderr
    assert "native runtime limitation" not in zig_result.stderr


def test_zig_replay_verify_reports_event_shape_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_missing_perk_choice_replay(
        tmp_path,
        replay=replay,
        name="missing-perk-choice.crd",
    )

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay event perk_pick missing choice_index: tick=0 event_index=0"
        in result.stderr
    )
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_verify_reports_unknown_command_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "network_ping", "player_index": 0}]
    replay_path = tmp_path / "unknown-command.crd"
    replay_path.write_bytes(msgspec.msgpack.encode(payload))

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay events include an unknown command kind" in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_reports_missing_quest_level_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_missing_quest_level_replay(
        tmp_path,
        replay=replay,
        name="missing-quest-level.crd",
    )

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: quest replays require a valid header.quest_level" in result.stderr
    assert "native runtime limitation" not in result.stderr
    assert "native runtime" not in result.stderr
    assert "InvalidQuestSpawnTable" not in result.stderr


def test_zig_replay_verify_reports_single_player_mode_count_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    cases = (
        (GameMode.TYPO, "typo-multiplayer.crd", "Typ-o replays require player_count == 1"),
        (GameMode.TUTORIAL, "tutorial-multiplayer.crd", "tutorial replays require player_count == 1"),
    )

    for mode, name, detail in cases:
        replay_path = write_current_mode_player_count_replay(
            tmp_path,
            replay=replay,
            name=name,
            mode=mode,
            player_count=2,
        )

        result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

        assert result.returncode == 1
        assert result.stdout == ""
        assert f"replay verification failed: {detail}" in result.stderr
        assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_reports_event_player_index_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "perk_menu_open", "player_index": 1}]
    replay_path = tmp_path / "event-player-index.crd"
    replay_path.write_bytes(msgspec.msgpack.encode(payload))

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay event player_index out of range: 1 "
        "(player_count=1, tick=0, event=perk_menu_open)"
    ) in result.stderr
    assert "ticks_processed=" not in result.stderr


def test_zig_replay_verify_reports_event_ordering_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_legacy_out_of_order_event_replay(tmp_path, replay=replay, name="event-order.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay events are not ordered in canonical tick order: "
        "tick=1 follows tick=2 (event_index=1, event=perk_menu_open)"
    ) in result.stderr
    assert "ticks_processed=" not in result.stderr


def test_zig_replay_verify_reports_event_kind_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_typo_event_replay(tmp_path, replay=replay, name="event-kind.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay event kind invalid for game mode: "
        "event=typo_char tick=0 event_index=0 game_mode=survival"
    ) in result.stderr
    assert "replay events include invalid kinds or values for this mode" not in result.stderr


def test_zig_replay_verify_reports_old_ruleset_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(replay.header, game_version="0.6.9"),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="old-ruleset.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: native replay tools require latest ruleset replays" in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_rejects_removed_score_options_as_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--submitted-score", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid replay verify args: --submitted-score" in result.stderr


def test_zig_replay_verify_rejects_removed_lenient_events_option_as_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--lenient-events"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid replay verify args: --lenient-events" in result.stderr


def test_zig_replay_verify_rejects_removed_strict_events_option_as_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--strict-events"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid replay verify args: --strict-events" in result.stderr


def _run_python_replay_verify(args: list[str]) -> dict[str, object]:
    result = _run_python_replay_verify_process(args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _run_python_replay_verify_process(args: list[str]):
    runner = CliRunner()
    result = runner.invoke(app, ["replay", "verify", *args])
    return result


def _run_zig_replay_verify(args: list[str]) -> dict[str, object]:
    verify_run = _run_zig_replay_verify_process(args)
    assert verify_run.returncode == 0, dbg_record._command_detail(verify_run)
    return json.loads(verify_run.stdout)


def _run_zig_replay_verify_process(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "verify", *args],
        cwd=dbg_record._REPO_ROOT,
    )
