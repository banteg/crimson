from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import msgspec
import zstandard as zstd

import crimson.dbg.record as dbg_record
from crimson.game_modes import GameMode
from crimson.replay import dump_replay
from crimson.replay.checkpoints import ReplayDeathLedgerEntry, dump_checkpoints_file, load_checkpoints_file

from ._helpers import (
    build_replay,
    build_typo_submit_replay,
    write_checkpoint_sidecar,
    write_current_bad_tick_player_count_replay,
    write_current_missing_perk_choice_replay,
    write_current_typo_event_replay,
    write_current_unknown_command_replay,
    write_legacy_out_of_order_event_replay,
    write_replay,
)


def test_zig_replay_diff_checkpoints_accepts_python_sidecars(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-copy.crd.chk"
    shutil.copyfile(sidecar_a, sidecar_b)

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match" in result.stdout


def test_zig_replay_verify_checkpoints_accepts_python_sidecar(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    write_checkpoint_sidecar(replay_path, replay)

    result = _run_zig_replay_verify_checkpoints([str(replay_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match; ticks=3 score_xp=0 kills=0" in result.stdout


def test_zig_replay_verify_checkpoints_accepts_two_player_sidecar(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3, player_count=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")
    write_checkpoint_sidecar(replay_path, replay)

    result = _run_zig_replay_verify_checkpoints([str(replay_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match; ticks=3 score_xp=0 kills=0" in result.stdout


def test_zig_replay_verify_checkpoints_accepts_rush_sidecar(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.RUSH, ticks=16)
    replay_path = write_replay(tmp_path, replay=replay, name="rush.crd")
    write_checkpoint_sidecar(replay_path, replay)

    result = _run_zig_replay_verify_checkpoints([str(replay_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match; ticks=16 score_xp=0 kills=0" in result.stdout


def test_zig_replay_verify_checkpoints_accepts_quest_sidecar(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=16, quest_level="1.1")
    replay_path = write_replay(tmp_path, replay=replay, name="quest.crd")
    write_checkpoint_sidecar(replay_path, replay)

    result = _run_zig_replay_verify_checkpoints([str(replay_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match; ticks=16 score_xp=0 kills=0" in result.stdout


def test_zig_replay_verify_checkpoints_accepts_tutorial_sidecar(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.TUTORIAL, ticks=16)
    replay_path = write_replay(tmp_path, replay=replay, name="tutorial.crd")
    write_checkpoint_sidecar(replay_path, replay)

    result = _run_zig_replay_verify_checkpoints([str(replay_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match; ticks=16 score_xp=0 kills=0" in result.stdout


def test_zig_replay_verify_checkpoints_accepts_typo_sidecar(tmp_path: Path) -> None:
    replay = build_typo_submit_replay(word="reload")
    replay_path = write_replay(tmp_path, replay=replay, name="typo.crd")
    write_checkpoint_sidecar(replay_path, replay)

    result = _run_zig_replay_verify_checkpoints([str(replay_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match" in result.stdout


def test_zig_replay_verify_checkpoints_reports_mismatch(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar = write_checkpoint_sidecar(replay_path.with_name("survival-mutated.crd"), replay, mutate_checkpoint=True)

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert "checkpoint mismatch at tick=0" in result.stderr
    assert "score_xp expected=999999 actual=0" in result.stderr


def test_zig_replay_verify_checkpoints_reports_tick_player_count_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    sidecar_source = write_replay(tmp_path, replay=replay, name="sidecar-source.crd")
    sidecar = write_checkpoint_sidecar(sidecar_source, replay)
    replay_path = write_current_bad_tick_player_count_replay(
        tmp_path,
        replay=replay,
        name="bad-tick-player-count.crd",
    )

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay tick 0 has 0 players, expected 1" in result.stderr
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_verify_checkpoints_reports_event_shape_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    sidecar_source = write_replay(tmp_path, replay=replay, name="sidecar-source.crd")
    sidecar = write_checkpoint_sidecar(sidecar_source, replay)
    replay_path = write_current_missing_perk_choice_replay(
        tmp_path,
        replay=replay,
        name="missing-perk-choice.crd",
    )

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay event perk_pick missing choice_index: tick=0 event_index=0"
        in result.stderr
    )
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_verify_checkpoints_reports_event_player_index_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="event-player-index.crd")
    sidecar = write_checkpoint_sidecar(replay_path, replay)
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "perk_menu_open", "player_index": 1}]
    replay_path.write_bytes(msgspec.msgpack.encode(payload))

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay event player_index out of range: 1 "
        "(player_count=1, tick=0, event=perk_menu_open)"
    ) in result.stderr
    assert "replay events include an out-of-range player index" not in result.stderr


def test_zig_replay_verify_checkpoints_reports_event_ordering_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    sidecar_source = write_replay(tmp_path, replay=replay, name="event-order-source.crd")
    sidecar = write_checkpoint_sidecar(sidecar_source, replay)
    replay_path = write_legacy_out_of_order_event_replay(tmp_path, replay=replay, name="event-order.crd")

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay events are not ordered in canonical tick order: "
        "tick=1 follows tick=2 (event_index=1, event=perk_menu_open)"
    ) in result.stderr
    assert "replay events are not ordered in canonical tick order (progress:" not in result.stderr


def test_zig_replay_verify_checkpoints_reports_event_kind_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    sidecar_source = write_replay(tmp_path, replay=replay, name="event-kind-source.crd")
    sidecar = write_checkpoint_sidecar(sidecar_source, replay)
    replay_path = write_current_typo_event_replay(tmp_path, replay=replay, name="event-kind.crd")

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay verification failed: replay event kind invalid for game mode: "
        "event=typo_char tick=0 event_index=0 game_mode=survival"
    ) in result.stderr
    assert "replay events include kinds or values invalid for this mode" not in result.stderr


def test_zig_replay_verify_checkpoints_reports_unknown_command_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    sidecar_source = write_replay(tmp_path, replay=replay, name="unknown-command-source.crd")
    sidecar = write_checkpoint_sidecar(sidecar_source, replay)
    replay_path = write_current_unknown_command_replay(tmp_path, replay=replay, name="unknown-command.crd")

    result = _run_zig_replay_verify_checkpoints([str(replay_path), "--checkpoints", str(sidecar)])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay events include an unknown command kind" in result.stderr
    assert "native replay run" not in result.stderr


def test_zig_replay_diff_checkpoints_reports_state_mismatch(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = write_checkpoint_sidecar(replay_path.with_name("survival-mutated.crd"), replay, mutate_checkpoint=True)

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 1
    assert "checkpoint mismatch at tick=0" in result.stderr
    assert "score_xp expected=0 actual=999999" in result.stderr


def test_zig_replay_diff_checkpoints_reports_player_field_mismatch(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-player-health.crd.chk"

    payload = load_checkpoints_file(sidecar_a)
    checkpoints = list(payload.checkpoints)
    players = list(checkpoints[0].players)
    players[0] = msgspec.structs.replace(players[0], health=float(players[0].health) - 1.0)
    checkpoints[0] = msgspec.structs.replace(checkpoints[0], players=players)
    dump_checkpoints_file(sidecar_b, msgspec.structs.replace(payload, checkpoints=checkpoints))

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 1
    assert "checkpoint mismatch at tick=0" in result.stderr
    assert "first state diff: players[0].health" in result.stderr


def test_zig_replay_diff_checkpoints_reports_event_field_mismatch(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-event-sfx.crd.chk"

    payload = load_checkpoints_file(sidecar_a)
    checkpoints = list(payload.checkpoints)
    events = msgspec.structs.replace(checkpoints[0].events, sfx_count=int(checkpoints[0].events.sfx_count) + 1)
    checkpoints[0] = msgspec.structs.replace(checkpoints[0], events=events)
    dump_checkpoints_file(sidecar_b, msgspec.structs.replace(payload, checkpoints=checkpoints))

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 1
    assert "checkpoint mismatch at tick=0" in result.stderr
    assert "first state diff: events.sfx_count" in result.stderr


def test_zig_replay_diff_checkpoints_reports_event_sfx_head_summary(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-event-sfx-head.crd.chk"

    payload = load_checkpoints_file(sidecar_a)
    checkpoints = list(payload.checkpoints)
    events = msgspec.structs.replace(
        checkpoints[0].events,
        sfx_head=[*checkpoints[0].events.sfx_head, "menu_click"],
    )
    checkpoints[0] = msgspec.structs.replace(checkpoints[0], events=events)
    dump_checkpoints_file(sidecar_b, msgspec.structs.replace(payload, checkpoints=checkpoints))

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 1
    assert "checkpoint mismatch at tick=0" in result.stderr
    assert "first state diff: events.sfx_head._len" in result.stderr
    assert "events expected=(hits=0, pickups=0, sfx=0, head=[])" in result.stderr
    assert "actual=(hits=0, pickups=0, sfx=0, head=['menu_click'])" in result.stderr


def test_zig_replay_diff_checkpoints_reports_first_death_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-death.crd.chk"

    payload = load_checkpoints_file(sidecar_a)
    checkpoints = list(payload.checkpoints)
    deaths = [
        ReplayDeathLedgerEntry(
            creature_index=7,
            type_id=2,
            reward_value=3.5,
            xp_awarded=4,
            owner_id=1,
        ),
    ]
    checkpoints[0] = msgspec.structs.replace(checkpoints[0], deaths=deaths)
    dump_checkpoints_file(sidecar_b, msgspec.structs.replace(payload, checkpoints=checkpoints))

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 1
    assert "checkpoint mismatch at tick=0" in result.stderr
    assert "first state diff: deaths._len expected=0 actual=1" in result.stderr
    assert "first death expected=[] actual=[ReplayDeathLedgerEntry(" in result.stderr
    assert "creature_index=7, type_id=2, reward_value=3.5, xp_awarded=4, owner_id=1" in result.stderr


def test_zig_replay_diff_checkpoints_preserves_rng_only_success(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-rng-only.crd.chk"

    payload = load_checkpoints_file(sidecar_a)
    checkpoints = list(payload.checkpoints)
    checkpoints[0] = msgspec.structs.replace(checkpoints[0], rng_state=int(checkpoints[0].rng_state) + 1)
    dump_checkpoints_file(sidecar_b, msgspec.structs.replace(payload, checkpoints=checkpoints))

    result = _run_zig_replay_diff_checkpoints([str(sidecar_a), str(sidecar_b)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: 1 checkpoints match" in result.stdout
    assert "first rng-only divergence tick=0" in result.stdout


def test_zig_replay_diff_checkpoints_emits_json_and_artifact(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "survival-copy.crd.chk"
    json_out = tmp_path / "artifacts" / "diff.json"
    shutil.copyfile(sidecar_a, sidecar_b)

    result = _run_zig_replay_diff_checkpoints(
        [
            str(sidecar_a),
            str(sidecar_b),
            "--format=json",
            "--json-out",
            str(json_out),
        ],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["command"] == "diff-checkpoints"
    assert payload["expected"] == str(sidecar_a)
    assert payload["actual"] == str(sidecar_b)
    assert payload["summary"] == {
        "expected_count": 1,
        "actual_count": 1,
        "checked_count": 1,
        "rng_only_drift_tick": None,
    }
    assert json.loads(json_out.read_text(encoding="utf-8")) == payload


def test_zig_replay_verify_checkpoints_emits_json_and_artifact(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar = write_checkpoint_sidecar(replay_path, replay)
    json_out = tmp_path / "artifacts" / "verify.json"

    result = _run_zig_replay_verify_checkpoints(
        [
            str(replay_path),
            "--checkpoints",
            str(sidecar),
            "--format",
            "json",
            "--json-out",
            str(json_out),
            "--max-ticks=3",
            "--trace-rng",
        ],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["command"] == "verify-checkpoints"
    assert payload["replay"] == str(replay_path)
    assert payload["checkpoints"] == str(sidecar)
    assert payload["summary"] == {
        "checkpoint_count": 1,
        "checked_count": 1,
        "ticks": 3,
        "score_xp": 0,
        "kills": 0,
        "rng_only_drift_tick": None,
        "max_ticks": 3,
        "trace_rng": True,
    }
    assert json.loads(json_out.read_text(encoding="utf-8")) == payload


def _run_zig_replay_diff_checkpoints(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "diff-checkpoints", *args],
        cwd=dbg_record._REPO_ROOT,
    )


def _run_zig_replay_verify_checkpoints(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "verify-checkpoints", *args],
        cwd=dbg_record._REPO_ROOT,
    )
