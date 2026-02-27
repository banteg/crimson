from __future__ import annotations

import stat
import textwrap
from pathlib import Path
from typing import cast

from typer.testing import CliRunner

import crimson.dbg.diff as dbg_diff
from crimson.cli import app
from crimson.dbg.policy import resolve_parity_policy
from crimson.dbg.trace import TraceReader, load_trace, write_trace
from crimson.game_modes import GameMode
from crimson.original.capture import dump_capture
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay
from crimson.sim.input import PlayerInput
from grim.geom import Vec2
from tests.builders.capture import (
    build_capture_creature_sample,
    build_capture_event_head_creature_update_micro_window,
    build_capture_file,
    build_capture_rng_head_entry,
    build_capture_tick,
)


def _write_capture(path: Path) -> Path:
    tick0 = build_capture_tick(
        tick_index=0,
        elapsed_ms=0,
        event_heads=[build_capture_event_head_creature_update_micro_window(slot=0)],
    )
    tick1 = build_capture_tick(
        tick_index=1,
        elapsed_ms=16,
        event_heads=[build_capture_event_head_creature_update_micro_window(slot=1)],
    )
    tick0.samples.creatures = [build_capture_creature_sample(index=5)]
    tick1.samples.creatures = [build_capture_creature_sample(index=5)]
    tick0.rng.head = [build_capture_rng_head_entry()]
    tick1.rng.head = [build_capture_rng_head_entry()]
    capture = build_capture_file(ticks=[tick0, tick1])
    dump_capture(path, capture)
    return path


def test_dbg_import_capture_and_health(tmp_path: Path) -> None:
    capture_path = _write_capture(tmp_path / "capture.json")
    trace_path = tmp_path / "capture.cdt"
    runner = CliRunner()

    import_result = runner.invoke(
        app,
        ["dbg", "import-capture", str(capture_path), "--out", str(trace_path)],
    )
    assert import_result.exit_code == 0, import_result.output
    assert trace_path.exists()
    assert "channels=" in import_result.output
    assert "entity_samples" in import_result.output

    health_result = runner.invoke(
        app,
        ["dbg", "health", str(trace_path), "--strict"],
    )
    assert health_result.exit_code == 0, health_result.output
    assert "movement_root_cause_ready=True" in health_result.output


def _write_replay(path: Path, *, ticks: int = 3) -> Path:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    path.write_bytes(dump_replay(recorder.finish()))
    return path


def _as_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    out: dict[str, object] = {}
    for key, item in value.items():
        assert isinstance(key, str)
        out[key] = item
    return out


def test_dbg_record_standard_profile(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--profile", "standard"],
    )
    assert result.exit_code == 0, result.output
    assert "channels=" in result.output
    assert "checkpoint" in result.output
    assert "rng_marks" in result.output
    assert "rng_stream_head" in result.output
    assert "entity_samples" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        assert "checkpoint" in tick0.channels
        assert "rng_marks" in tick0.channels
        assert "rng_stream_head" in tick0.channels
        assert "entity_samples" in tick0.channels


def test_dbg_record_full_profile_includes_event_and_micro_channels(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_full.crd")
    trace_path = tmp_path / "sample_full.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--profile", "full"],
    )
    assert result.exit_code == 0, result.output
    assert "rng_stream_head" in result.output
    assert "event_heads" in result.output
    assert "micro_traces" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        rng_stream_head = tick0.channels.get("rng_stream_head")
        assert isinstance(rng_stream_head, list)
        event_heads = tick0.channels.get("event_heads")
        assert isinstance(event_heads, list)
        micro_traces = tick0.channels.get("micro_traces")
        assert isinstance(micro_traces, list)


def _write_fake_zig_bin(path: Path) -> Path:
    script = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import json
        import pathlib
        import struct
        import sys

        args = sys.argv[1:]
        trace_path = None
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--debug-trace-jsonl":
                idx += 1
                trace_path = pathlib.Path(args[idx])
            idx += 1

        if trace_path is None:
            raise SystemExit("missing --debug-trace-jsonl")

        def f32_bits(value: float) -> int:
            return struct.unpack("<I", struct.pack("<f", float(value)))[0]

        def build_row(*, tick_index: int, elapsed_ms: int, rng_state: int, rng_base: int, score_xp: int, kills: int, creature_state_hash: int, projectile_state_hash: int, player_ammo: float, player_health: float, player_pos_x: float, player_pos_y: float, player_experience: int, player_shot_seq: int, perk_pending: int, debug_pending_nuke: int) -> dict[str, object]:
            return {
                "schema_version": 3,
                "tick_index": tick_index,
                "timing": {
                    "elapsed_ms": elapsed_ms,
                },
                "rng": {
                    "rng_state": rng_state,
                    "rng_after_perk_effects": rng_base + 0,
                    "rng_after_creatures": rng_base + 1,
                    "rng_after_projectiles": rng_base + 2,
                    "rng_after_secondary_projectiles": rng_base + 3,
                    "rng_after_particles": rng_base + 4,
                    "rng_after_player_update": rng_base + 5,
                    "rng_after_stage_spawns": rng_base + 6,
                    "rng_after_wave_spawns": rng_base + 7,
                    "rng_after_spawns": rng_base + 8,
                    "rng_after_bonus_update": rng_base + 9,
                },
                "summary": {
                    "score_xp": score_xp,
                    "kills": kills,
                    "shots_fired_p0": player_shot_seq,
                    "creature_count": 0,
                    "creature_active_index_sum": 0,
                    "creature_active_index_xor": 0,
                    "creature_state_hash": creature_state_hash,
                    "perk_pending": perk_pending,
                },
                "player": {
                    "player_weapon_id": 14,
                    "player_ammo_bits": f32_bits(player_ammo),
                    "player_health_bits": f32_bits(player_health),
                    "player_pos_x_bits": f32_bits(player_pos_x),
                    "player_pos_y_bits": f32_bits(player_pos_y),
                    "player_aim_x_bits": f32_bits(player_pos_x),
                    "player_aim_y_bits": f32_bits(player_pos_y),
                    "player_heading_bits": f32_bits(0.0),
                    "player_aim_heading_bits": f32_bits(0.0),
                    "player_move_speed_bits": f32_bits(0.0),
                    "player_turn_speed_bits": f32_bits(0.0),
                    "player_experience": player_experience,
                    "player_level": 1,
                    "player_reload_active": False,
                    "player_reload_timer_bits": f32_bits(0.0),
                    "player_shot_cooldown_bits": f32_bits(0.0),
                    "player_shot_seq": player_shot_seq,
                    "player_perk_counts": [0] * 58,
                    "player_hot_tempered_timer_bits": f32_bits(0.0),
                    "player_shield_timer_bits": f32_bits(0.0),
                    "player_man_bomb_timer_bits": f32_bits(0.0),
                    "player_fire_cough_timer_bits": f32_bits(0.0),
                    "player_living_fortress_timer_bits": f32_bits(0.0),
                    "perk_interval_hot_tempered_bits": f32_bits(0.0),
                    "perk_interval_man_bomb_bits": f32_bits(0.0),
                    "perk_interval_fire_cough_bits": f32_bits(0.0),
                },
                "bonuses": {
                    "bonus_timer_ms_by_id": [0] * 15,
                    "bonus_active_count": 0,
                    "active_entries": [],
                },
                "projectiles": {
                    "projectile_state_hash": projectile_state_hash,
                    "projectile_count": 0,
                    "projectile_active_index_sum": 0,
                    "projectile_active_index_xor": 0,
                    "projectile_hit_count": 0,
                    "projectile_first_hit_creature_index": -1,
                    "projectile_first_hit_projectile_index": -1,
                    "projectile_first_hit_type_id": 0,
                    "projectile_first_hit_origin_x_bits": f32_bits(0.0),
                    "projectile_first_hit_origin_y_bits": f32_bits(0.0),
                    "projectile_first_hit_pos_x_bits": f32_bits(0.0),
                    "projectile_first_hit_pos_y_bits": f32_bits(0.0),
                    "projectile_first_hit_target_size_bits": f32_bits(0.0),
                    "projectile_first_hit_target_x_bits": f32_bits(0.0),
                    "projectile_first_hit_target_y_bits": f32_bits(0.0),
                    "projectile_type_counts": [],
                    "entries": [],
                },
                "creatures": {
                    "entries": [],
                },
                "debug": {
                    "debug_pending_nuke": debug_pending_nuke,
                    "debug_nuke_kills_last": 0,
                    "debug_nuke_tick_last": -1,
                    "debug_nuke_kill_index_sum": 0,
                    "debug_last_picked_bonus_id": 0,
                    "debug_last_picked_bonus_amount": 0,
                },
            }

        trace_path.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            build_row(
                tick_index=0,
                elapsed_ms=0,
                rng_state=11,
                rng_base=100,
                score_xp=10,
                kills=0,
                creature_state_hash=1,
                projectile_state_hash=2,
                player_ammo=0.008,
                player_health=0.024,
                player_pos_x=0.8192,
                player_pos_y=0.8192,
                player_experience=10,
                player_shot_seq=0,
                perk_pending=0,
                debug_pending_nuke=0,
            ),
            build_row(
                tick_index=1,
                elapsed_ms=16,
                rng_state=12,
                rng_base=200,
                score_xp=20,
                kills=1,
                creature_state_hash=3,
                projectile_state_hash=4,
                player_ammo=0.0076,
                player_health=0.0236,
                player_pos_x=0.82,
                player_pos_y=0.8208,
                player_experience=20,
                player_shot_seq=1,
                perk_pending=1,
                debug_pending_nuke=1,
            ),
        ]
        with trace_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row))
                handle.write("\\n")

        payload = {
            "producer": {"impl": "zig", "impl_version": "test"},
            "run_result": {"ticks": 2},
        }
        sys.stdout.write(json.dumps(payload) + "\\n")
        """,
    )
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_dbg_record_zig_impl(tmp_path: Path, monkeypatch) -> None:
    replay_path = _write_replay(tmp_path / "sample_zig.crd")
    trace_path = tmp_path / "sample_zig.cdt"
    fake_zig = _write_fake_zig_bin(tmp_path / "fake-zig")
    monkeypatch.setenv("CRIMSON_DBG_ZIG_BIN", str(fake_zig))
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--impl", "zig", "--profile", "standard"],
    )
    assert result.exit_code == 0, result.output
    assert "channels=" in result.output
    assert "checkpoint" in result.output
    assert "zig_tick_trace" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        checkpoint = cast(dict[str, object], tick0.channels["checkpoint"])
        assert checkpoint["score_xp"] == 10
        assert checkpoint["state_hash"] == "zig:0000000000000001:0000000000000002"
        assert "zig_tick_trace" in tick0.channels


def test_dbg_diff_and_bisect(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    repro_trace = tmp_path / "repro.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    diff_result = runner.invoke(
        app,
        ["dbg", "diff", str(golden_trace), str(candidate_trace)],
    )
    assert diff_result.exit_code == 1, diff_result.output
    assert "result=diverged" in diff_result.output
    assert "checkpoint_field_mismatch" in diff_result.output

    bisect_result = runner.invoke(
        app,
        ["dbg", "bisect", str(golden_trace), str(candidate_trace), "--out", str(repro_trace)],
    )
    assert bisect_result.exit_code == 0, bisect_result.output
    assert "result=diverged" in bisect_result.output
    assert "first_bad_tick=1" in bisect_result.output
    assert repro_trace.exists()


def test_dbg_diff_hash_fields_respect_policy(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_hashes.crd")
    golden_trace = tmp_path / "golden_hashes.cdt"
    candidate_trace = tmp_path / "candidate_hashes.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick0 = next(row for row in ticks if int(row.tick_index) == 0)
    checkpoint = cast(dict[str, object], tick0.channels["checkpoint"])
    checkpoint["state_hash"] = "ffffffffffffffff"
    checkpoint["command_hash"] = "eeeeeeeeeeeeeeee"
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    relaxed_result = runner.invoke(
        app,
        [
            "dbg",
            "diff",
            str(golden_trace),
            str(candidate_trace),
            "--policy",
            "original_vs_python_default",
        ],
    )
    assert relaxed_result.exit_code == 0, relaxed_result.output
    assert "result=ok" in relaxed_result.output

    strict_result = runner.invoke(
        app,
        [
            "dbg",
            "diff",
            str(golden_trace),
            str(candidate_trace),
            "--policy",
            "python_vs_rust_strict",
        ],
    )
    assert strict_result.exit_code == 1, strict_result.output
    assert "result=diverged" in strict_result.output
    assert ("command_hash_mismatch" in strict_result.output) or ("state_hash_mismatch" in strict_result.output)


def test_dbg_diff_python_vs_zig_core_policy_ignores_untracked_channels(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_core.crd")
    golden_trace = tmp_path / "golden_core.cdt"
    candidate_trace = tmp_path / "candidate_core.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick0 = next(row for row in ticks if int(row.tick_index) == 0)
    tick0.channels.pop("entity_samples", None)
    checkpoint = cast(dict[str, object], tick0.channels["checkpoint"])
    checkpoint["state_hash"] = "ffffffffffffffff"
    checkpoint["command_hash"] = "eeeeeeeeeeeeeeee"
    checkpoint["players"] = [
        {
            "pos": {"x": 12345.0, "y": 67890.0},
            "health": 1.0,
            "weapon_id": 99,
            "ammo": 2.0,
            "experience": 3,
            "level": 4,
        },
    ]
    checkpoint["perk"] = {
        "pending_count": 0,
        "choices_dirty": False,
        "choices": [1, 2, 3],
        "player_nonzero_counts": [[[1, 2]]],
    }
    checkpoint["events"] = {
        "hit_count": 999,
        "pickup_count": 999,
        "sfx_count": 999,
        "sfx_head": ["x"],
    }
    checkpoint["deaths"] = [
        {
            "creature_index": 1,
            "type_id": 2,
            "reward_value": 3.0,
            "xp_awarded": 4,
            "owner_id": 5,
        },
    ]
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    default_result = runner.invoke(
        app,
        ["dbg", "diff", str(golden_trace), str(candidate_trace), "--policy", "original_vs_python_default"],
    )
    assert default_result.exit_code == 1, default_result.output
    assert "result=diverged" in default_result.output

    core_result = runner.invoke(
        app,
        ["dbg", "diff", str(golden_trace), str(candidate_trace), "--policy", "python_vs_zig_core"],
    )
    assert core_result.exit_code == 0, core_result.output
    assert "result=ok" in core_result.output


def test_dbg_bisect_scans_once(tmp_path: Path, monkeypatch) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if row.tick_index == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    call_count = 0
    original_first_mismatch = dbg_diff._first_mismatch

    def _counting_first_mismatch(*, pairs, policy, tick_end=None):
        nonlocal call_count
        call_count += 1
        return original_first_mismatch(pairs=pairs, policy=policy, tick_end=tick_end)

    monkeypatch.setattr(dbg_diff, "_first_mismatch", _counting_first_mismatch)
    report = dbg_diff.bisect_traces(
        expected_trace_path=golden_trace,
        actual_trace_path=candidate_trace,
        policy=resolve_parity_policy("python_vs_rust_strict"),
    )
    assert report.first_bad_tick == 1
    assert call_count == 1


def test_dbg_tick_entity_query_focus(tmp_path: Path) -> None:
    capture_path = _write_capture(tmp_path / "capture.json")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    import_result = runner.invoke(
        app,
        ["dbg", "import-capture", str(capture_path), "--out", str(golden_trace)],
    )
    assert import_result.exit_code == 0, import_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    entity_samples = _as_dict(tick1.channels["entity_samples"])
    creatures_obj = entity_samples.get("creatures")
    assert isinstance(creatures_obj, list)
    first_creature = _as_dict(creatures_obj[0])
    uid_obj = first_creature.get("uid")
    assert isinstance(uid_obj, int)
    entity_uid = int(uid_obj)

    tick_result = runner.invoke(
        app,
        ["dbg", "tick", str(golden_trace), "1"],
    )
    assert tick_result.exit_code == 0, tick_result.output
    assert "tick=1" in tick_result.output
    assert "entity_counts" in tick_result.output

    entity_result = runner.invoke(
        app,
        ["dbg", "entity", str(golden_trace), str(entity_uid)],
    )
    assert entity_result.exit_code == 0, entity_result.output
    assert f"uid={entity_uid}" in entity_result.output
    assert "spawn_tick=0" in entity_result.output

    query_ticks_result = runner.invoke(
        app,
        ["dbg", "query", str(golden_trace), "ticks where checkpoint.score_xp >= 0"],
    )
    assert query_ticks_result.exit_code == 0, query_ticks_result.output
    assert "scope=ticks" in query_ticks_result.output
    assert "match_count=2" in query_ticks_result.output

    query_entities_result = runner.invoke(
        app,
        ["dbg", "query", str(golden_trace), "entities where pool_kind == 'creature'"],
    )
    assert query_entities_result.exit_code == 0, query_entities_result.output
    assert "scope=entities" in query_entities_result.output

    focus_result = runner.invoke(
        app,
        ["dbg", "focus", str(golden_trace), str(candidate_trace), "--tick", "1"],
    )
    assert focus_result.exit_code == 0, focus_result.output
    assert "result=diverged" in focus_result.output
    assert "checkpoint_field_count=" in focus_result.output


def test_dbg_viz(tmp_path: Path) -> None:
    capture_path = _write_capture(tmp_path / "capture.json")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    html_out = tmp_path / "viz.html"
    runner = CliRunner()

    import_result = runner.invoke(
        app,
        ["dbg", "import-capture", str(capture_path), "--out", str(golden_trace)],
    )
    assert import_result.exit_code == 0, import_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    result = runner.invoke(
        app,
        ["dbg", "viz", str(golden_trace), str(candidate_trace), "--tick", "1", "--out", str(html_out)],
    )
    assert result.exit_code == 0, result.output
    assert "viz_html=" in result.output
    assert html_out.exists()
    html_text = html_out.read_text(encoding="utf-8")
    assert "Crimson Debug Viz" in html_text
    assert "Focus tick: 1" in html_text
    assert "tick-slider" in html_text
