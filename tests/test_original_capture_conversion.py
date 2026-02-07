from __future__ import annotations

import gzip
import json
from pathlib import Path

from crimson.replay import unpack_input_flags
from crimson.replay.checkpoints import dump_checkpoints, load_checkpoints
from crimson.replay.original_capture import (
    ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND,
    ORIGINAL_CAPTURE_FORMAT_VERSION,
    ORIGINAL_CAPTURE_UNKNOWN_INT,
    OriginalCaptureSidecar,
    OriginalCaptureTick,
    build_original_capture_dt_frame_overrides,
    convert_original_capture_to_checkpoints,
    convert_original_capture_to_replay,
    default_original_capture_replay_path,
    load_original_capture_sidecar,
)


def test_convert_original_capture_to_checkpoints_roundtrip(tmp_path: Path) -> None:
    capture_obj = {
        "v": ORIGINAL_CAPTURE_FORMAT_VERSION,
        "sample_rate": 2,
        "replay_sha256": "orig-hash",
        "ticks": [
            {
                "tick_index": 0,
                "state_hash": "aaaaaaaaaaaaaaaa",
                "command_hash": "bbbbbbbbbbbbbbbb",
                "rng_state": 100,
                "elapsed_ms": 16,
                "score_xp": 10,
                "kills": 1,
                "creature_count": 20,
                "perk_pending": 0,
                "players": [
                    {
                        "pos": {"x": 512.0, "y": 512.0},
                        "health": 100.0,
                        "weapon_id": 1,
                        "ammo": 12.0,
                        "experience": 10,
                        "level": 1,
                    }
                ],
                "rng_marks": {"gw_begin": 1234},
                "events": {"hit_count": 2, "pickup_count": 1, "sfx_count": 3, "sfx_head": ["sfx_a"]},
            },
            {
                "tick_index": 1,
                "state_hash": "cccccccccccccccc",
                "command_hash": "dddddddddddddddd",
            },
        ],
    }

    path = tmp_path / "capture.json.gz"
    path.write_bytes(gzip.compress(json.dumps(capture_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")))

    capture = load_original_capture_sidecar(path)
    checkpoints = convert_original_capture_to_checkpoints(capture)

    assert checkpoints.sample_rate == 2
    assert checkpoints.replay_sha256 == "orig-hash"
    assert len(checkpoints.checkpoints) == 2
    assert checkpoints.checkpoints[0].tick_index == 0
    assert checkpoints.checkpoints[0].command_hash == "bbbbbbbbbbbbbbbb"
    assert checkpoints.checkpoints[0].events.hit_count == 2
    assert checkpoints.checkpoints[1].events.hit_count == -1
    assert checkpoints.checkpoints[1].events.pickup_count == -1
    assert checkpoints.checkpoints[1].events.sfx_count == -1

    loaded = load_checkpoints(dump_checkpoints(checkpoints))
    assert loaded == checkpoints


def test_convert_original_capture_to_replay_from_sidecar_ticks(tmp_path: Path) -> None:
    capture_obj = {
        "v": ORIGINAL_CAPTURE_FORMAT_VERSION,
        "sample_rate": 1,
        "ticks": [
            {
                "tick_index": 1,
                "state_hash": "hash-1",
                "command_hash": "cmd-1",
                "game_mode_id": 2,
                "input_queries": {
                    "stats": {
                        "primary_edge": {"true_calls": 1},
                        "primary_down": {"true_calls": 1},
                    }
                },
                "input_approx": [
                    {
                        "player_index": 0,
                        "move_dx": 1.0,
                        "move_dy": -1.0,
                        "aim_x": 400.0,
                        "aim_y": 300.0,
                        "fired_events": 1,
                    }
                ],
                "players": [
                    {
                        "pos": {"x": 512.0, "y": 512.0},
                        "health": 100.0,
                        "weapon_id": 1,
                        "ammo": 12.0,
                        "experience": 10,
                        "level": 1,
                    }
                ],
            },
            {
                "tick_index": 3,
                "state_hash": "hash-3",
                "command_hash": "cmd-3",
                "input_approx": [
                    {
                        "player_index": 1,
                        "move_dx": -0.5,
                        "move_dy": 0.75,
                        "aim_x": 200.0,
                        "aim_y": 100.0,
                        "fired_events": 0,
                    }
                ],
                "players": [
                    {
                        "pos": {"x": 100.0, "y": 150.0},
                        "health": 100.0,
                        "weapon_id": 1,
                        "ammo": 12.0,
                        "experience": 10,
                        "level": 1,
                    },
                    {
                        "pos": {"x": 200.0, "y": 250.0},
                        "health": 100.0,
                        "weapon_id": 1,
                        "ammo": 12.0,
                        "experience": 10,
                        "level": 1,
                    },
                ],
            },
        ],
    }

    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture_obj, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    capture = load_original_capture_sidecar(path)
    replay = convert_original_capture_to_replay(capture, seed=0xBEEF, tick_rate=75)

    assert replay.header.game_mode_id == 2
    assert replay.header.seed == 0xBEEF
    assert replay.header.tick_rate == 75
    assert replay.header.player_count == 2
    assert len(replay.inputs) == 4
    assert len(replay.events) == 1
    assert replay.events[0].kind == ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND
    assert replay.events[0].tick_index == 1

    tick1_p0 = replay.inputs[1][0]
    assert tick1_p0[0] == 1.0
    assert tick1_p0[1] == -1.0
    assert tick1_p0[2] == [400.0, 300.0]
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(tick1_p0[3]))
    assert fire_down is True
    assert fire_pressed is True
    assert reload_pressed is False

    tick3_p1 = replay.inputs[3][1]
    assert tick3_p1[0] == -0.5
    assert tick3_p1[1] == 0.75
    assert tick3_p1[2] == [200.0, 100.0]
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(tick3_p1[3]))
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_load_original_capture_sidecar_supports_plain_json(tmp_path: Path) -> None:
    capture_obj = {
        "v": ORIGINAL_CAPTURE_FORMAT_VERSION,
        "sample_rate": 1,
        "ticks": [{"tick_index": 0, "state_hash": "hash0", "command_hash": "cmd0"}],
    }
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture_obj, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    capture = load_original_capture_sidecar(path)
    assert capture.version == ORIGINAL_CAPTURE_FORMAT_VERSION
    assert capture.sample_rate == 1
    assert [tick.tick_index for tick in capture.ticks] == [0]


def test_load_original_capture_sidecar_supports_gameplay_trace_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "gameplay_state_capture.jsonl"
    rows = [
        {"event": "start"},
        {
            "event": "snapshot_compact",
            "gameplay_frame": 0,
            "globals": {
                "game_state_id": 0,
                "time_played_ms": 0,
            },
            "players": [
                {
                    "pos_x": 512.0,
                    "pos_y": 512.0,
                    "health": 100.0,
                    "weapon_id": 1,
                    "ammo_f32": 12.0,
                    "experience": 0,
                    "level": 1,
                }
            ],
        },
        {
            "event": "snapshot_compact",
            "gameplay_frame": 5,
            "globals": {
                "game_state_id": 9,
                "time_played_ms": 85,
                "perk_pending_count": 1,
                "creature_active_count": 33,
                "bonus_weapon_power_up_timer": 1.2,
                "bonus_reflex_boost_timer": 0.6,
                "bonus_energizer_timer": 2.0,
                "bonus_double_xp_timer": 3.0,
                "bonus_freeze_timer": 4.0,
            },
            "players": [
                {
                    "pos_x": 100.123456,
                    "pos_y": 200.987654,
                    "health": 95.5,
                    "weapon_id": 9,
                    "ammo_f32": 7.25,
                    "experience": 42,
                    "level": 3,
                }
            ],
        },
        {
            "event": "snapshot_full",
            "gameplay_frame": 8,
            "globals": {
                "game_state_id": 9,
                "time_played_ms": 136,
                "perk_pending_count": 0,
                "creature_active_count": 30,
                "bonus_weapon_power_up_timer": 1.0,
                "bonus_reflex_boost_timer": 0.5,
                "bonus_energizer_timer": 1.5,
                "bonus_double_xp_timer": 2.5,
                "bonus_freeze_timer": 3.5,
            },
            "players": [
                {
                    "pos_x": 110.0,
                    "pos_y": 210.0,
                    "health": 90.0,
                    "weapon_id": 10,
                    "ammo_f32": 5.0,
                    "experience": 50,
                    "level": 4,
                }
            ],
        },
    ]
    path.write_text("\n".join(json.dumps(row, separators=(",", ":"), sort_keys=True) for row in rows) + "\n", encoding="utf-8")

    capture = load_original_capture_sidecar(path)
    assert capture.version == ORIGINAL_CAPTURE_FORMAT_VERSION
    assert capture.sample_rate == 3
    assert [tick.tick_index for tick in capture.ticks] == [4, 7]

    first = capture.ticks[0]
    assert first.elapsed_ms == 85
    assert first.kills == ORIGINAL_CAPTURE_UNKNOWN_INT
    assert first.players[0].pos.x == 100.1235
    assert first.players[0].pos.y == 200.9877
    assert first.players[0].experience == 42
    assert first.score_xp == 42
    assert first.bonus_timers["4"] == 1200
    assert first.perk.pending_count == ORIGINAL_CAPTURE_UNKNOWN_INT
    assert len(first.deaths) == 1
    assert first.deaths[0].type_id == -1


def test_load_original_capture_sidecar_supports_v2_tick_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "gameplay_diff_capture_v2.jsonl"
    rows = [
        {"event": "start"},
        {
            "event": "tick",
            "tick_index": 42,
            "mode_hint": "survival_update",
            "event_heads": {
                "input_any_key": [
                    {"query": "grim_is_key_active", "pressed": True, "arg0": 31},
                    {"query": "grim_is_key_active", "pressed": True, "arg0": 30},
                ],
                "input_primary_down": [
                    {"query": "grim_is_key_active", "pressed": True, "arg0": 18},
                ],
                "input_primary_edge": [],
            },
            "input_queries": {
                "stats": {
                    "primary_edge": {"calls": 2, "true_calls": 1},
                    "primary_down": {"calls": 2, "true_calls": 2},
                    "any_key": {"calls": 2, "true_calls": 2},
                }
            },
            "before": {
                "input_bindings": {
                    "players": [
                        {
                            "player_index": 0,
                            "move_forward": 17,
                            "move_backward": 31,
                            "turn_left": 30,
                            "turn_right": 32,
                            "fire": 18,
                        }
                    ]
                }
            },
            "input_approx": [
                {
                    "player_index": 0,
                    "move_dx": 1.0,
                    "move_dy": 0.0,
                    "aim_x": 333.0,
                    "aim_y": 444.0,
                    "fired_events": 2,
                    "reload_active": False,
                }
            ],
            "after": {
                "globals": {"config_game_mode": 1},
                "players": [
                    {
                        "aim_heading": -0.75,
                    }
                ],
            },
            "checkpoint": {
                "tick_index": 42,
                "state_hash": "deadbeef",
                "command_hash": "cafebabe",
                "rng_state": -1,
                "elapsed_ms": 701,
                "score_xp": 1234,
                "kills": -1,
                "creature_count": 31,
                "perk_pending": 0,
                "players": [
                    {
                        "pos": {"x": 321.5, "y": 654.25},
                        "health": 88.0,
                        "weapon_id": 7,
                        "ammo": 9.5,
                        "experience": 1234,
                        "level": 5,
                    }
                ],
                "bonus_timers": {"4": 2500, "11": 3000},
                "rng_marks": {
                    "rand_calls": 16,
                    "rand_hash": "0xfce2bde6",
                    "rand_last": 14224,
                    "rand_head": [{"value": 1}],
                },
                "events": {"hit_count": -1, "pickup_count": -1, "sfx_count": 3, "sfx_head": ["101", "102"]},
                "deaths": [
                    {
                        "creature_index": -1,
                        "type_id": -1,
                        "reward_value": 0.0,
                        "xp_awarded": -1,
                        "owner_id": -1,
                    }
                ],
                "perk": {"pending_count": -1, "choices_dirty": False, "choices": [], "player_nonzero_counts": []},
            },
        },
    ]
    path.write_text("\n".join(json.dumps(row, separators=(",", ":"), sort_keys=True) for row in rows) + "\n", encoding="utf-8")

    capture = load_original_capture_sidecar(path)
    assert capture.version == ORIGINAL_CAPTURE_FORMAT_VERSION
    assert capture.sample_rate == 1
    assert len(capture.ticks) == 1
    tick = capture.ticks[0]
    assert tick.tick_index == 42
    assert tick.state_hash == "deadbeef"
    assert tick.command_hash == "cafebabe"
    assert tick.score_xp == 1234
    assert tick.players[0].weapon_id == 7
    assert tick.rng_marks["rand_calls"] == 16
    assert tick.rng_marks["rand_hash"] == int("0xfce2bde6", 16)
    assert tick.rng_marks["rand_last"] == 14224
    assert "rand_head" not in tick.rng_marks
    assert tick.events.sfx_count == 3
    assert tick.mode_hint == "survival_update"
    assert tick.game_mode_id == 1
    assert tick.input_primary_edge_true_calls == 1
    assert tick.input_primary_down_true_calls == 2
    assert len(tick.input_approx) == 1
    assert tick.input_approx[0].move_dx == 1.0
    assert tick.input_approx[0].aim_y == 444.0
    assert tick.input_approx[0].aim_heading == -0.75
    assert tick.input_approx[0].move_forward_pressed is False
    assert tick.input_approx[0].move_backward_pressed is True
    assert tick.input_approx[0].turn_left_pressed is True
    assert tick.input_approx[0].turn_right_pressed is False
    assert tick.input_approx[0].fire_down is True


def test_default_original_capture_replay_path_derives_expected_name() -> None:
    checkpoints = Path("/tmp/original_capture_v2.checkpoints.json.gz")
    replay = default_original_capture_replay_path(checkpoints)
    assert replay.name == "original_capture_v2.crdemo.gz"


def test_build_original_capture_dt_frame_overrides_distributes_gaps() -> None:
    capture = OriginalCaptureSidecar(
        version=ORIGINAL_CAPTURE_FORMAT_VERSION,
        sample_rate=3,
        ticks=[
            OriginalCaptureTick(tick_index=10, state_hash="", command_hash="", elapsed_ms=1000),
            OriginalCaptureTick(tick_index=13, state_hash="", command_hash="", elapsed_ms=1060),
            OriginalCaptureTick(tick_index=16, state_hash="", command_hash="", elapsed_ms=1180),
        ],
    )

    overrides = build_original_capture_dt_frame_overrides(capture, tick_rate=60)

    assert overrides[11] == 0.02
    assert overrides[12] == 0.02
    assert overrides[13] == 0.02
    assert overrides[14] == 0.04
    assert overrides[15] == 0.04
    assert overrides[16] == 0.04
    assert 10 not in overrides


def test_build_original_capture_dt_frame_overrides_skips_non_monotonic_elapsed() -> None:
    capture = OriginalCaptureSidecar(
        version=ORIGINAL_CAPTURE_FORMAT_VERSION,
        sample_rate=1,
        ticks=[
            OriginalCaptureTick(tick_index=0, state_hash="", command_hash="", elapsed_ms=16),
            OriginalCaptureTick(tick_index=1, state_hash="", command_hash="", elapsed_ms=16),
            OriginalCaptureTick(tick_index=2, state_hash="", command_hash="", elapsed_ms=33),
        ],
    )

    overrides = build_original_capture_dt_frame_overrides(capture, tick_rate=60)

    assert 1 not in overrides
    assert overrides[2] == 0.017


def test_convert_original_capture_to_replay_v2_prefers_discrete_input_and_heading(tmp_path: Path) -> None:
    path = tmp_path / "gameplay_diff_capture_v2.jsonl"
    rows = [
        {"event": "start"},
        {
            "event": "tick",
            "tick_index": 0,
            "event_heads": {
                "input_any_key": [
                    {"query": "grim_is_key_active", "pressed": True, "arg0": 32},
                    {"query": "grim_is_key_active", "pressed": True, "arg0": 17},
                ],
                "input_primary_down": [
                    {"query": "grim_is_key_active", "pressed": True, "arg0": 18},
                ],
                "input_primary_edge": [],
            },
            "input_queries": {
                "stats": {
                    "primary_edge": {"calls": 0, "true_calls": 0},
                    "primary_down": {"calls": 1, "true_calls": 1},
                    "any_key": {"calls": 2, "true_calls": 2},
                }
            },
            "before": {
                "input_bindings": {
                    "players": [
                        {
                            "player_index": 0,
                            "move_forward": 17,
                            "move_backward": 31,
                            "turn_left": 30,
                            "turn_right": 32,
                            "fire": 18,
                        }
                    ]
                }
            },
            "after": {
                "globals": {"config_game_mode": 1},
                "players": [{"aim_heading": -0.5}],
            },
            "checkpoint": {
                "tick_index": 0,
                "state_hash": "h0",
                "command_hash": "c0",
                "players": [{"pos": {"x": 512.0, "y": 512.0}, "health": 100.0, "weapon_id": 1, "ammo": 10.0}],
            },
        },
        {
            "event": "tick",
            "tick_index": 1,
            "event_heads": {"input_any_key": [], "input_primary_down": [], "input_primary_edge": []},
            "input_queries": {
                "stats": {
                    "primary_edge": {"calls": 0, "true_calls": 0},
                    "primary_down": {"calls": 1, "true_calls": 0},
                    "any_key": {"calls": 0, "true_calls": 0},
                }
            },
            "before": {
                "input_bindings": {
                    "players": [
                        {
                            "player_index": 0,
                            "move_forward": 17,
                            "move_backward": 31,
                            "turn_left": 30,
                            "turn_right": 32,
                            "fire": 18,
                        }
                    ]
                }
            },
            "after": {
                "globals": {"config_game_mode": 1},
                "players": [{"aim_heading": -0.5}],
            },
            "checkpoint": {
                "tick_index": 1,
                "state_hash": "h1",
                "command_hash": "c1",
                "players": [{"pos": {"x": 512.0, "y": 512.0}, "health": 100.0, "weapon_id": 1, "ammo": 10.0}],
            },
        },
    ]
    path.write_text("\n".join(json.dumps(row, separators=(",", ":"), sort_keys=True) for row in rows) + "\n", encoding="utf-8")

    capture = load_original_capture_sidecar(path)
    replay = convert_original_capture_to_replay(capture)

    assert len(replay.inputs) == 2
    tick0 = replay.inputs[0][0]
    assert tick0[0] == 1.0  # turn_right pressed
    assert tick0[1] == -1.0  # move_forward pressed
    fire_down0, fire_pressed0, _reload0 = unpack_input_flags(int(tick0[3]))
    assert fire_down0 is True
    assert fire_pressed0 is True
    assert tick0[2] != [0.0, 0.0]

    tick1 = replay.inputs[1][0]
    assert tick1[0] == 0.0
    assert tick1[1] == 0.0
    fire_down1, fire_pressed1, _reload1 = unpack_input_flags(int(tick1[3]))
    assert fire_down1 is False
    assert fire_pressed1 is False
