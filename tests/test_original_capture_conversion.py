from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
    build_capture_dt_frame_overrides,
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_inter_tick_rand_draws_overrides,
    capture_bootstrap_payload_from_event_payload,
    capture_perk_apply_from_event_payload,
    capture_perk_apply_id_from_event_payload,
    capture_perk_pending_from_event_payload,
    convert_capture_to_checkpoints,
    convert_capture_to_replay,
    default_capture_replay_path,
    load_capture,
    parse_player_int_overrides,
)
from crimson.original.schema import CAPTURE_FORMAT_VERSION
from crimson.replay import UnknownEvent, unpack_input_flags
from crimson.replay.checkpoints import dump_checkpoints, load_checkpoints
from grim.geom import Vec2


def _crt_rand_outputs(seed: int, calls: int) -> list[int]:
    state = int(seed) & 0xFFFFFFFF
    out: list[int] = []
    for _ in range(int(calls)):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        out.append((state >> 16) & 0x7FFF)
    return out


def _base_player() -> dict[str, object]:
    return {
        "pos": {"x": 512.0, "y": 512.0},
        "health": 100.0,
        "weapon_id": 1,
        "ammo": 12.0,
        "experience": 0,
        "level": 1,
    }


def _base_checkpoint(
    *,
    tick_index: int,
    elapsed_ms: int,
    perk_pending: int = 0,
    score_xp: int = 0,
    rng_state: int = 0,
) -> dict[str, object]:
    return {
        "tick_index": int(tick_index),
        "state_hash": f"state-{int(tick_index)}",
        "command_hash": f"cmd-{int(tick_index)}",
        "rng_state": int(rng_state),
        "elapsed_ms": int(elapsed_ms),
        "score_xp": int(score_xp),
        "kills": 0,
        "creature_count": 0,
        "perk_pending": int(perk_pending),
        "players": [_base_player()],
        "status": {
            "quest_unlock_index": -1,
            "quest_unlock_index_full": -1,
            "weapon_usage_counts": [],
        },
        "bonus_timers": {},
        "rng_marks": {
            "rand_calls": 0,
            "rand_hash": "",
            "rand_last": None,
            "rand_head": [],
            "rand_callers": [],
            "rand_caller_overflow": 0,
            "rand_seq_first": None,
            "rand_seq_last": None,
            "rand_seed_epoch_enter": None,
            "rand_seed_epoch_last": None,
            "rand_outside_before_calls": 0,
            "rand_outside_before_dropped": 0,
            "rand_outside_before_head": [],
            "rand_mirror_mismatch_total": 0,
            "rand_mirror_unknown_total": 0,
        },
        "deaths": [],
        "perk": {
            "pending_count": int(perk_pending),
            "choices_dirty": False,
            "choices": [],
            "player_nonzero_counts": [],
        },
        "events": {
            "hit_count": -1,
            "pickup_count": -1,
            "sfx_count": -1,
            "sfx_head": [],
        },
        "debug": {
            "sampling_phase": "",
            "timing": {},
            "spawn": {},
            "rng": {},
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "before_players": [],
            "before_status": {
                "quest_unlock_index": -1,
                "quest_unlock_index_full": -1,
            },
        },
    }


def _base_tick(
    *,
    tick_index: int,
    elapsed_ms: int,
    perk_pending: int = 0,
    score_xp: int = 0,
    rng_state: int = 0,
) -> dict[str, object]:
    return {
        "tick_index": int(tick_index),
        "gameplay_frame": int(tick_index) + 1,
        "mode_hint": "survival_update",
        "game_mode_id": int(GameMode.SURVIVAL),
        "checkpoint": _base_checkpoint(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            perk_pending=int(perk_pending),
            score_xp=int(score_xp),
            rng_state=int(rng_state),
        ),
        "input_queries": {
            "stats": {
                "primary_edge": {"calls": 0, "true_calls": 0},
                "primary_down": {"calls": 0, "true_calls": 0},
                "any_key": {"calls": 0, "true_calls": 0},
            },
            "query_hash": "",
        },
        "input_player_keys": [{"player_index": 0}],
        "input_approx": [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0}],
    }


def _sample_creature(*, index: int = 5) -> dict[str, object]:
    return {
        "index": int(index),
        "active": 1,
        "state_flag": 1,
        "collision_flag": 1,
        "hitbox_size": 16.0,
        "pos": {"x": 10.0, "y": 20.0},
        "hp": 100.0,
        "type_id": 2,
        "target_player": 0,
        "flags": 0,
    }


def _sample_projectile(*, index: int = 7) -> dict[str, object]:
    return {
        "index": int(index),
        "active": 1,
        "angle": 0.5,
        "pos": {"x": 15.0, "y": 25.0},
        "vel": {"x": 3.0, "y": -2.0},
        "type_id": 1,
        "life_timer": 0.9,
        "speed_scale": 1.0,
        "damage_pool": 12.0,
        "hit_radius": 9.0,
        "base_damage": 5.0,
        "owner_id": 0,
    }


def _sample_secondary_projectile(*, index: int = 9) -> dict[str, object]:
    return {
        "index": int(index),
        "active": 1,
        "pos": {"x": 17.0, "y": 27.0},
        "life_timer": 0.8,
        "angle": 0.2,
        "vel": {"x": 1.0, "y": -1.0},
        "trail_timer": 0.1,
        "type_id": 3,
        "target_id": -1,
    }


def _sample_bonus(*, index: int = 2) -> dict[str, object]:
    return {
        "index": int(index),
        "bonus_id": 6,
        "state": 0,
        "time_left": 10.0,
        "time_max": 10.0,
        "pos": {"x": 30.0, "y": 40.0},
        "amount_f32": 0.0,
        "amount_i32": 0,
    }


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    return {
        "capture_format_version": int(CAPTURE_FORMAT_VERSION),
        "script": "gameplay_diff_capture",
        "session_id": "session-1",
        "out_path": "capture.json",
        "config": {},
        "session_fingerprint": {
            "session_id": "session-1",
            "module_hash": "deadbeef",
            "ptrs_hash": "feedface",
        },
        "process": {
            "pid": 123,
            "platform": "windows",
            "arch": "x86",
            "frida_version": "16.0.0",
            "runtime": "v8",
        },
        "exe": {
            "base": "0x00400000",
            "size": 1,
            "path": "crimsonland.exe",
        },
        "grim": None,
        "pointers_resolved": {},
        "ticks": ticks,
    }


def _write_capture(path: Path, obj: dict[str, object]) -> None:
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    ticks_obj = obj.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks
    )
    encoded = ("\n".join(rows) + "\n").encode("utf-8")
    if str(path).endswith(".gz"):
        path.write_bytes(gzip.compress(encoded))
    else:
        path.write_bytes(encoded)


def _write_capture_stream(path: Path, *, meta: dict[str, object], ticks: list[dict[str, object]]) -> None:
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks
    )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_capture_event_payload_helpers_parse_msgspec_payloads() -> None:
    assert capture_bootstrap_payload_from_event_payload([{"elapsed_ms": "123"}]) == {"elapsed_ms": "123"}
    assert capture_perk_apply_from_event_payload([{"perk_id": "14"}]) == (14, False)
    assert capture_perk_apply_from_event_payload([{"perk_id": 49, "outside_before": True}]) == (49, True)
    assert capture_perk_apply_id_from_event_payload([{"perk_id": "14"}]) == 14
    assert capture_perk_pending_from_event_payload([{"perk_pending": "2"}]) == 2

    assert capture_bootstrap_payload_from_event_payload([]) is None
    assert capture_bootstrap_payload_from_event_payload(["bad"]) is None
    assert capture_perk_apply_from_event_payload([{"perk_pending": 2}]) is None
    assert capture_perk_apply_id_from_event_payload([{"perk_pending": 2}]) is None
    assert capture_perk_pending_from_event_payload([{"perk_id": 14}]) is None


def test_load_capture_supports_plain_json_and_gz(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])

    plain = tmp_path / "capture.json"
    zipped = tmp_path / "capture.json.gz"
    _write_capture(plain, obj)
    _write_capture(zipped, obj)

    capture_plain = load_capture(plain)
    capture_zipped = load_capture(zipped)

    assert capture_plain.script == "gameplay_diff_capture"
    assert capture_zipped.script == "gameplay_diff_capture"
    assert len(capture_plain.ticks) == 1
    assert len(capture_zipped.ticks) == 1


def test_load_capture_rejects_missing_capture_format_version(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj.pop("capture_format_version", None)
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(ValueError, match="unsupported capture format version"):
        load_capture(path)


def test_load_capture_rejects_unsupported_capture_format_version(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj["capture_format_version"] = int(CAPTURE_FORMAT_VERSION) - 1
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(ValueError, match="unsupported capture format version"):
        load_capture(path)


def test_load_capture_decodes_f32_tokens(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    checkpoint = tick.get("checkpoint")
    assert isinstance(checkpoint, dict)
    players = checkpoint.get("players")
    assert isinstance(players, list)
    assert isinstance(players[0], dict)
    pos = players[0].get("pos")
    assert isinstance(pos, dict)
    pos["x"] = "f32:3f800000"
    players[0]["health"] = "f32:42c80000"
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    assert capture.ticks[0].checkpoint.players[0].pos.x == pytest.approx(1.0)
    assert capture.ticks[0].checkpoint.players[0].health == pytest.approx(100.0)


def test_load_capture_decodes_f32_tokens_with_0x_prefix(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    checkpoint = tick.get("checkpoint")
    assert isinstance(checkpoint, dict)
    players = checkpoint.get("players")
    assert isinstance(players, list)
    assert isinstance(players[0], dict)
    pos = players[0].get("pos")
    assert isinstance(pos, dict)
    pos["x"] = "f32:0x3f800000"
    players[0]["health"] = "f32:0X42c80000"
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    assert capture.ticks[0].checkpoint.players[0].pos.x == pytest.approx(1.0)
    assert capture.ticks[0].checkpoint.players[0].health == pytest.approx(100.0)


def test_load_capture_rejects_invalid_f32_token(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    checkpoint = tick.get("checkpoint")
    assert isinstance(checkpoint, dict)
    players = checkpoint.get("players")
    assert isinstance(players, list)
    assert isinstance(players[0], dict)
    players[0]["ammo"] = "f32:bad"
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(Exception):
        load_capture(path)


def test_load_capture_rejects_legacy_canonical_json(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(obj, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    with pytest.raises(Exception):
        load_capture(path)


def test_load_capture_accepts_projectile_find_query_event_head(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["event_counts"] = {"projectile_find_query": 1}
    tick["event_heads"] = [
        {
            "kind": "projectile_find_query",
            "data": {
                "result_creature_index": None,
                "result_kind": "miss",
                "caller_static": "0x00420e52",
            },
        }
    ]
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    assert capture.ticks[0].event_counts.projectile_find_query == 1
    assert capture.ticks[0].event_heads
    assert capture.ticks[0].event_heads[0].data.get("result_kind") == "miss"


def test_load_capture_supports_jsonl_stream_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    _write_capture_stream(path, meta=meta, ticks=[tick])

    capture = load_capture(path)

    assert capture.script == "gameplay_diff_capture"
    assert len(capture.ticks) == 1
    assert int(capture.ticks[0].tick_index) == 0


def test_load_capture_stream_accepts_forward_compatible_config_fields(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    meta["config"] = {
        "log_mode": "truncate",
        "console_all_events": True,
        "console_events": ["start", "ready", "capture_shutdown"],
        "include_caller": False,
        "future_knob": 12345,
    }
    _write_capture_stream(path, meta=meta, ticks=[tick])

    capture = load_capture(path)

    assert capture.script == "gameplay_diff_capture"
    assert capture.config.console_all_events is True
    assert capture.config.console_events == ["start", "ready", "capture_shutdown"]
    assert capture.config.include_caller is False
    assert len(capture.ticks) == 1


def test_load_capture_stream_rejects_truncated_last_line(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True),
        '{"event":"tick","tick"',
    ]
    path.write_text("\n".join(rows), encoding="utf-8")

    with pytest.raises(Exception):
        load_capture(path)


def test_load_capture_stream_rejects_legacy_capture_end_row(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "capture_end", "reason": "manual_stop", "ticks_written": 1}, separators=(",", ":")),
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(Exception):
        load_capture(path)


def test_load_capture_rejects_unknown_fields(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj["unexpected"] = 1
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(Exception):
        load_capture(path)


def test_load_capture_accepts_strict_typed_sample_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["samples"] = {
        "creatures": [_sample_creature()],
        "projectiles": [_sample_projectile()],
        "secondary_projectiles": [_sample_secondary_projectile()],
        "bonuses": [_sample_bonus()],
    }
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    samples = capture.ticks[0].samples
    assert samples is not None
    assert len(samples.creatures) == 1
    assert len(samples.projectiles) == 1
    assert len(samples.secondary_projectiles) == 1
    assert len(samples.bonuses) == 1


def test_load_capture_rejects_incomplete_sample_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    bad_creature = _sample_creature()
    del bad_creature["collision_flag"]
    tick["samples"] = {
        "creatures": [bad_creature],
        "projectiles": [],
        "secondary_projectiles": [],
        "bonuses": [],
    }
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(Exception):
        load_capture(path)


def test_load_capture_rejects_non_canonical_extension(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    path = tmp_path / "capture.jsonl"
    _write_capture(path, obj)

    with pytest.raises(Exception):
        load_capture(path)


def test_convert_capture_to_checkpoints_roundtrip(tmp_path: Path) -> None:
    obj = _capture_obj(
        ticks=[
            _base_tick(tick_index=0, elapsed_ms=16, score_xp=10, rng_state=100),
            _base_tick(tick_index=2, elapsed_ms=48, score_xp=30, rng_state=200),
        ]
    )
    path = tmp_path / "capture.json.gz"
    _write_capture(path, obj)

    capture = load_capture(path)
    checkpoints = convert_capture_to_checkpoints(capture)
    blob = dump_checkpoints(checkpoints)
    loaded = load_checkpoints(blob)

    assert loaded.sample_rate == 2
    assert len(loaded.checkpoints) == 2
    assert loaded.checkpoints[0].tick_index == 0
    assert loaded.checkpoints[1].tick_index == 2


def test_convert_capture_to_replay_from_ticks(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": True,
            "fire_pressed": True,
            "reload_pressed": False,
        }
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 1.0,
            "move_dy": -1.0,
            "aim_x": 540.0,
            "aim_y": 500.0,
        }
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0xBEEF, tick_rate=75)

    assert replay.header.game_mode_id == int(GameMode.SURVIVAL)
    assert replay.header.seed == 0xBEEF
    assert replay.header.tick_rate == 75
    assert len(replay.inputs) == 1
    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, _reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is True


def test_convert_capture_to_replay_heading_fallback_uses_checkpoint_pos(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 0.0, "aim_y": 0.0, "aim_heading": 0.0}]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    aim = replay.inputs[0][0][2]
    expected = Vec2(512.0, 512.0) + Vec2.from_heading(0.0) * 256.0
    assert float(aim[0]) == pytest.approx(expected.x)
    assert float(aim[1]) == pytest.approx(expected.y)


def test_convert_capture_to_replay_does_not_fallback_to_primary_query_stats(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_queries"] = {
        "stats": {
            "primary_edge": {"calls": 1, "true_calls": 1},
            "primary_down": {"calls": 1, "true_calls": 1},
            "any_key": {"calls": 0, "true_calls": 0},
        },
        "query_hash": "",
    }
    tick0["input_player_keys"] = [{"player_index": 0}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 540.0, "aim_y": 500.0, "reload_active": True}]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False



def test_convert_capture_to_replay_infers_pending_drop_events(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=2)
    tick1 = _base_tick(tick_index=1, elapsed_ms=32, perk_pending=1)
    tick2 = _base_tick(tick_index=2, elapsed_ms=48, perk_pending=1)

    obj = _capture_obj(ticks=[tick0, tick1, tick2])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    kinds = [
        type(event).__name__ if not isinstance(event, UnknownEvent) else str(event.kind)
        for event in replay.events
    ]
    assert CAPTURE_BOOTSTRAP_EVENT_KIND in kinds
    assert CAPTURE_PERK_PENDING_EVENT_KIND in kinds
    assert "PerkMenuOpenEvent" in kinds



def test_convert_capture_to_replay_infers_pending_drop_events_from_perk_delta(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=-1)
    tick1 = _base_tick(tick_index=1, elapsed_ms=32, perk_pending=-1)
    tick2 = _base_tick(tick_index=2, elapsed_ms=48, perk_pending=-1)

    tick0["event_heads"] = [{"kind": "perk_delta", "data": {"perk_pending_count": 1}}]
    tick1["event_heads"] = [{"kind": "perk_delta", "data": {"perk_pending_count": 0}}]
    tick2["event_heads"] = [{"kind": "perk_delta", "data": {"perk_pending_count": 0}}]

    obj = _capture_obj(ticks=[tick0, tick1, tick2])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    pending_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_PERK_PENDING_EVENT_KIND
    ]
    assert [event.tick_index for event in pending_events] == [0, 1]
    assert [capture_perk_pending_from_event_payload(list(event.payload)) for event in pending_events] == [1, 0]

    kinds = [
        type(event).__name__ if not isinstance(event, UnknownEvent) else str(event.kind)
        for event in replay.events
    ]
    assert "PerkMenuOpenEvent" in kinds


def test_convert_capture_to_replay_emits_perk_apply_events(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["perk_apply_in_tick"] = [
        {
            "perk_id": 14,
            "pending_before": 1,
            "pending_after": 0,
            "caller": None,
            "caller_static": None,
            "backtrace": None,
        }
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    perk_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_PERK_APPLY_EVENT_KIND
    ]
    assert len(perk_events) == 1
    assert perk_events[0].tick_index == 0


def test_default_capture_replay_path_derives_expected_name() -> None:
    checkpoints = Path("/tmp/gameplay_diff_capture.checkpoints.json.gz")
    replay = default_capture_replay_path(checkpoints)
    assert replay.name == "gameplay_diff_capture.crdemo.gz"


def test_build_capture_dt_frame_overrides_distributes_gaps(tmp_path: Path) -> None:
    obj = _capture_obj(
        ticks=[
            _base_tick(tick_index=0, elapsed_ms=0),
            _base_tick(tick_index=2, elapsed_ms=40),
            _base_tick(tick_index=5, elapsed_ms=100),
        ]
    )
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert overrides[1] == pytest.approx(0.02)
    assert overrides[2] == pytest.approx(0.02)
    assert overrides[3] == pytest.approx(0.02)
    assert overrides[5] == pytest.approx(0.02)


def test_build_capture_dt_frame_overrides_prefers_explicit_tick_frame_dt(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms"] = 20.0
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert overrides[0] == pytest.approx(0.02)


def test_build_capture_dt_frame_overrides_ignores_denormal_frame_dt_ms_and_prefers_i32(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms"] = 1.401298464324817e-43
    tick0["frame_dt_ms_i32"] = 32
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert overrides[0] == pytest.approx(0.032)


def test_build_capture_dt_frame_overrides_prefers_timing_frame_dt_after_over_i32(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms"] = 30.0
    tick0["frame_dt_ms_i32"] = 30
    tick0["diagnostics"] = {"timing": {"frame_dt_after": "f32:3ced9169"}}
    tick1 = _base_tick(tick_index=1, elapsed_ms=29)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert overrides[0] == pytest.approx(0.029000001028180122)


def test_build_capture_dt_frame_ms_i32_overrides_uses_explicit_values(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms_i32"] = 17
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_ms_i32_overrides(capture)

    assert overrides == {0: 17}


def test_build_capture_inter_tick_rand_draws_overrides_uses_checkpoint_marks(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=10, elapsed_ms=0)
    tick1 = _base_tick(tick_index=11, elapsed_ms=16)
    tick2 = _base_tick(tick_index=12, elapsed_ms=32)
    assert isinstance(tick0["checkpoint"], dict)
    assert isinstance(tick1["checkpoint"], dict)
    assert isinstance(tick2["checkpoint"], dict)
    assert isinstance(tick0["checkpoint"]["rng_marks"], dict)
    assert isinstance(tick1["checkpoint"]["rng_marks"], dict)
    assert isinstance(tick2["checkpoint"]["rng_marks"], dict)
    tick0["checkpoint"]["rng_marks"]["rand_outside_before_calls"] = 7
    tick1["checkpoint"]["rng_marks"]["rand_outside_before_calls"] = 3
    tick2["checkpoint"]["rng_marks"]["rand_outside_before_calls"] = -1
    obj = _capture_obj(ticks=[tick0, tick1, tick2])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_inter_tick_rand_draws_overrides(capture)

    assert overrides == {10: 0, 11: 3}


def test_build_capture_inter_tick_rand_draws_overrides_returns_none_when_missing(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    assert isinstance(tick0["checkpoint"], dict)
    assert isinstance(tick1["checkpoint"], dict)
    assert isinstance(tick0["checkpoint"]["rng_marks"], dict)
    assert isinstance(tick1["checkpoint"]["rng_marks"], dict)
    tick0["checkpoint"]["rng_marks"]["rand_outside_before_calls"] = -1
    tick1["checkpoint"]["rng_marks"]["rand_outside_before_calls"] = -1
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_inter_tick_rand_draws_overrides(capture)

    assert overrides is None


def test_convert_capture_to_replay_infers_seed_from_rng_head(tmp_path: Path) -> None:
    seed = 0x1234
    outputs = _crt_rand_outputs(seed, 8)
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    checkpoint = tick0["checkpoint"]
    assert isinstance(checkpoint, dict)
    rng_marks = checkpoint["rng_marks"]
    assert isinstance(rng_marks, dict)
    rng_marks["rand_calls"] = 8
    rng_marks["rand_last"] = outputs[-1]
    rng_marks["rand_head"] = [{"value": int(value), "value_15": int(value)} for value in outputs]

    rng = {
        "calls": 8,
        "last_value": outputs[-1],
        "head": [{"value": int(value), "value_15": int(value)} for value in outputs],
    }
    tick0["rng"] = rng

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    assert replay.header.seed == int(seed) & 0x7FFFFFFF


def test_convert_capture_to_replay_prefers_rng_state_before_seed(tmp_path: Path) -> None:
    seed = 0x8C6978CC
    outputs = _crt_rand_outputs(seed, 8)
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    checkpoint = tick0["checkpoint"]
    assert isinstance(checkpoint, dict)
    rng_marks = checkpoint["rng_marks"]
    assert isinstance(rng_marks, dict)
    rng_marks["rand_calls"] = 8
    rng_marks["rand_last"] = outputs[-1]
    rng_marks["rand_head"] = [
        {
            "value": int(outputs[0]),
            "value_15": int(outputs[0]),
            "state_before_u32": int(seed),
        }
    ]
    tick0["rng"] = {
        "calls": 8,
        "last_value": outputs[-1],
        "head": [
            {
                "value": int(outputs[0]),
                "value_15": int(outputs[0]),
                "state_before_u32": int(seed),
            }
        ],
    }

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    assert replay.header.seed == int(seed)


def test_convert_capture_to_replay_explicit_seed_overrides_inferred_seed(tmp_path: Path) -> None:
    seed = 0x1234
    outputs = _crt_rand_outputs(seed, 8)
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    checkpoint = tick0["checkpoint"]
    assert isinstance(checkpoint, dict)
    rng_marks = checkpoint["rng_marks"]
    assert isinstance(rng_marks, dict)
    rng_marks["rand_calls"] = 8
    rng_marks["rand_last"] = outputs[-1]
    rng_marks["rand_head"] = [{"value": int(value), "value_15": int(value)} for value in outputs]
    tick0["rng"] = {
        "calls": 8,
        "last_value": outputs[-1],
        "head": [{"value": int(value), "value_15": int(value)} for value in outputs],
    }

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0xBEEF)

    assert replay.header.seed == 0xBEEF


def test_convert_capture_to_replay_prefers_input_player_keys_for_digital_move(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
            "move_backward_pressed": False,
            "turn_left_pressed": True,
            "turn_right_pressed": False,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        }
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -21.5,
            "move_dy": -7.6,
            "aim_x": 540.0,
            "aim_y": 500.0,
            "fired_events": 0,
            "reload_active": False,
        }
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    move_x, move_y, _aim, flags = replay.inputs[0][0]
    assert move_x == -1.0
    assert move_y == -1.0
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.get("digital_move_enabled_by_player") == [True]


def test_convert_capture_to_replay_ignores_input_approx_for_digital_move_capability(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [{"player_index": 0}]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 0.25,
            "move_dy": 0.5,
            "move_mode": 1,
            "move_forward_pressed": True,
            "move_backward_pressed": False,
            "turn_left_pressed": True,
            "turn_right_pressed": False,
            "aim_x": 540.0,
            "aim_y": 500.0,
            "fired_events": 0,
            "reload_active": False,
        }
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    move_x, move_y, _aim, _flags = replay.inputs[0][0]
    assert move_x == pytest.approx(0.25, abs=1e-6)
    assert move_y == pytest.approx(0.5, abs=1e-6)

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.get("digital_move_enabled_by_player") == [False]


def test_convert_capture_to_replay_conflicting_turn_keys_use_contextual_precedence(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": False,
            "turn_left_pressed": False,
            "turn_right_pressed": True,
        }
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 98.0,
            "move_dy": 5.0,
            "aim_x": 306.0,
            "aim_y": 309.0,
        }
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": True,
            "turn_left_pressed": True,
            "turn_right_pressed": True,
        }
    ]
    tick1["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -77.0,
            "move_dy": 11.0,
            "aim_x": 308.0,
            "aim_y": 311.0,
        }
    ]
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    move_x0, move_y0, _aim0, _flags0 = replay.inputs[0][0]
    move_x1, move_y1, _aim1, _flags1 = replay.inputs[1][0]
    assert move_x0 == pytest.approx(1.0, abs=1e-6)
    assert move_y0 == pytest.approx(0.0, abs=1e-6)
    assert move_x1 == pytest.approx(-1.0, abs=1e-6)
    assert move_y1 == pytest.approx(1.0, abs=1e-6)


def test_convert_capture_to_replay_conflicting_move_keys_use_contextual_precedence(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": True,
            "turn_left_pressed": False,
            "turn_right_pressed": False,
        }
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 4.0,
            "move_dy": 66.0,
            "aim_x": 306.0,
            "aim_y": 309.0,
        }
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
            "move_backward_pressed": True,
            "turn_left_pressed": True,
            "turn_right_pressed": False,
        }
    ]
    tick1["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -8.0,
            "move_dy": -55.0,
            "aim_x": 307.0,
            "aim_y": 310.0,
        }
    ]
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    move_x0, move_y0, _aim0, _flags0 = replay.inputs[0][0]
    move_x1, move_y1, _aim1, _flags1 = replay.inputs[1][0]
    assert move_x0 == pytest.approx(0.0, abs=1e-6)
    assert move_y0 == pytest.approx(1.0, abs=1e-6)
    assert move_x1 == pytest.approx(-1.0, abs=1e-6)
    assert move_y1 == pytest.approx(-1.0, abs=1e-6)


def test_convert_capture_to_replay_conflicting_keys_ignore_sample_axis_sign(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": False,
            "turn_left_pressed": True,
            "turn_right_pressed": True,
        }
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -92.0,
            "move_dy": 8.0,
            "aim_x": 400.0,
            "aim_y": 410.0,
        }
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
            "move_backward_pressed": True,
            "turn_left_pressed": False,
            "turn_right_pressed": False,
        }
    ]
    tick1["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 12.0,
            "move_dy": -73.0,
            "aim_x": 402.0,
            "aim_y": 412.0,
        }
    ]
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    move_x0, move_y0, _aim0, _flags0 = replay.inputs[0][0]
    move_x1, move_y1, _aim1, _flags1 = replay.inputs[1][0]
    assert move_x0 == pytest.approx(1.0, abs=1e-6)
    assert move_y0 == pytest.approx(0.0, abs=1e-6)
    assert move_x1 == pytest.approx(0.0, abs=1e-6)
    assert move_y1 == pytest.approx(1.0, abs=1e-6)


def test_convert_capture_to_replay_uses_player_key_fire_reload_edges(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": True,
            "fire_pressed": True,
            "reload_pressed": True,
        }
    ]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "fired_events": 0}]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is True
    assert reload_pressed is True


def test_convert_capture_to_replay_synthesizes_computer_aim_fire_down_from_projectile_spawn(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = {
        "globals": {"config_aim_scheme": [5]},
        "status": {},
        "player_count": 1,
        "players": [],
        "input": {},
        "input_bindings": {},
    }
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        }
    ]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}]
    tick0["event_heads"] = [
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}}
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_non_computer_fire_down(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = {
        "globals": {"config_aim_scheme": [0]},
        "status": {},
        "player_count": 1,
        "players": [],
        "input": {},
        "input_bindings": {},
    }
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        }
    ]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}]
    tick0["event_heads"] = [
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}}
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_computer_fire_when_mode_missing_but_ammo_drops(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["checkpoint"]["players"][0]["ammo"] = 10.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "fired_events": 0}]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["checkpoint"]["players"][0]["ammo"] = 9.0
    tick1["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick1["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}]
    tick1["event_heads"] = [{"kind": "projectile_spawn", "data": {"owner_id": -100}}]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags0 = int(replay.inputs[0][0][3])
    flags1 = int(replay.inputs[1][0][3])
    fire_down0, fire_pressed0, _reload_pressed0 = unpack_input_flags(flags0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down0 is False
    assert fire_pressed0 is False
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_computer_fire_when_reload_completes_then_shot(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["checkpoint"]["players"][0]["ammo"] = 0.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 1}]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["checkpoint"]["players"][0]["ammo"] = 9.0
    tick1["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick1["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 1}]
    tick1["event_heads"] = [
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}}
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags1 = int(replay.inputs[1][0][3])
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_unknown_mode_fire_for_fire_bullets_projectile(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["checkpoint"]["players"][0]["weapon_id"] = 3
    tick0["checkpoint"]["players"][0]["ammo"] = 9.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 3}]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["checkpoint"]["players"][0]["weapon_id"] = 3
    tick1["checkpoint"]["players"][0]["ammo"] = 9.0
    tick1["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick1["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 3}]
    tick1["event_heads"] = [
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 45, "actual_type_id": 45}}
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags1 = int(replay.inputs[1][0][3])
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_unknown_mode_fire_for_secondary_projectile_spawn(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["checkpoint"]["players"][0]["weapon_id"] = 17
    tick0["checkpoint"]["players"][0]["ammo"] = 5.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 17}]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["checkpoint"]["players"][0]["weapon_id"] = 17
    tick1["checkpoint"]["players"][0]["ammo"] = 5.0
    tick1["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick1["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 17}]
    tick1["event_heads"] = [{"kind": "secondary_projectile_spawn", "data": {"requested_type_id": 2, "actual_type_id": 0}}]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags1 = int(replay.inputs[1][0][3])
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_does_not_synthesize_computer_fire_for_bonus_projectile_spawn(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = {
        "globals": {"config_aim_scheme": [5]},
        "status": {},
        "player_count": 1,
        "players": [],
        "input": {},
        "input_bindings": {},
    }
    tick0["checkpoint"]["players"][0]["weapon_id"] = 5
    tick0["checkpoint"]["players"][0]["ammo"] = 12.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 5}]
    tick0["event_heads"] = [
        {"kind": "bonus_apply", "data": {"bonus_id": 8}},
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 9, "actual_type_id": 9}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_computer_fire_for_nuke_fire_bullets_override(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = {
        "globals": {"config_aim_scheme": [5]},
        "status": {},
        "player_count": 1,
        "players": [],
        "input": {},
        "input_bindings": {},
    }
    tick0["checkpoint"]["players"][0]["weapon_id"] = 23
    tick0["checkpoint"]["players"][0]["ammo"] = 6.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 23, "fired_events": 0}]
    tick0["event_heads"] = [
        {"kind": "bonus_apply", "data": {"player_index": 0, "bonus_id": 5}},
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 45}},
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 6, "actual_type_id": 45}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags = int(replay.inputs[0][0][3])
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_secondary_spawn_without_owner_in_multiplayer(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["checkpoint"]["players"] = [_base_player(), _base_player()]
    tick0["input_player_keys"] = [
        {"player_index": 0, "fire_down": False, "fire_pressed": False},
        {"player_index": 1, "fire_down": False, "fire_pressed": False},
    ]
    tick0["input_approx"] = [
        {"player_index": 0, "aim_x": 512.0, "aim_y": 512.0},
        {"player_index": 1, "aim_x": 256.0, "aim_y": 256.0},
    ]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["checkpoint"]["players"] = [_base_player(), _base_player()]
    tick1["input_player_keys"] = [
        {"player_index": 0, "fire_down": False, "fire_pressed": False},
        {"player_index": 1, "fire_down": False, "fire_pressed": False},
    ]
    tick1["input_approx"] = [
        {"player_index": 0, "aim_x": 520.0, "aim_y": 500.0},
        {"player_index": 1, "aim_x": 250.0, "aim_y": 260.0},
    ]
    tick1["event_heads"] = [{"kind": "secondary_projectile_spawn", "data": {"requested_type_id": 2, "actual_type_id": 0}}]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags10 = int(replay.inputs[1][0][3])
    flags11 = int(replay.inputs[1][1][3])
    fire_down10, fire_pressed10, reload_pressed10 = unpack_input_flags(flags10)
    fire_down11, fire_pressed11, reload_pressed11 = unpack_input_flags(flags11)
    assert fire_down10 is False
    assert fire_pressed10 is False
    assert reload_pressed10 is False
    assert fire_down11 is False
    assert fire_pressed11 is False
    assert reload_pressed11 is False


def test_convert_capture_to_replay_applies_aim_scheme_override_for_missing_telemetry(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 2}]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay_default = convert_capture_to_replay(capture)
    replay_override = convert_capture_to_replay(capture, aim_scheme_overrides_by_player={0: 5})

    flags_default = int(replay_default.inputs[0][0][3])
    flags_override = int(replay_override.inputs[0][0][3])
    fire_down_default, _fire_pressed_default, _reload_pressed_default = unpack_input_flags(flags_default)
    fire_down_override, _fire_pressed_override, _reload_pressed_override = unpack_input_flags(flags_override)
    assert fire_down_default is False
    assert fire_down_override is True


def test_parse_player_int_overrides_accepts_equals_and_colon() -> None:
    parsed = parse_player_int_overrides(["0=5", "1:4"], option_name="--aim-scheme-player")
    assert parsed == {0: 5, 1: 4}


def test_parse_player_int_overrides_rejects_bad_entry() -> None:
    with pytest.raises(ValueError):
        parse_player_int_overrides(["nope"], option_name="--aim-scheme-player")


def test_convert_capture_to_replay_does_not_synthesize_unknown_mode_without_weapon_match(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["checkpoint"]["players"][0]["ammo"] = 0.0
    tick0["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick0["input_approx"] = [{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 1}]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["checkpoint"]["players"][0]["ammo"] = 9.0
    tick1["input_player_keys"] = [{"player_index": 0, "fire_down": False, "fire_pressed": False}]
    tick1["input_approx"] = [{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 1}]
    tick1["event_heads"] = [
        {"kind": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 7, "actual_type_id": 7}}
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    flags1 = int(replay.inputs[1][0][3])
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is False
    assert fire_pressed1 is False
    assert reload_pressed1 is False
