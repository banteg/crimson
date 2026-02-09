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
    capture_bootstrap_payload_from_event_payload,
    capture_perk_apply_id_from_event_payload,
    capture_perk_pending_from_event_payload,
    convert_capture_to_checkpoints,
    convert_capture_to_replay,
    default_capture_replay_path,
    load_capture,
)
from crimson.replay import UnknownEvent, unpack_input_flags
from crimson.replay.checkpoints import dump_checkpoints, load_checkpoints


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


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    return {
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
    encoded = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if str(path).endswith(".gz"):
        path.write_bytes(gzip.compress(encoded))
    else:
        path.write_bytes(encoded)


def test_capture_event_payload_helpers_parse_msgspec_payloads() -> None:
    assert capture_bootstrap_payload_from_event_payload([{"elapsed_ms": "123"}]) == {"elapsed_ms": "123"}
    assert capture_perk_apply_id_from_event_payload([{"perk_id": "14"}]) == 14
    assert capture_perk_pending_from_event_payload([{"perk_pending": "2"}]) == 2

    assert capture_bootstrap_payload_from_event_payload([]) is None
    assert capture_bootstrap_payload_from_event_payload(["bad"]) is None
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


def test_load_capture_rejects_unknown_fields(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj["unexpected"] = 1
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
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 1.0,
            "move_dy": -1.0,
            "aim_x": 540.0,
            "aim_y": 500.0,
            "fired_events": 1,
            "reload_active": False,
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
