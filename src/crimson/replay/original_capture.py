from __future__ import annotations

"""Schema + conversion helpers for original-game differential sidecars."""

import gzip
import json
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from grim.geom import Vec2

from ..bonuses import BonusId
from ..game_modes import GameMode
from .checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoint,
    ReplayCheckpoints,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from .types import Replay, ReplayHeader, ReplayStatusSnapshot, UnknownEvent, WEAPON_USAGE_COUNT, pack_input_flags

ORIGINAL_CAPTURE_FORMAT_VERSION = 1
ORIGINAL_CAPTURE_UNKNOWN_INT = -1
ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND = "orig_capture_bootstrap_v1"

_CRT_RAND_MULT = 214013
_CRT_RAND_INC = 2531011
_CRT_RAND_MOD_MASK = 0xFFFFFFFF
_CRT_RAND_INV_MULT = pow(_CRT_RAND_MULT, -1, 1 << 32)

_RAW_TRACE_UNKNOWN_DEATH = ReplayDeathLedgerEntry(
    creature_index=-1,
    type_id=-1,
    reward_value=0.0,
    xp_awarded=-1,
    owner_id=-1,
)


class OriginalCaptureError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OriginalCaptureTick:
    tick_index: int
    state_hash: str
    command_hash: str
    rng_state: int = 0
    elapsed_ms: int = 0
    score_xp: int = 0
    kills: int = 0
    creature_count: int = 0
    perk_pending: int = 0
    players: list[ReplayPlayerCheckpoint] = field(default_factory=list)
    bonus_timers: dict[str, int] = field(default_factory=dict)
    rng_marks: dict[str, int] = field(default_factory=dict)
    deaths: list[ReplayDeathLedgerEntry] = field(default_factory=list)
    perk: ReplayPerkSnapshot = field(default_factory=ReplayPerkSnapshot)
    events: ReplayEventSummary = field(
        default_factory=lambda: ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1)
    )
    game_mode_id: int = -1
    mode_hint: str = ""
    input_primary_edge_true_calls: int = 0
    input_primary_down_true_calls: int = 0
    input_approx: list["OriginalCaptureInputApprox"] = field(default_factory=list)
    frame_dt_ms: float | None = None
    rng_head: list[int] = field(default_factory=list)
    status_quest_unlock_index: int = -1
    status_quest_unlock_index_full: int = -1
    status_weapon_usage_counts: tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class OriginalCaptureInputApprox:
    player_index: int
    move_dx: float = 0.0
    move_dy: float = 0.0
    aim_x: float = 0.0
    aim_y: float = 0.0
    aim_heading: float | None = None
    fired_events: int = 0
    reload_active: bool = False
    move_forward_pressed: bool | None = None
    move_backward_pressed: bool | None = None
    turn_left_pressed: bool | None = None
    turn_right_pressed: bool | None = None
    fire_down: bool | None = None
    fire_pressed: bool | None = None


@dataclass(frozen=True, slots=True)
class OriginalCaptureSidecar:
    version: int
    sample_rate: int
    ticks: list[OriginalCaptureTick]
    replay_sha256: str = ""


def _int_or(value: object, default: int) -> int:
    if value is None:
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _float_or(value: object, default: float) -> float:
    if value is None:
        return float(default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _parse_player(raw: object) -> ReplayPlayerCheckpoint:
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"player must be an object: {raw!r}")
    pos_raw = raw.get("pos") or {}
    if not isinstance(pos_raw, dict):
        raise OriginalCaptureError("player.pos must be an object")
    return ReplayPlayerCheckpoint(
        pos=Vec2(float(pos_raw.get("x", 0.0)), float(pos_raw.get("y", 0.0))),
        health=float(raw.get("health", 0.0)),
        weapon_id=int(raw.get("weapon_id", 0)),
        ammo=float(raw.get("ammo", 0.0)),
        experience=int(raw.get("experience", 0)),
        level=int(raw.get("level", 0)),
    )


def _parse_death(raw: object) -> ReplayDeathLedgerEntry:
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"death entry must be an object: {raw!r}")
    return ReplayDeathLedgerEntry(
        creature_index=int(raw.get("creature_index", -1)),
        type_id=int(raw.get("type_id", 0)),
        reward_value=float(raw.get("reward_value", 0.0)),
        xp_awarded=int(raw.get("xp_awarded", 0)),
        owner_id=int(raw.get("owner_id", -100)),
    )


def _parse_perk(raw: object) -> ReplayPerkSnapshot:
    if not isinstance(raw, dict):
        return ReplayPerkSnapshot()
    raw_choices = raw.get("choices") or []
    raw_counts = raw.get("player_nonzero_counts") or []
    choices = [int(value) for value in raw_choices] if isinstance(raw_choices, list) else []

    player_nonzero_counts: list[list[list[int]]] = []
    if isinstance(raw_counts, list):
        for player_counts in raw_counts:
            if not isinstance(player_counts, list):
                player_nonzero_counts.append([])
                continue
            parsed_player: list[list[int]] = []
            for pair in player_counts:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    parsed_player.append([int(pair[0]), int(pair[1])])
            player_nonzero_counts.append(parsed_player)

    return ReplayPerkSnapshot(
        pending_count=int(raw.get("pending_count", 0)),
        choices_dirty=bool(raw.get("choices_dirty", False)),
        choices=choices,
        player_nonzero_counts=player_nonzero_counts,
    )


def _parse_events(raw: object) -> ReplayEventSummary:
    if raw is None:
        return ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[])
    if not isinstance(raw, dict):
        raise OriginalCaptureError("events must be an object")
    sfx_head_raw = raw.get("sfx_head") or []
    if not isinstance(sfx_head_raw, list):
        raise OriginalCaptureError("events.sfx_head must be a list")
    return ReplayEventSummary(
        hit_count=int(raw.get("hit_count", -1)),
        pickup_count=int(raw.get("pickup_count", -1)),
        sfx_count=int(raw.get("sfx_count", -1)),
        sfx_head=[str(value) for value in sfx_head_raw[:4]],
    )


def _coerce_int_like(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _coerce_float_like(value: object) -> float | None:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        out = float(value)
        if not math.isfinite(out):
            return None
        return out
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            out = float(text)
        except ValueError:
            return None
        if not math.isfinite(out):
            return None
        return out
    return None


def _parse_frame_dt_ms_from_globals(globals_obj: dict[str, object]) -> float | None:
    dt_ms_i32 = _coerce_int_like(globals_obj.get("frame_dt_ms_i32"))
    if dt_ms_i32 is not None and int(dt_ms_i32) > 0:
        return float(dt_ms_i32)

    dt_ms_f32 = _coerce_float_like(globals_obj.get("frame_dt_ms_f32"))
    if dt_ms_f32 is not None and float(dt_ms_f32) > 0.0:
        return float(dt_ms_f32)

    dt_seconds = _coerce_float_like(globals_obj.get("frame_dt"))
    if dt_seconds is not None and float(dt_seconds) > 0.0:
        return float(dt_seconds) * 1000.0

    return None


def _parse_int_map(raw: object, name: str) -> dict[str, int]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"{name} must be an object")
    out: dict[str, int] = {}
    for key, value in raw.items():
        coerced = _coerce_int_like(value)
        if coerced is not None:
            out[str(key)] = coerced
    return out


def _parse_rng_head(raw_rng_marks: object) -> list[int]:
    if not isinstance(raw_rng_marks, dict):
        return []
    rand_head_raw = raw_rng_marks.get("rand_head")
    if not isinstance(rand_head_raw, list):
        return []
    out: list[int] = []
    for item in rand_head_raw:
        if isinstance(item, dict):
            value = _coerce_int_like(item.get("value"))
        else:
            value = _coerce_int_like(item)
        if value is None:
            continue
        if 0 <= int(value) <= 0x7FFF:
            out.append(int(value))
    return out


def _parse_status_snapshot(raw: object) -> tuple[int, int, tuple[int, ...]]:
    if not isinstance(raw, dict):
        return (-1, -1, ())

    unlock_index = _coerce_int_like(raw.get("quest_unlock_index"))
    unlock_index_full = _coerce_int_like(raw.get("quest_unlock_index_full"))

    counts_out: list[int] = []
    counts_raw = raw.get("weapon_usage_counts")
    if isinstance(counts_raw, list):
        for value in counts_raw[:WEAPON_USAGE_COUNT]:
            coerced = _coerce_int_like(value)
            counts_out.append(0 if coerced is None else int(coerced) & 0xFFFFFFFF)

    return (
        -1 if unlock_index is None else int(unlock_index),
        -1 if unlock_index_full is None else int(unlock_index_full),
        tuple(counts_out),
    )


def _parse_tick(raw: object) -> OriginalCaptureTick:
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"tick must be an object: {raw!r}")

    players_raw = raw.get("players") or []
    if not isinstance(players_raw, list):
        raise OriginalCaptureError("tick.players must be a list")
    players = [_parse_player(item) for item in players_raw]

    deaths_raw = raw.get("deaths") or []
    if not isinstance(deaths_raw, list):
        raise OriginalCaptureError("tick.deaths must be a list")
    deaths = [_parse_death(item) for item in deaths_raw]

    bonus_timers = _parse_int_map(raw.get("bonus_timers") or {}, "tick.bonus_timers")
    raw_rng_marks = raw.get("rng_marks") or {}
    rng_marks = _parse_int_map(raw_rng_marks, "tick.rng_marks")
    rng_head = _parse_rng_head(raw_rng_marks)
    status_unlock_index, status_unlock_index_full, status_weapon_usage_counts = _parse_status_snapshot(raw.get("status"))
    mode_hint = str(raw.get("mode_hint", ""))
    game_mode_id = _int_or(raw.get("game_mode_id"), -1)
    input_primary_edge_true_calls = _int_or(raw.get("input_primary_edge_true_calls"), 0)
    input_primary_down_true_calls = _int_or(raw.get("input_primary_down_true_calls"), 0)
    input_approx = _parse_input_approx(raw.get("input_approx"))
    frame_dt_ms = _coerce_float_like(raw.get("frame_dt_ms"))
    if frame_dt_ms is not None and float(frame_dt_ms) <= 0.0:
        frame_dt_ms = None
    input_queries_raw = raw.get("input_queries")
    if isinstance(input_queries_raw, dict):
        stats_raw = input_queries_raw.get("stats")
        if isinstance(stats_raw, dict):
            input_primary_edge_true_calls = _int_or(
                (stats_raw.get("primary_edge") or {}).get("true_calls")
                if isinstance(stats_raw.get("primary_edge"), dict)
                else None,
                input_primary_edge_true_calls,
            )
            input_primary_down_true_calls = _int_or(
                (stats_raw.get("primary_down") or {}).get("true_calls")
                if isinstance(stats_raw.get("primary_down"), dict)
                else None,
                input_primary_down_true_calls,
            )

    return OriginalCaptureTick(
        tick_index=int(raw.get("tick_index", 0)),
        state_hash=str(raw.get("state_hash", "")),
        command_hash=str(raw.get("command_hash", "")),
        rng_state=int(raw.get("rng_state", 0)),
        elapsed_ms=int(raw.get("elapsed_ms", 0)),
        score_xp=int(raw.get("score_xp", 0)),
        kills=int(raw.get("kills", 0)),
        creature_count=int(raw.get("creature_count", 0)),
        perk_pending=int(raw.get("perk_pending", 0)),
        players=players,
        bonus_timers=bonus_timers,
        rng_marks=rng_marks,
        deaths=deaths,
        perk=_parse_perk(raw.get("perk")),
        events=_parse_events(raw.get("events")),
        game_mode_id=game_mode_id,
        mode_hint=mode_hint,
        input_primary_edge_true_calls=input_primary_edge_true_calls,
        input_primary_down_true_calls=input_primary_down_true_calls,
        input_approx=input_approx,
        frame_dt_ms=frame_dt_ms,
        rng_head=rng_head,
        status_quest_unlock_index=int(status_unlock_index),
        status_quest_unlock_index_full=int(status_unlock_index_full),
        status_weapon_usage_counts=tuple(status_weapon_usage_counts),
    )


def _iter_jsonl_objects(path: Path) -> Iterator[dict[str, object]]:
    if str(path).lower().endswith(".gz"):
        handle = gzip.open(path, mode="rt", encoding="utf-8")
    else:
        handle = path.open(mode="rt", encoding="utf-8")
    with handle:
        for line in handle:
            row = line.strip()
            if not row:
                continue
            try:
                obj = json.loads(row)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _round4(value: float) -> float:
    return round(float(value), 4)


def _bonus_timer_ms_or_unknown(value: object) -> int:
    if value is None:
        return ORIGINAL_CAPTURE_UNKNOWN_INT
    try:
        ms = int(round(float(value) * 1000.0))
    except (TypeError, ValueError):
        return ORIGINAL_CAPTURE_UNKNOWN_INT
    if ms < 0:
        return 0
    return ms


def _parse_input_approx(raw: object) -> list[OriginalCaptureInputApprox]:
    if not isinstance(raw, list):
        return []
    samples_by_player: dict[int, OriginalCaptureInputApprox] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        player_index = _int_or(item.get("player_index"), len(samples_by_player))
        if player_index < 0:
            continue
        samples_by_player[int(player_index)] = OriginalCaptureInputApprox(
            player_index=int(player_index),
            move_dx=_float_or(item.get("move_dx"), 0.0),
            move_dy=_float_or(item.get("move_dy"), 0.0),
            aim_x=_float_or(item.get("aim_x"), 0.0),
            aim_y=_float_or(item.get("aim_y"), 0.0),
            aim_heading=_float_or(item.get("aim_heading"), 0.0) if item.get("aim_heading") is not None else None,
            fired_events=_int_or(item.get("fired_events"), 0),
            reload_active=bool(item.get("reload_active", False)),
            move_forward_pressed=(
                bool(item.get("move_forward_pressed")) if item.get("move_forward_pressed") is not None else None
            ),
            move_backward_pressed=(
                bool(item.get("move_backward_pressed")) if item.get("move_backward_pressed") is not None else None
            ),
            turn_left_pressed=bool(item.get("turn_left_pressed")) if item.get("turn_left_pressed") is not None else None,
            turn_right_pressed=(
                bool(item.get("turn_right_pressed")) if item.get("turn_right_pressed") is not None else None
            ),
            fire_down=bool(item.get("fire_down")) if item.get("fire_down") is not None else None,
            fire_pressed=bool(item.get("fire_pressed")) if item.get("fire_pressed") is not None else None,
        )
    return [samples_by_player[idx] for idx in sorted(samples_by_player)]


def _parse_v2_game_mode_id(raw: dict[str, object]) -> int:
    for scope_name in ("after", "before"):
        scope_raw = raw.get(scope_name)
        if not isinstance(scope_raw, dict):
            continue
        globals_raw = scope_raw.get("globals")
        if not isinstance(globals_raw, dict):
            continue
        mode = globals_raw.get("config_game_mode")
        mode_id = _coerce_int_like(mode)
        if mode_id is not None and int(mode_id) >= 0:
            return int(mode_id)
    return -1


def _parse_v2_frame_dt_ms(raw: dict[str, object]) -> float | None:
    for scope_name in ("after", "before"):
        scope_raw = raw.get(scope_name)
        if not isinstance(scope_raw, dict):
            continue
        globals_raw = scope_raw.get("globals")
        if not isinstance(globals_raw, dict):
            continue
        frame_dt_ms = _parse_frame_dt_ms_from_globals(globals_raw)
        if frame_dt_ms is not None and float(frame_dt_ms) > 0.0:
            return float(frame_dt_ms)
    return None


def _parse_v2_input_query_true_calls(raw: dict[str, object], key: str) -> int:
    input_queries = raw.get("input_queries")
    if not isinstance(input_queries, dict):
        return 0
    stats_raw = input_queries.get("stats")
    if not isinstance(stats_raw, dict):
        return 0
    stat_raw = stats_raw.get(key)
    if not isinstance(stat_raw, dict):
        return 0
    return _int_or(stat_raw.get("true_calls"), 0)


def _parse_v2_pressed_key_codes(raw: dict[str, object]) -> set[int]:
    event_heads = raw.get("event_heads")
    if not isinstance(event_heads, dict):
        return set()
    pressed: set[int] = set()
    for kind in ("input_any_key", "input_primary_down", "input_primary_edge"):
        entries = event_heads.get(kind)
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            query = str(item.get("query", ""))
            if not query.startswith("grim_"):
                continue
            key_code = _coerce_int_like(item.get("arg0"))
            if key_code is None:
                continue
            pressed.add(int(key_code))
    return pressed


def _parse_v2_player_keybinds(raw: dict[str, object]) -> list[dict[str, int | None]]:
    before_raw = raw.get("before")
    if not isinstance(before_raw, dict):
        return []
    input_bindings = before_raw.get("input_bindings")
    if not isinstance(input_bindings, dict):
        return []
    players_raw = input_bindings.get("players")
    if not isinstance(players_raw, list):
        return []
    out: list[dict[str, int | None]] = []
    for item in players_raw:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "move_forward": _coerce_int_like(item.get("move_forward")),
                "move_backward": _coerce_int_like(item.get("move_backward")),
                "turn_left": _coerce_int_like(item.get("turn_left")),
                "turn_right": _coerce_int_like(item.get("turn_right")),
                "fire": _coerce_int_like(item.get("fire")),
            }
        )
    return out


def _parse_v2_aim_heading_by_player(raw: dict[str, object]) -> dict[int, float]:
    after_raw = raw.get("after")
    if not isinstance(after_raw, dict):
        return {}
    players_raw = after_raw.get("players")
    if not isinstance(players_raw, list):
        return {}
    out: dict[int, float] = {}
    for idx, item in enumerate(players_raw):
        if not isinstance(item, dict):
            continue
        heading_raw = item.get("aim_heading")
        if not isinstance(heading_raw, (int, float)):
            continue
        heading = float(heading_raw)
        if not math.isfinite(heading):
            continue
        out[int(idx)] = heading
    return out


def _enrich_v2_input_approx(
    raw: dict[str, object],
    *,
    samples: list[OriginalCaptureInputApprox],
) -> list[OriginalCaptureInputApprox]:
    by_player: dict[int, OriginalCaptureInputApprox] = {int(sample.player_index): sample for sample in samples}
    pressed_key_codes = _parse_v2_pressed_key_codes(raw)
    keybinds = _parse_v2_player_keybinds(raw)
    aim_heading_by_player = _parse_v2_aim_heading_by_player(raw)
    player_count = max(
        len(keybinds),
        len(aim_heading_by_player),
        (max(by_player) + 1) if by_player else 0,
    )

    for player_index in range(int(player_count)):
        existing = by_player.get(int(player_index))
        if existing is None:
            existing = OriginalCaptureInputApprox(player_index=int(player_index))

        keybind = keybinds[player_index] if player_index < len(keybinds) else {}
        move_forward_key = keybind.get("move_forward")
        move_backward_key = keybind.get("move_backward")
        turn_left_key = keybind.get("turn_left")
        turn_right_key = keybind.get("turn_right")
        fire_key = keybind.get("fire")

        move_forward_pressed = existing.move_forward_pressed
        move_backward_pressed = existing.move_backward_pressed
        turn_left_pressed = existing.turn_left_pressed
        turn_right_pressed = existing.turn_right_pressed
        fire_down = existing.fire_down
        aim_heading = existing.aim_heading

        if move_forward_key is not None:
            move_forward_pressed = bool(int(move_forward_key) in pressed_key_codes)
        if move_backward_key is not None:
            move_backward_pressed = bool(int(move_backward_key) in pressed_key_codes)
        if turn_left_key is not None:
            turn_left_pressed = bool(int(turn_left_key) in pressed_key_codes)
        if turn_right_key is not None:
            turn_right_pressed = bool(int(turn_right_key) in pressed_key_codes)
        if fire_key is not None:
            fire_down = bool(int(fire_key) in pressed_key_codes)
        if int(player_index) in aim_heading_by_player:
            aim_heading = float(aim_heading_by_player[int(player_index)])

        by_player[int(player_index)] = OriginalCaptureInputApprox(
            player_index=int(player_index),
            move_dx=float(existing.move_dx),
            move_dy=float(existing.move_dy),
            aim_x=float(existing.aim_x),
            aim_y=float(existing.aim_y),
            aim_heading=aim_heading,
            fired_events=int(existing.fired_events),
            reload_active=bool(existing.reload_active),
            move_forward_pressed=move_forward_pressed,
            move_backward_pressed=move_backward_pressed,
            turn_left_pressed=turn_left_pressed,
            turn_right_pressed=turn_right_pressed,
            fire_down=fire_down,
            fire_pressed=existing.fire_pressed,
        )

    return [by_player[idx] for idx in sorted(by_player)]


def _parse_trace_players(raw: object) -> list[ReplayPlayerCheckpoint]:
    if not isinstance(raw, list):
        return []
    out: list[ReplayPlayerCheckpoint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ammo = item.get("ammo_f32")
        if ammo is None:
            ammo = item.get("ammo_i32")
        out.append(
            ReplayPlayerCheckpoint(
                pos=Vec2(
                    _round4(_float_or(item.get("pos_x"), 0.0)),
                    _round4(_float_or(item.get("pos_y"), 0.0)),
                ),
                health=_round4(_float_or(item.get("health"), 0.0)),
                weapon_id=_int_or(item.get("weapon_id"), 0),
                ammo=_round4(_float_or(ammo, 0.0)),
                experience=_int_or(item.get("experience"), 0),
                level=_int_or(item.get("level"), 0),
            )
        )
    return out


def _estimate_sample_rate(frames: list[int]) -> int:
    if len(frames) < 2:
        return 1
    deltas = [next_frame - frame for frame, next_frame in zip(frames, frames[1:]) if int(next_frame) > int(frame)]
    if not deltas:
        return 1
    deltas.sort()
    return max(1, int(deltas[len(deltas) // 2]))


def _load_original_capture_v2_ticks(path: Path) -> OriginalCaptureSidecar | None:
    ticks_by_index: dict[int, OriginalCaptureTick] = {}
    saw_tick_rows = False
    for obj in _iter_jsonl_objects(path):
        if obj.get("event") != "tick":
            continue
        saw_tick_rows = True
        raw_checkpoint = obj.get("checkpoint")
        checkpoint_obj = raw_checkpoint if isinstance(raw_checkpoint, dict) else obj
        parsed = _parse_tick(checkpoint_obj)
        tick_index = _int_or(checkpoint_obj.get("tick_index"), _int_or(obj.get("tick_index"), parsed.tick_index))
        mode_hint = str(obj.get("mode_hint", parsed.mode_hint))
        game_mode_id = _parse_v2_game_mode_id(obj)
        frame_dt_ms = _parse_v2_frame_dt_ms(obj)
        input_primary_edge_true_calls = _parse_v2_input_query_true_calls(obj, "primary_edge")
        input_primary_down_true_calls = _parse_v2_input_query_true_calls(obj, "primary_down")
        input_approx = _enrich_v2_input_approx(
            obj,
            samples=_parse_input_approx(obj.get("input_approx")),
        )
        ticks_by_index[int(tick_index)] = OriginalCaptureTick(
            tick_index=int(tick_index),
            state_hash=parsed.state_hash,
            command_hash=parsed.command_hash,
            rng_state=parsed.rng_state,
            elapsed_ms=parsed.elapsed_ms,
            score_xp=parsed.score_xp,
            kills=parsed.kills,
            creature_count=parsed.creature_count,
            perk_pending=parsed.perk_pending,
            players=list(parsed.players),
            bonus_timers=dict(parsed.bonus_timers),
            rng_marks=dict(parsed.rng_marks),
            deaths=list(parsed.deaths),
            perk=parsed.perk,
            events=parsed.events,
            game_mode_id=game_mode_id if game_mode_id >= 0 else int(parsed.game_mode_id),
            mode_hint=mode_hint,
            input_primary_edge_true_calls=(
                int(input_primary_edge_true_calls)
                if input_primary_edge_true_calls > 0
                else int(parsed.input_primary_edge_true_calls)
            ),
            input_primary_down_true_calls=(
                int(input_primary_down_true_calls)
                if input_primary_down_true_calls > 0
                else int(parsed.input_primary_down_true_calls)
            ),
            input_approx=list(input_approx) if input_approx else list(parsed.input_approx),
            frame_dt_ms=float(frame_dt_ms) if frame_dt_ms is not None else parsed.frame_dt_ms,
            rng_head=list(parsed.rng_head),
            status_quest_unlock_index=int(parsed.status_quest_unlock_index),
            status_quest_unlock_index_full=int(parsed.status_quest_unlock_index_full),
            status_weapon_usage_counts=tuple(parsed.status_weapon_usage_counts),
        )

    if not saw_tick_rows:
        return None
    if not ticks_by_index:
        raise OriginalCaptureError(f"raw trace has tick events but no parseable checkpoints: {path}")

    tick_indices = sorted(ticks_by_index)
    ticks = [ticks_by_index[idx] for idx in tick_indices]
    return OriginalCaptureSidecar(
        version=ORIGINAL_CAPTURE_FORMAT_VERSION,
        sample_rate=_estimate_sample_rate(tick_indices),
        ticks=ticks,
        replay_sha256="",
    )


def _tick_from_trace_snapshot(frame: int, raw_snapshot: dict[str, object]) -> OriginalCaptureTick:
    globals_raw = raw_snapshot.get("globals")
    globals_obj = globals_raw if isinstance(globals_raw, dict) else {}

    players = _parse_trace_players(raw_snapshot.get("players"))
    score_xp = (
        int(sum(int(player.experience) for player in players))
        if players
        else ORIGINAL_CAPTURE_UNKNOWN_INT
    )

    return OriginalCaptureTick(
        # gameplay_frame increments before gameplay_update_and_render executes.
        tick_index=max(0, int(frame) - 1),
        state_hash="",
        command_hash="",
        rng_state=ORIGINAL_CAPTURE_UNKNOWN_INT,
        elapsed_ms=_int_or(globals_obj.get("time_played_ms"), ORIGINAL_CAPTURE_UNKNOWN_INT),
        score_xp=score_xp,
        kills=ORIGINAL_CAPTURE_UNKNOWN_INT,
        creature_count=_int_or(globals_obj.get("creature_active_count"), ORIGINAL_CAPTURE_UNKNOWN_INT),
        perk_pending=_int_or(globals_obj.get("perk_pending_count"), ORIGINAL_CAPTURE_UNKNOWN_INT),
        players=players,
        bonus_timers={
            str(BonusId.WEAPON_POWER_UP): _bonus_timer_ms_or_unknown(
                globals_obj.get("bonus_weapon_power_up_timer")
            ),
            str(BonusId.REFLEX_BOOST): _bonus_timer_ms_or_unknown(globals_obj.get("bonus_reflex_boost_timer")),
            str(BonusId.ENERGIZER): _bonus_timer_ms_or_unknown(globals_obj.get("bonus_energizer_timer")),
            str(BonusId.DOUBLE_EXPERIENCE): _bonus_timer_ms_or_unknown(globals_obj.get("bonus_double_xp_timer")),
            str(BonusId.FREEZE): _bonus_timer_ms_or_unknown(globals_obj.get("bonus_freeze_timer")),
        },
        deaths=[_RAW_TRACE_UNKNOWN_DEATH],
        perk=ReplayPerkSnapshot(pending_count=ORIGINAL_CAPTURE_UNKNOWN_INT),
        events=ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[]),
        frame_dt_ms=_parse_frame_dt_ms_from_globals(globals_obj),
    )


def _infer_game_mode_id(capture: OriginalCaptureSidecar) -> int:
    for tick in capture.ticks:
        if int(tick.game_mode_id) >= 0:
            return int(tick.game_mode_id)

    mode_hint_to_game_mode = {
        "survival_update": int(GameMode.SURVIVAL),
        "rush_mode_update": int(GameMode.RUSH),
        "quest_mode_update": int(GameMode.QUESTS),
        "typo_gameplay_update_and_render": int(GameMode.TYPO),
    }
    for tick in capture.ticks:
        mode_hint = str(tick.mode_hint)
        if mode_hint in mode_hint_to_game_mode:
            return int(mode_hint_to_game_mode[mode_hint])
    return int(GameMode.SURVIVAL)


def _infer_player_count(capture: OriginalCaptureSidecar) -> int:
    player_count = 1
    for tick in capture.ticks:
        player_count = max(player_count, int(len(tick.players)))
        for sample in tick.input_approx:
            player_count = max(player_count, int(sample.player_index) + 1)
    return max(1, int(player_count))


def _infer_status_snapshot(capture: OriginalCaptureSidecar) -> ReplayStatusSnapshot:
    unlock_index = -1
    unlock_index_full = -1
    usage_counts: tuple[int, ...] = ()

    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        if int(unlock_index) < 0 and int(tick.status_quest_unlock_index) >= 0:
            unlock_index = int(tick.status_quest_unlock_index)
        if int(unlock_index_full) < 0 and int(tick.status_quest_unlock_index_full) >= 0:
            unlock_index_full = int(tick.status_quest_unlock_index_full)
        if not usage_counts and tick.status_weapon_usage_counts:
            usage_counts = tuple(int(value) & 0xFFFFFFFF for value in tick.status_weapon_usage_counts)
        if int(unlock_index) >= 0 and int(unlock_index_full) >= 0 and usage_counts:
            break

    counts = list(usage_counts[:WEAPON_USAGE_COUNT])
    if len(counts) < WEAPON_USAGE_COUNT:
        counts.extend([0] * (WEAPON_USAGE_COUNT - len(counts)))

    return ReplayStatusSnapshot(
        quest_unlock_index=max(0, int(unlock_index)),
        quest_unlock_index_full=max(0, int(unlock_index_full)),
        weapon_usage_counts=tuple(int(value) & 0xFFFFFFFF for value in counts),
    )


def _crt_rand_step(state: int) -> tuple[int, int]:
    next_state = (int(state) * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MOD_MASK
    return int(next_state), int((next_state >> 16) & 0x7FFF)


def _seed_matches_rng_marks(
    seed: int,
    *,
    rng_head: list[int],
    rand_calls: object,
    rand_last: object,
) -> bool:
    if not rng_head:
        return False

    parsed_rand_calls = _coerce_int_like(rand_calls)
    parsed_rand_last = _coerce_int_like(rand_last)
    required_calls = len(rng_head)
    if parsed_rand_calls is not None and int(parsed_rand_calls) > 0:
        required_calls = max(required_calls, int(parsed_rand_calls))

    state = int(seed) & _CRT_RAND_MOD_MASK
    output_at_rand_calls: int | None = None
    for call_idx in range(1, int(required_calls) + 1):
        state, out = _crt_rand_step(state)
        if call_idx <= len(rng_head) and int(out) != int(rng_head[call_idx - 1]):
            return False
        if parsed_rand_calls is not None and int(parsed_rand_calls) > 0 and int(call_idx) == int(parsed_rand_calls):
            output_at_rand_calls = int(out)

    if parsed_rand_calls is not None and int(parsed_rand_calls) > 0 and parsed_rand_last is not None:
        if output_at_rand_calls is None:
            return False
        return int(output_at_rand_calls) == int(parsed_rand_last)

    return True


def _infer_seed_from_rng_head(
    *,
    rng_head: list[int],
    rand_calls: object,
    rand_last: object,
) -> int | None:
    if not rng_head:
        return None

    first_rand = int(rng_head[0])
    if first_rand < 0 or first_rand > 0x7FFF:
        return None

    best: int | None = None
    for high_word in (int(first_rand), int(first_rand) | 0x8000):
        state_prefix = int(high_word) << 16
        for state_low in range(0x10000):
            state_after_first = (int(state_prefix) | int(state_low)) & _CRT_RAND_MOD_MASK
            seed = ((int(state_after_first) - _CRT_RAND_INC) * _CRT_RAND_INV_MULT) & _CRT_RAND_MOD_MASK
            if not _seed_matches_rng_marks(
                int(seed),
                rng_head=rng_head,
                rand_calls=rand_calls,
                rand_last=rand_last,
            ):
                continue
            # Seeds that differ only by bit 31 produce the same rand() stream.
            canonical_seed = int(seed) & 0x7FFFFFFF
            if best is None or int(canonical_seed) < int(best):
                best = int(canonical_seed)
    return best


def infer_original_capture_seed(capture: OriginalCaptureSidecar) -> int:
    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        rng_head = [int(value) for value in tick.rng_head if 0 <= int(value) <= 0x7FFF]
        if not rng_head:
            continue
        seed = _infer_seed_from_rng_head(
            rng_head=rng_head,
            rand_calls=tick.rng_marks.get("rand_calls"),
            rand_last=tick.rng_marks.get("rand_last"),
        )
        if seed is not None:
            return int(seed)
    return 0


def build_original_capture_dt_frame_overrides(
    capture: OriginalCaptureSidecar,
    *,
    tick_rate: int = 60,
) -> dict[int, float]:
    """Build per-tick frame dt overrides (seconds) from capture elapsed deltas.

    The returned mapping is sparse:
    - keys are replay tick indices,
    - values are `dt_frame` seconds to use for that tick.

    Deltas are distributed across gaps so sampled captures (e.g. every Nth frame)
    still produce per-frame timing overrides for intermediate ticks.
    """

    nominal_tick_rate = max(1, int(tick_rate))
    nominal_dt = 1.0 / float(nominal_tick_rate)
    if not capture.ticks:
        return {}

    sorted_ticks = sorted(capture.ticks, key=lambda item: int(item.tick_index))
    out: dict[int, float] = {}
    explicit_overrides: dict[int, float] = {}
    last_timed_tick: int | None = None
    last_timed_elapsed_ms: int | None = None

    for tick in sorted_ticks:
        tick_index = int(tick.tick_index)
        if tick.frame_dt_ms is not None:
            dt_frame = float(tick.frame_dt_ms) / 1000.0
            if math.isfinite(dt_frame) and dt_frame > 0.0:
                explicit_overrides[int(tick_index)] = float(dt_frame)
        elapsed_ms = int(tick.elapsed_ms)
        if elapsed_ms < 0:
            continue

        if last_timed_tick is not None and last_timed_elapsed_ms is not None:
            gap = int(tick_index) - int(last_timed_tick)
            delta_ms = int(elapsed_ms) - int(last_timed_elapsed_ms)
            if gap > 0 and delta_ms > 0:
                dt_frame = float(delta_ms) / float(gap) / 1000.0
                if math.isfinite(dt_frame) and dt_frame > 0.0:
                    for step_tick in range(int(last_timed_tick) + 1, int(tick_index) + 1):
                        out[int(step_tick)] = float(dt_frame)

        last_timed_tick = int(tick_index)
        last_timed_elapsed_ms = int(elapsed_ms)

    # Prefer direct per-tick frame timing samples (includes tick 0 when available).
    out.update(explicit_overrides)

    # Trim values that are effectively nominal to keep sparse overrides compact.
    for tick_index in list(out.keys()):
        if int(tick_index) in explicit_overrides:
            continue
        if math.isclose(float(out[tick_index]), float(nominal_dt), rel_tol=1e-9, abs_tol=1e-9):
            del out[tick_index]

    return out


def _capture_bootstrap_payload(tick: OriginalCaptureTick) -> dict[str, object]:
    players: list[dict[str, object]] = []
    for player in tick.players:
        players.append(
            {
                "pos": {"x": float(player.pos.x), "y": float(player.pos.y)},
                "health": float(player.health),
                "weapon_id": int(player.weapon_id),
                "ammo": float(player.ammo),
                "experience": int(player.experience),
                "level": int(player.level),
            }
        )
    return {
        "tick_index": int(tick.tick_index),
        "elapsed_ms": int(tick.elapsed_ms),
        "score_xp": int(tick.score_xp),
        "perk_pending": int(tick.perk_pending),
        "bonus_timers_ms": dict(tick.bonus_timers),
        "players": players,
    }


def original_capture_bootstrap_payload_from_event_payload(payload: list[object]) -> dict[str, object] | None:
    if not payload:
        return None
    first = payload[0]
    if not isinstance(first, dict):
        return None
    return first


def apply_original_capture_bootstrap_payload(
    payload: dict[str, object],
    *,
    state: object,
    players: list[object],
) -> int | None:
    from ..gameplay import weapon_assign_player

    elapsed_ms: int | None = None
    elapsed_raw = _coerce_int_like(payload.get("elapsed_ms"))
    if elapsed_raw is not None and int(elapsed_raw) >= 0:
        elapsed_ms = int(elapsed_raw)

    players_raw = payload.get("players")
    if isinstance(players_raw, list):
        for idx, raw_player in enumerate(players_raw):
            if idx >= len(players):
                break
            if not isinstance(raw_player, dict):
                continue
            player = players[idx]

            weapon_id = _coerce_int_like(raw_player.get("weapon_id"))
            if weapon_id is not None and int(weapon_id) > 0:
                try:
                    if int(getattr(player, "weapon_id", 0)) != int(weapon_id):
                        weapon_assign_player(player, int(weapon_id), state=state)
                except Exception:
                    pass

            pos_raw = raw_player.get("pos")
            if isinstance(pos_raw, dict):
                px = _float_or(pos_raw.get("x"), float(getattr(player, "pos").x))
                py = _float_or(pos_raw.get("y"), float(getattr(player, "pos").y))
                if math.isfinite(px) and math.isfinite(py):
                    setattr(player, "pos", Vec2(float(px), float(py)))

            health = _float_or(raw_player.get("health"), float(getattr(player, "health")))
            ammo = _float_or(raw_player.get("ammo"), float(getattr(player, "ammo")))
            experience = _coerce_int_like(raw_player.get("experience"))
            level = _coerce_int_like(raw_player.get("level"))

            setattr(player, "health", float(health))
            setattr(player, "ammo", float(ammo))
            if experience is not None:
                setattr(player, "experience", int(experience))
            if level is not None and int(level) > 0:
                setattr(player, "level", int(level))

    pending = _coerce_int_like(payload.get("perk_pending"))
    if pending is not None and int(pending) >= 0:
        try:
            state.perk_selection.pending_count = int(pending)
            state.perk_selection.choices_dirty = True
        except Exception:
            pass

    timers_raw = payload.get("bonus_timers_ms")
    if isinstance(timers_raw, dict):
        try:
            weapon_power_up_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.WEAPON_POWER_UP))))
            reflex_boost_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.REFLEX_BOOST))))
            energizer_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.ENERGIZER))))
            double_xp_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.DOUBLE_EXPERIENCE))))
            freeze_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.FREEZE))))
            if weapon_power_up_ms is not None:
                state.bonuses.weapon_power_up = max(0.0, float(weapon_power_up_ms) / 1000.0)
            if reflex_boost_ms is not None:
                state.bonuses.reflex_boost = max(0.0, float(reflex_boost_ms) / 1000.0)
            if energizer_ms is not None:
                state.bonuses.energizer = max(0.0, float(energizer_ms) / 1000.0)
            if double_xp_ms is not None:
                state.bonuses.double_experience = max(0.0, float(double_xp_ms) / 1000.0)
            if freeze_ms is not None:
                state.bonuses.freeze = max(0.0, float(freeze_ms) / 1000.0)
        except Exception:
            pass

    return elapsed_ms


def _load_original_capture_gameplay_trace(path: Path) -> OriginalCaptureSidecar:
    v2 = _load_original_capture_v2_ticks(path)
    if v2 is not None:
        return v2

    snapshots_by_frame: dict[int, dict[str, object]] = {}
    saw_snapshots = False
    for obj in _iter_jsonl_objects(path):
        event = obj.get("event")
        if event not in ("snapshot_compact", "snapshot_full"):
            continue
        saw_snapshots = True
        frame = _int_or(obj.get("gameplay_frame"), -1)
        if int(frame) <= 0:
            continue
        globals_raw = obj.get("globals")
        globals_obj = globals_raw if isinstance(globals_raw, dict) else {}
        if _int_or(globals_obj.get("game_state_id"), -1) < 0:
            continue
        snapshots_by_frame[int(frame)] = obj

    if not saw_snapshots:
        raise OriginalCaptureError(f"raw trace has no snapshot events: {path}")
    if not snapshots_by_frame:
        raise OriginalCaptureError(f"raw trace has no gameplay snapshots with gameplay_frame>0: {path}")

    frames = sorted(snapshots_by_frame)
    ticks = [_tick_from_trace_snapshot(frame, snapshots_by_frame[frame]) for frame in frames]
    return OriginalCaptureSidecar(
        version=ORIGINAL_CAPTURE_FORMAT_VERSION,
        sample_rate=_estimate_sample_rate(frames),
        ticks=ticks,
        replay_sha256="",
    )


def load_original_capture_sidecar(path: Path) -> OriginalCaptureSidecar:
    path = Path(path)
    lower_name = str(path).lower()
    if lower_name.endswith(".jsonl") or lower_name.endswith(".jsonl.gz"):
        return _load_original_capture_gameplay_trace(path)

    raw = path.read_bytes()
    if raw.startswith(b"\x1f\x8b"):
        raw = gzip.decompress(raw)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        # Allow accidental .json extension for line-delimited gameplay traces.
        return _load_original_capture_gameplay_trace(path)
    if not isinstance(obj, dict):
        raise OriginalCaptureError("original capture root must be an object")

    version = int(obj.get("v", 0))
    if version != ORIGINAL_CAPTURE_FORMAT_VERSION:
        raise OriginalCaptureError(f"unsupported original capture version: {version}")

    ticks_raw = obj.get("ticks") or []
    if not isinstance(ticks_raw, list):
        raise OriginalCaptureError("original capture ticks must be a list")
    ticks = [_parse_tick(item) for item in ticks_raw]
    sample_rate = max(1, int(obj.get("sample_rate", 1)))

    return OriginalCaptureSidecar(
        version=version,
        sample_rate=sample_rate,
        ticks=ticks,
        replay_sha256=str(obj.get("replay_sha256", "")),
    )


def convert_original_capture_to_checkpoints(
    capture: OriginalCaptureSidecar,
    *,
    replay_sha256: str = "",
) -> ReplayCheckpoints:
    checkpoints: list[ReplayCheckpoint] = []
    for tick in capture.ticks:
        checkpoints.append(
            ReplayCheckpoint(
                tick_index=int(tick.tick_index),
                rng_state=int(tick.rng_state),
                elapsed_ms=int(tick.elapsed_ms),
                score_xp=int(tick.score_xp),
                kills=int(tick.kills),
                creature_count=int(tick.creature_count),
                perk_pending=int(tick.perk_pending),
                players=list(tick.players),
                bonus_timers=dict(tick.bonus_timers),
                state_hash=str(tick.state_hash),
                command_hash=str(tick.command_hash),
                rng_marks=dict(tick.rng_marks),
                deaths=list(tick.deaths),
                perk=tick.perk,
                events=tick.events,
            )
        )

    return ReplayCheckpoints(
        version=FORMAT_VERSION,
        replay_sha256=str(replay_sha256 or capture.replay_sha256),
        sample_rate=max(1, int(capture.sample_rate)),
        checkpoints=checkpoints,
    )


def convert_original_capture_to_replay(
    capture: OriginalCaptureSidecar,
    *,
    seed: int | None = None,
    tick_rate: int = 60,
    world_size: float = 1024.0,
    game_mode_id: int | None = None,
) -> Replay:
    resolved_seed = infer_original_capture_seed(capture) if seed is None else int(seed)
    player_count = _infer_player_count(capture)
    resolved_mode_id = _infer_game_mode_id(capture) if game_mode_id is None else int(game_mode_id)
    status_snapshot = _infer_status_snapshot(capture)

    if capture.ticks:
        max_tick_index = max(max(0, int(tick.tick_index)) for tick in capture.ticks)
        total_ticks = int(max_tick_index) + 1
    else:
        total_ticks = 0

    inputs: list[list[list[float | int | list[float]]]] = [
        [[0.0, 0.0, [0.0, 0.0], 0] for _ in range(player_count)] for _ in range(total_ticks)
    ]
    previous_fire_down: list[bool] = [False for _ in range(player_count)]
    previous_reload_active: list[bool] = [False for _ in range(player_count)]

    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        tick_index = int(tick.tick_index)
        if tick_index < 0 or tick_index >= total_ticks:
            continue
        approx_by_player = {int(sample.player_index): sample for sample in tick.input_approx}
        for player_index in range(player_count):
            sample = approx_by_player.get(int(player_index))
            if sample is not None:
                has_digital_move = (
                    sample.move_forward_pressed is not None
                    or sample.move_backward_pressed is not None
                    or sample.turn_left_pressed is not None
                    or sample.turn_right_pressed is not None
                )
                if has_digital_move:
                    move_x = float(bool(sample.turn_right_pressed)) - float(bool(sample.turn_left_pressed))
                    move_y = float(bool(sample.move_backward_pressed)) - float(bool(sample.move_forward_pressed))
                else:
                    move_x = max(-1.0, min(1.0, float(sample.move_dx)))
                    move_y = max(-1.0, min(1.0, float(sample.move_dy)))

                aim_x_raw = float(sample.aim_x)
                aim_y_raw = float(sample.aim_y)
                has_aim_xy = math.isfinite(aim_x_raw) and math.isfinite(aim_y_raw)
                use_heading_fallback = (
                    (not has_aim_xy or (aim_x_raw == 0.0 and aim_y_raw == 0.0))
                    and sample.aim_heading is not None
                )

                if use_heading_fallback:
                    if player_index < len(tick.players):
                        player_pos = tick.players[player_index].pos
                    else:
                        player_pos = Vec2()
                    aim_pos = player_pos + Vec2.from_heading(float(sample.aim_heading)) * 256.0
                    aim_x = float(aim_pos.x)
                    aim_y = float(aim_pos.y)
                else:
                    aim_x = float(sample.aim_x)
                    aim_y = float(sample.aim_y)

                fire_down = bool(sample.fire_down) if sample.fire_down is not None else int(sample.fired_events) > 0
                fire_pressed = bool(sample.fire_pressed) if sample.fire_pressed is not None else bool(
                    int(sample.fired_events) > 0
                )
                reload_active = bool(sample.reload_active)
            else:
                move_x = 0.0
                move_y = 0.0
                if player_index < len(tick.players):
                    player = tick.players[player_index]
                    aim_x = float(player.pos.x)
                    aim_y = float(player.pos.y)
                else:
                    aim_x = 0.0
                    aim_y = 0.0
                fire_pressed = False
                fire_down = False
                reload_active = False

            if player_index == 0:
                fire_down = bool(
                    fire_down or int(tick.input_primary_down_true_calls) > 0 or int(tick.input_primary_edge_true_calls) > 0
                )
                fire_pressed = bool(fire_pressed or int(tick.input_primary_edge_true_calls) > 0)

            if not fire_pressed:
                fire_pressed = bool(fire_down and not previous_fire_down[player_index])

            reload_pressed = bool(
                int(tick_index) > 0 and bool(reload_active) and not bool(previous_reload_active[player_index])
            )
            previous_fire_down[player_index] = bool(fire_down)
            previous_reload_active[player_index] = bool(reload_active)

            flags = pack_input_flags(
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
            )
            inputs[tick_index][player_index] = [float(move_x), float(move_y), [float(aim_x), float(aim_y)], int(flags)]

    events: list[UnknownEvent] = []
    if capture.ticks:
        first_tick = min(capture.ticks, key=lambda item: int(item.tick_index))
        bootstrap_tick = max(0, int(first_tick.tick_index))
        events.append(
            UnknownEvent(
                tick_index=int(bootstrap_tick),
                kind=ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND,
                payload=[_capture_bootstrap_payload(first_tick)],
            )
        )

    return Replay(
        version=FORMAT_VERSION,
        header=ReplayHeader(
            game_mode_id=int(resolved_mode_id),
            seed=int(resolved_seed),
            tick_rate=max(1, int(tick_rate)),
            player_count=int(player_count),
            world_size=float(world_size),
            status=status_snapshot,
        ),
        inputs=inputs,
        events=list(events),
    )


def default_original_capture_replay_path(checkpoints_path: Path) -> Path:
    checkpoints_path = Path(checkpoints_path)
    name = checkpoints_path.name
    if name.endswith(".checkpoints.json.gz"):
        stem = name[: -len(".checkpoints.json.gz")]
    elif name.endswith(".json.gz"):
        stem = name[: -len(".json.gz")]
    elif name.endswith(".json"):
        stem = name[: -len(".json")]
    else:
        stem = name
    return checkpoints_path.with_name(f"{stem}.crdemo.gz")
