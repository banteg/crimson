from __future__ import annotations

import gzip
import math
import struct
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Protocol, cast

import msgspec

from grim.geom import Vec2

from ..bonuses import BonusId
from ..game_modes import GameMode
from ..perks.ids import PerkId
from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINTS_FORMAT_VERSION,
)
from ..replay.checkpoints import (
    ReplayCheckpoint,
    ReplayCheckpoints,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from ..replay.types import (
    WEAPON_USAGE_COUNT,
    PerkMenuOpenEvent,
    Replay,
    ReplayHeader,
    ReplayStatusSnapshot,
    UnknownEvent,
    pack_input_flags,
)
from ..weapons import WeaponId, projectile_type_ids_from_weapon_id
from .schema import (
    CAPTURE_FORMAT_VERSION,
    CaptureDeath,
    CaptureEventHeadBonusApply,
    CaptureEventHeadCreatureLifecycle,
    CaptureEventHeadCreatureSpawn,
    CaptureEventHeadPerkApply,
    CaptureEventHeadPerkDelta,
    CaptureEventHeadPlayerFire,
    CaptureEventHeadProjectileSpawn,
    CaptureEventHeadQuestTimelineDelta,
    CaptureEventHeadSecondaryProjectileSpawn,
    CaptureEventHeadSfx,
    CaptureEventHeadStateTransition,
    CaptureEventSummary,
    CaptureFile,
    CaptureInputApprox,
    CapturePerkSnapshot,
    CapturePlayerCheckpoint,
    CaptureTick,
)

CAPTURE_UNKNOWN_INT = -1
CAPTURE_BOOTSTRAP_EVENT_KIND = "orig_capture_bootstrap"
CAPTURE_PERK_PENDING_EVENT_KIND = "orig_capture_perk_pending"
CAPTURE_PERK_APPLY_EVENT_KIND = "orig_capture_perk_apply"
CAPTURE_CREATURE_SPAWN_EVENT_KIND = "orig_capture_creature_spawn"
CAPTURE_STATE_TRANSITION_EVENT_KIND = "orig_capture_state_transition"

_CRT_RAND_MULT = 214013
_CRT_RAND_INC = 2531011
_CRT_RAND_MOD_MASK = 0xFFFFFFFF
_CRT_RAND_INV_MULT = pow(_CRT_RAND_MULT, -1, 1 << 32)
_AIM_SCHEME_COMPUTER = 5
_PLAYER_PROJECTILE_OWNER_SENTINEL = -100
_PROJECTILE_TYPE_FIRE_BULLETS = 45
_FRACTIONAL_AMMO_DRAIN_WEAPON_IDS = frozenset(
    {
        int(WeaponId.FLAMETHROWER),
        int(WeaponId.BLOW_TORCH),
        int(WeaponId.HR_FLAMER),
        int(WeaponId.BUBBLEGUN),
    },
)
_FRACTIONAL_WEAPON_FIRE_SFX_CALLER_SUFFIXES = frozenset({"+0x15f1c"})
_QUEST_CAPTURE_SPAWN_CALLERS = frozenset(
    {
        # quest timeline script-driven spawns
        "0x00434373",
        # creature_update_all owner-slot spawn path
        "0x00426d56",
    },
)
_PERK_INTERVAL_GLOBAL_KEYS: dict[str, str] = {
    "man_bomb": "perk_man_bomb_trigger_interval_s",
    "fire_cough": "perk_fire_cough_trigger_interval_s",
    "hot_tempered": "perk_hot_tempered_trigger_interval_s",
}
_PERK_INTERVAL_PERK_IDS: dict[str, int] = {
    "man_bomb": int(PerkId.MAN_BOMB),
    "fire_cough": int(PerkId.FIRE_CAUGH),
    "hot_tempered": int(PerkId.HOT_TEMPERED),
}
_PROJECTILE_SPAWNING_BONUS_IDS = frozenset(
    {
        int(BonusId.FIREBLAST),
        int(BonusId.SHOCK_CHAIN),
        int(BonusId.NUKE),
    },
)


class CaptureError(ValueError):
    pass


class _BootstrapPerkSelection(Protocol):
    pending_count: int
    choices: list[int]
    choices_dirty: bool
    capture_player_perk_counts_known: bool


class _BootstrapBonuses(Protocol):
    weapon_power_up: float
    reflex_boost: float
    energizer: float
    double_experience: float
    freeze: float


class _BootstrapPerkIntervals(Protocol):
    man_bomb: float
    fire_cough: float
    hot_tempered: float


class _BootstrapState(Protocol):
    perk_selection: _BootstrapPerkSelection
    bonuses: _BootstrapBonuses
    perk_intervals: _BootstrapPerkIntervals
    time_scale_active: bool


class _BootstrapPlayer(Protocol):
    weapon_id: int
    pos: Vec2
    health: float
    ammo: float
    experience: int
    level: int
    clip_size: int
    reload_active: bool
    reload_timer: float
    reload_timer_max: float
    shot_cooldown: float
    spread_heat: float
    aim: Vec2
    aim_heading: float
    aim_dir: Vec2
    alt_weapon_id: int | None
    alt_clip_size: int
    alt_ammo: float
    alt_reload_active: bool
    alt_reload_timer: float
    alt_reload_timer_max: float
    alt_shot_cooldown: float
    shield_timer: float
    fire_bullets_timer: float
    speed_bonus_timer: float
    hot_tempered_timer: float
    man_bomb_timer: float
    living_fortress_timer: float
    fire_cough_timer: float
    perk_counts: list[int]


class _CapturePerkApplyPayload(msgspec.Struct, forbid_unknown_fields=True):
    perk_id: int
    outside_before: bool = False
    pending_before: int | None = None
    pending_after: int | None = None


class _CapturePerkPendingPayload(msgspec.Struct, forbid_unknown_fields=True):
    perk_pending: int


class _CaptureStreamMetaRow(msgspec.Struct, tag="capture_meta", tag_field="event", forbid_unknown_fields=True):
    capture: CaptureFile


class _CaptureStreamTickRow(msgspec.Struct, tag="tick", tag_field="event", forbid_unknown_fields=True):
    tick: CaptureTick


_CaptureStreamRow = _CaptureStreamMetaRow | _CaptureStreamTickRow
_F32_TOKEN_PREFIX = "f32:"


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


def parse_player_int_overrides(entries: Iterable[str] | None, *, option_name: str) -> dict[int, int]:
    out: dict[int, int] = {}
    if entries is None:
        return out

    for raw_entry in entries:
        entry = str(raw_entry).strip()
        if not entry:
            continue
        if "=" in entry:
            player_text, value_text = entry.split("=", 1)
        elif ":" in entry:
            player_text, value_text = entry.split(":", 1)
        else:
            raise ValueError(
                f"{option_name} expects PLAYER=VALUE (or PLAYER:VALUE), got {entry!r}",
            )

        player_index = _coerce_int_like(player_text.strip())
        value = _coerce_int_like(value_text.strip())
        if player_index is None or int(player_index) < 0:
            raise ValueError(f"{option_name} has invalid player index in {entry!r}")
        if value is None:
            raise ValueError(f"{option_name} has invalid value in {entry!r}")
        out[int(player_index)] = int(value)

    return out


def _f32_from_u32(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(value) & 0xFFFFFFFF))[0]


def _decode_f32_token(value: object) -> object:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text.startswith(_F32_TOKEN_PREFIX):
        return value
    raw = text[len(_F32_TOKEN_PREFIX) :].strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if len(raw) != 8:
        raise CaptureError(f"invalid f32 token width: {value!r}")
    try:
        bits = int(raw, 16)
    except ValueError as exc:
        raise CaptureError(f"invalid f32 token hex: {value!r}") from exc
    return float(_f32_from_u32(int(bits)))


def _decode_f32_tokens(value: object) -> object:
    if isinstance(value, dict):
        return {str(k): _decode_f32_tokens(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_f32_tokens(item) for item in value]
    if isinstance(value, tuple):
        return [_decode_f32_tokens(item) for item in value]
    return _decode_f32_token(value)


def _float_or(value: object, default: float) -> float:
    if value is None:
        return float(default)
    try:
        return float(value)  # ty:ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return float(default)


def _int_or(value: object, default: int) -> int:
    parsed = _coerce_int_like(value)
    if parsed is None:
        return int(default)
    return int(parsed)


def _finite_float_or_none(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)):
        return None
    candidate = float(value)
    if not math.isfinite(candidate):
        return None
    return float(candidate)


def _estimate_sample_rate(tick_indices: list[int]) -> int:
    if len(tick_indices) < 2:
        return 1
    deltas = [
        next_tick - tick
        for tick, next_tick in zip(tick_indices, tick_indices[1:])
        if int(next_tick) > int(tick)
    ]
    if not deltas:
        return 1
    deltas.sort()
    return max(1, int(deltas[len(deltas) // 2]))


def _tick_indices(capture: CaptureFile) -> list[int]:
    return sorted(int(tick.tick_index) for tick in capture.ticks)


def _capture_sample_rate(capture: CaptureFile) -> int:
    return _estimate_sample_rate(_tick_indices(capture))


def _replay_player(player: CapturePlayerCheckpoint) -> ReplayPlayerCheckpoint:
    return ReplayPlayerCheckpoint(
        pos=Vec2(float(player.pos.x), float(player.pos.y)),
        health=float(player.health),
        weapon_id=int(player.weapon_id),
        ammo=float(player.ammo),
        experience=int(player.experience),
        level=int(player.level),
    )


def _replay_death(raw: CaptureDeath) -> ReplayDeathLedgerEntry:
    return ReplayDeathLedgerEntry(
        creature_index=int(raw.creature_index),
        type_id=int(raw.type_id),
        reward_value=float(raw.reward_value),
        xp_awarded=int(raw.xp_awarded),
        owner_id=int(raw.owner_id),
    )


def _replay_perk(raw: CapturePerkSnapshot) -> ReplayPerkSnapshot:
    return ReplayPerkSnapshot(
        pending_count=int(raw.pending_count),
        choices_dirty=bool(raw.choices_dirty),
        choices=[int(value) for value in raw.choices],
        player_nonzero_counts=[
            [[int(pair[0]), int(pair[1])] for pair in player_counts]
            for player_counts in raw.player_nonzero_counts
        ],
    )


def _replay_events(raw: CaptureEventSummary) -> ReplayEventSummary:
    return ReplayEventSummary(
        hit_count=int(raw.hit_count),
        pickup_count=int(raw.pickup_count),
        sfx_count=int(raw.sfx_count),
        sfx_head=[str(value) for value in raw.sfx_head[:4]],
    )


def _rng_head_values(tick: CaptureTick) -> list[int]:
    out: list[int] = []
    sources = list(tick.rng.head)
    if not sources:
        sources = list(tick.checkpoint.rng_marks.rand_head)
    for item in sources:
        value: int | None = None
        if item.value_15 is not None:
            value = int(item.value_15)
        elif item.value is not None:
            value = int(item.value) & 0x7FFF
        if value is None:
            continue
        if 0 <= int(value) <= 0x7FFF:
            out.append(int(value))
    return out


def _infer_seed_from_rng_state_before(tick: CaptureTick) -> int | None:
    sources = list(tick.rng.head)
    if not sources:
        sources = list(tick.checkpoint.rng_marks.rand_head)
    if not sources:
        return None

    rng_head = _rng_head_values(tick)
    marks = tick.checkpoint.rng_marks
    rand_calls: object = int(marks.rand_calls)
    rand_last: object = marks.rand_last
    if int(rand_calls) <= 0 and int(tick.rng.calls) > 0:
        rand_calls = int(tick.rng.calls)
    if rand_last is None:
        rand_last = tick.rng.last_value

    for item in sources:
        state_before_u32 = item.state_before_u32
        if state_before_u32 is None:
            parsed_from_hex = _coerce_int_like(item.state_before_hex)
            if parsed_from_hex is not None:
                state_before_u32 = int(parsed_from_hex)
        if state_before_u32 is None:
            continue
        candidate = int(state_before_u32) & _CRT_RAND_MOD_MASK
        if rng_head and not _seed_matches_rng_marks(
            int(candidate),
            rng_head=rng_head,
            rand_calls=rand_calls,
            rand_last=rand_last,
        ):
            continue
        return int(candidate)

    return None


def _rng_marks_int_map(tick: CaptureTick) -> dict[str, int]:
    marks = tick.checkpoint.rng_marks
    out: dict[str, int] = {}

    def put(name: str, value: int | None) -> None:
        if value is None:
            return
        out[name] = int(value)

    put("rand_calls", int(marks.rand_calls))
    put("rand_last", marks.rand_last)
    put("rand_seq_first", marks.rand_seq_first)
    put("rand_seq_last", marks.rand_seq_last)
    put("rand_seed_epoch_enter", marks.rand_seed_epoch_enter)
    put("rand_seed_epoch_last", marks.rand_seed_epoch_last)
    put("rand_outside_before_calls", int(marks.rand_outside_before_calls))
    put("rand_outside_before_dropped", int(marks.rand_outside_before_dropped))
    put("rand_mirror_mismatch_total", int(marks.rand_mirror_mismatch_total))
    put("rand_mirror_unknown_total", int(marks.rand_mirror_unknown_total))
    return out


def _tick_game_mode_id(tick: CaptureTick) -> int:
    if int(tick.game_mode_id) >= 0:
        return int(tick.game_mode_id)

    after_globals = tick.after.globals if tick.after is not None else {}
    game_mode = _coerce_int_like(after_globals.get("config_game_mode")) if isinstance(after_globals, dict) else None
    if game_mode is not None and int(game_mode) >= 0:
        return int(game_mode)

    before_globals = tick.before.globals if tick.before is not None else {}
    game_mode = _coerce_int_like(before_globals.get("config_game_mode")) if isinstance(before_globals, dict) else None
    if game_mode is not None and int(game_mode) >= 0:
        return int(game_mode)
    return -1


def _tick_frame_dt_ms(tick: CaptureTick) -> float | None:
    def _valid_dt_ms(value: object) -> float | None:
        if value is None:
            return None
        if not isinstance(value, (int, float)):
            return None
        candidate = float(value)
        if not math.isfinite(candidate):
            return None
        if candidate < 0.1 or candidate > 1000.0:
            return None
        return float(candidate)

    timing = tick.diagnostics.timing
    if isinstance(timing, dict):
        value = timing.get("frame_dt_after")
        if isinstance(value, (int, float)) and math.isfinite(float(value)) and float(value) > 0.0:
            validated = _valid_dt_ms(float(value) * 1000.0)
            if validated is not None:
                return float(validated)

    globals_obj: dict[str, object] = {}
    if tick.after is not None and isinstance(tick.after.globals, dict):
        globals_obj = tick.after.globals
    elif tick.before is not None and isinstance(tick.before.globals, dict):
        globals_obj = tick.before.globals

    if tick.frame_dt_ms_i32 is not None and int(tick.frame_dt_ms_i32) > 0:
        validated = _valid_dt_ms(int(tick.frame_dt_ms_i32))
        if validated is not None:
            return float(validated)

    dt_ms_i32 = _coerce_int_like(globals_obj.get("frame_dt_ms_i32"))
    if dt_ms_i32 is not None and int(dt_ms_i32) > 0:
        validated = _valid_dt_ms(int(dt_ms_i32))
        if validated is not None:
            return float(validated)

    validated_tick_dt = _valid_dt_ms(tick.frame_dt_ms)
    if validated_tick_dt is not None:
        return float(validated_tick_dt)

    validated_globals_dt = _valid_dt_ms(globals_obj.get("frame_dt_ms_f32"))
    if validated_globals_dt is not None:
        return float(validated_globals_dt)

    dt_seconds = globals_obj.get("frame_dt")
    if isinstance(dt_seconds, (int, float)) and math.isfinite(float(dt_seconds)):
        if 0.0 < float(dt_seconds) <= 1.0:
            validated = _valid_dt_ms(float(dt_seconds) * 1000.0)
            if validated is not None:
                return float(validated)

    timing = tick.diagnostics.timing
    if isinstance(timing, dict):
        value = timing.get("frame_dt_after")
        if isinstance(value, (int, float)) and math.isfinite(float(value)) and float(value) > 0.0:
            validated = _valid_dt_ms(float(value) * 1000.0)
            if validated is not None:
                return float(validated)

    return None


def _tick_frame_dt_ms_i32(tick: CaptureTick) -> int | None:
    if tick.frame_dt_ms_i32 is not None and int(tick.frame_dt_ms_i32) > 0:
        return int(tick.frame_dt_ms_i32)

    globals_obj: dict[str, object] = {}
    if tick.after is not None and isinstance(tick.after.globals, dict):
        globals_obj = tick.after.globals
    elif tick.before is not None and isinstance(tick.before.globals, dict):
        globals_obj = tick.before.globals

    value = _coerce_int_like(globals_obj.get("frame_dt_ms_i32"))
    if value is not None and int(value) > 0:
        return int(value)

    timing = tick.diagnostics.timing
    if isinstance(timing, dict):
        value = _coerce_int_like(timing.get("frame_dt_ms_after_i32"))
        if value is not None and int(value) > 0:
            return int(value)

    return None


def summarize_capture_health(
    capture: CaptureFile,
    *,
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> dict[str, object]:
    """Summarize capture telemetry coverage for differential/parity workflows."""
    ticks_sorted = sorted(capture.ticks, key=lambda item: int(item.tick_index))
    window_start = int(tick_start) if tick_start is not None else None
    window_end = int(tick_end) if tick_end is not None else None
    if window_start is not None and window_end is not None and int(window_start) > int(window_end):
        raise ValueError("tick_start must be <= tick_end")

    ticks: list[CaptureTick] = []
    for tick in ticks_sorted:
        tick_index = int(tick.tick_index)
        if window_start is not None and tick_index < int(window_start):
            continue
        if window_end is not None and tick_index > int(window_end):
            continue
        ticks.append(tick)

    key_rows = 0
    key_rows_with_any_signal = 0
    perk_apply_in_tick_entries = 0
    perk_apply_outside_calls = 0
    sample_creature_rows = 0
    sample_creature_rows_with_ai_lineage = 0
    creature_lifecycle_rows = 0
    creature_lifecycle_rows_with_ai_lineage = 0
    creature_update_micro_rows = 0
    creature_update_micro_angle_rows = 0
    creature_update_micro_window_rows = 0
    mode_tick_event_count_total = 0
    frame_dt_source_after_counts: Counter[str] = Counter()

    for tick in ticks:
        mode_tick_event_count_total += int(tick.event_counts.mode_tick)
        timing = tick.diagnostics.timing
        if isinstance(timing, dict):
            source_obj = timing.get("frame_dt_source_after")
            source = str(source_obj).strip() if source_obj is not None else ""
            if source:
                frame_dt_source_after_counts[source] += 1

        for row in tick.input_player_keys:
            key_rows += 1
            if any(
                value is not None
                for value in (
                    row.move_forward_pressed,
                    row.move_backward_pressed,
                    row.turn_left_pressed,
                    row.turn_right_pressed,
                    row.fire_down,
                    row.fire_pressed,
                    row.reload_pressed,
                )
            ):
                key_rows_with_any_signal += 1

        perk_apply_in_tick_entries += sum(1 for item in tick.perk_apply_in_tick if item.perk_id is not None)
        perk_apply_outside_calls += int(tick.perk_apply_outside_before.calls)

        if tick.samples is not None:
            for creature in tick.samples.creatures:
                sample_creature_rows += 1
                if creature.ai_mode is not None or creature.link_index is not None:
                    sample_creature_rows_with_ai_lineage += 1

        for head in msgspec.to_builtins(tick.event_heads):
            if not isinstance(head, dict):
                continue
            kind = str(head.get("kind") or "")
            if kind == "creature_update_micro":
                creature_update_micro_rows += 1
                data = head.get("data")
                data_obj = data if isinstance(data, dict) else {}
                event_kind = str(data_obj.get("event_kind") or "")
                if event_kind == "angle_approach":
                    creature_update_micro_angle_rows += 1
                elif event_kind == "creature_update_window":
                    creature_update_micro_window_rows += 1
                continue
            if kind != "creature_lifecycle":
                continue

            data = head.get("data")
            data_obj = data if isinstance(data, dict) else {}
            for key in ("added_head", "removed_head"):
                rows_obj = data_obj.get(key)
                rows = rows_obj if isinstance(rows_obj, list) else []
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    creature_lifecycle_rows += 1
                    if row.get("ai_mode") is not None or row.get("link_index") is not None:
                        creature_lifecycle_rows_with_ai_lineage += 1

    issues: list[str] = []
    if creature_update_micro_rows <= 0:
        issues.append("creature_update_micro_rows == 0")
    if creature_update_micro_angle_rows <= 0:
        issues.append("creature_update_micro_angle_rows == 0")
    if creature_update_micro_window_rows <= 0:
        issues.append("creature_update_micro_window_rows == 0")
    if mode_tick_event_count_total <= 0:
        issues.append("mode_tick_event_count_total == 0")

    first_tick = int(ticks[0].tick_index) if ticks else None
    last_tick = int(ticks[-1].tick_index) if ticks else None
    metrics: dict[str, object] = {
        "key_rows": int(key_rows),
        "key_rows_with_any_signal": int(key_rows_with_any_signal),
        "perk_apply_in_tick_entries": int(perk_apply_in_tick_entries),
        "perk_apply_outside_calls": int(perk_apply_outside_calls),
        "sample_creature_rows": int(sample_creature_rows),
        "sample_creature_rows_with_ai_lineage": int(sample_creature_rows_with_ai_lineage),
        "creature_lifecycle_rows": int(creature_lifecycle_rows),
        "creature_lifecycle_rows_with_ai_lineage": int(creature_lifecycle_rows_with_ai_lineage),
        "creature_update_micro_rows": int(creature_update_micro_rows),
        "creature_update_micro_angle_rows": int(creature_update_micro_angle_rows),
        "creature_update_micro_window_rows": int(creature_update_micro_window_rows),
        "mode_tick_event_count_total": int(mode_tick_event_count_total),
        "frame_dt_source_after_counts": dict(sorted(frame_dt_source_after_counts.items())),
    }
    return {
        "capture_format_version": int(capture.capture_format_version),
        "tick_window": {
            "requested_start": window_start,
            "requested_end": window_end,
            "actual_start": first_tick,
            "actual_end": last_tick,
            "ticks_total": int(len(capture.ticks)),
            "ticks_in_window": int(len(ticks)),
        },
        "metrics": metrics,
        "ok_for_movement_root_cause": not issues,
        "issues": issues,
    }


def _infer_game_mode_id(capture: CaptureFile) -> int:
    for tick in capture.ticks:
        mode_id = _tick_game_mode_id(tick)
        if mode_id >= 0:
            return int(mode_id)

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
    raise ValueError(
        "cannot infer replay game_mode_id from capture; pass an explicit game_mode_id override",
    )


def _tick_quest_stage(tick: CaptureTick) -> tuple[int, int] | None:
    major = _coerce_int_like(tick.quest_stage_major)
    minor = _coerce_int_like(tick.quest_stage_minor)
    if major is not None and minor is not None and int(major) > 0 and int(minor) > 0:
        return int(major), int(minor)

    after_globals = tick.after.globals if tick.after is not None else {}
    major = _coerce_int_like(after_globals.get("quest_stage_major")) if isinstance(after_globals, dict) else None
    minor = _coerce_int_like(after_globals.get("quest_stage_minor")) if isinstance(after_globals, dict) else None
    if major is not None and minor is not None and int(major) > 0 and int(minor) > 0:
        return int(major), int(minor)

    before_globals = tick.before.globals if tick.before is not None else {}
    major = _coerce_int_like(before_globals.get("quest_stage_major")) if isinstance(before_globals, dict) else None
    minor = _coerce_int_like(before_globals.get("quest_stage_minor")) if isinstance(before_globals, dict) else None
    if major is not None and minor is not None and int(major) > 0 and int(minor) > 0:
        return int(major), int(minor)

    return None


def _tick_quest_session_bootstrap_payload(tick: CaptureTick) -> dict[str, float] | None:
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadQuestTimelineDelta):
            continue
        data = head.data if isinstance(head.data, dict) else {}
        timeline_ms = _coerce_int_like(data.get("quest_spawn_timeline"))
        stall_timer_ms = _coerce_int_like(data.get("quest_spawn_stall_timer_ms"))
        transition_timer_ms = _coerce_int_like(data.get("quest_transition_timer_ms"))
        payload: dict[str, float] = {}
        if timeline_ms is not None:
            payload["spawn_timeline_ms"] = float(timeline_ms)
        if stall_timer_ms is not None:
            payload["no_creatures_timer_ms"] = float(stall_timer_ms)
        if transition_timer_ms is not None:
            payload["completion_transition_ms"] = float(transition_timer_ms)
        if payload:
            return payload
    return None


def _infer_quest_level(capture: CaptureFile, *, game_mode_id: int) -> str:
    if int(game_mode_id) != int(GameMode.QUESTS):
        return ""
    for tick in capture.ticks:
        stage = _tick_quest_stage(tick)
        if stage is None:
            continue
        major, minor = stage
        return f"{int(major)}.{int(minor)}"
    return ""


def _infer_player_count(capture: CaptureFile) -> int:
    player_count = 0
    for tick in capture.ticks:
        player_count = max(player_count, int(len(tick.checkpoint.players)))
        for sample in tick.input_approx:
            player_count = max(player_count, int(sample.player_index) + 1)
        for key_row in tick.input_player_keys:
            player_count = max(player_count, int(key_row.player_index) + 1)
    if int(player_count) <= 0:
        raise ValueError(
            "cannot infer replay player_count from capture; pass an explicit player_count override",
        )
    return int(player_count)


def _infer_digital_move_enabled_by_player(capture: CaptureFile, *, player_count: int) -> list[bool]:
    size = max(1, int(player_count))
    saw_digital_keys: list[bool] = [False for _ in range(size)]

    for tick in capture.ticks:
        for key_row in tick.input_player_keys:
            player_index = int(key_row.player_index)
            if not (0 <= player_index < len(saw_digital_keys)):
                continue
            if (
                key_row.move_forward_pressed is not None
                or key_row.move_backward_pressed is not None
                or key_row.turn_left_pressed is not None
                or key_row.turn_right_pressed is not None
            ):
                saw_digital_keys[player_index] = True

    return [bool(enabled) for enabled in saw_digital_keys]


def _coerce_player_int(value: object, *, player_index: int) -> int | None:
    direct = _coerce_int_like(value)
    if direct is not None:
        return int(direct)
    if isinstance(value, (list, tuple)):
        if 0 <= int(player_index) < len(value):
            nested = _coerce_int_like(value[int(player_index)])
            if nested is not None:
                return int(nested)
        return None
    if isinstance(value, dict):
        key_text = str(int(player_index))
        preferred_key_texts = (
            key_text,
            f"player_{key_text}",
            f"player{key_text}",
            f"p{key_text}",
        )
        for raw_key, raw_value in value.items():
            if raw_key != int(player_index) and str(raw_key) not in preferred_key_texts:
                continue
            nested = _coerce_int_like(raw_value)
            if nested is not None:
                return int(nested)
    return None


def _tick_player_aim_scheme(tick: CaptureTick, *, player_index: int) -> int | None:
    for sample in tick.input_approx:
        if int(sample.player_index) != int(player_index):
            continue
        if sample.aim_scheme is None:
            continue
        parsed = _coerce_int_like(sample.aim_scheme)
        if parsed is not None:
            return int(parsed)

    for snapshot in (tick.after, tick.before):
        if snapshot is None:
            continue
        globals_obj = snapshot.globals if isinstance(snapshot.globals, dict) else {}
        globals_scheme = _coerce_player_int(
            globals_obj.get("config_aim_scheme"),
            player_index=int(player_index),
        )
        if globals_scheme is not None:
            return int(globals_scheme)
        input_obj = snapshot.input if isinstance(snapshot.input, dict) else {}
        input_scheme = _coerce_player_int(
            input_obj.get("config_aim_scheme"),
            player_index=int(player_index),
        )
        if input_scheme is not None:
            return int(input_scheme)
    return None


def _owner_id_to_player_index(owner_id: int, *, player_count: int) -> int | None:
    owner = int(owner_id)
    if -4 <= owner <= -1:
        player_index = -1 - int(owner)
        if 0 <= int(player_index) < int(player_count):
            return int(player_index)
    if int(owner) == _PLAYER_PROJECTILE_OWNER_SENTINEL and int(player_count) == 1:
        return 0
    return None


def _tick_player_projectile_spawn_count(tick: CaptureTick, *, player_index: int, player_count: int) -> int:
    total = 0
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is None:
            continue
        owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
        if owner_player_index is None or int(owner_player_index) != int(player_index):
            continue
        total += 1
    return int(total)


def _tick_player_secondary_projectile_spawn_count(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
) -> int:
    total = 0
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadSecondaryProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is not None:
            owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
            if owner_player_index is None or int(owner_player_index) != int(player_index):
                continue
            total += 1
            continue
        if int(player_count) == 1 and int(player_index) == 0:
            # Older captures did not include owner IDs on secondary spawns.
            total += 1
    return int(total)


def _tick_player_weapon_projectile_spawned(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
    weapon_id: int,
) -> bool:
    # Captures report projectile type IDs; many weapons do not emit `weapon_id` directly.
    target_type_ids = set(projectile_type_ids_from_weapon_id(int(weapon_id)))
    target_type_ids.add(int(weapon_id))
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is None:
            continue
        owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
        if owner_player_index is None or int(owner_player_index) != int(player_index):
            continue
        requested_type = _coerce_int_like(head.data.get("requested_type_id"))
        actual_type = _coerce_int_like(head.data.get("actual_type_id"))
        if requested_type is not None and int(requested_type) in target_type_ids:
            return True
        if actual_type is not None and int(actual_type) in target_type_ids:
            return True
    return False


def _tick_player_projectile_bonus_apply(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
) -> bool:
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadBonusApply):
            continue
        bonus_id = _coerce_int_like(head.data.get("bonus_id"))
        if bonus_id is None or int(bonus_id) not in _PROJECTILE_SPAWNING_BONUS_IDS:
            continue
        applied_player_index = _coerce_int_like(head.data.get("player_index"))
        if applied_player_index is None:
            if int(player_count) == 1 and int(player_index) == 0:
                return True
            continue
        if int(applied_player_index) == int(player_index):
            return True
    return False


def _tick_player_projectile_type_spawned(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
    projectile_type_id: int,
) -> bool:
    target_type_id = int(projectile_type_id)
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is None:
            continue
        owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
        if owner_player_index is None or int(owner_player_index) != int(player_index):
            continue
        requested_type = _coerce_int_like(head.data.get("requested_type_id"))
        actual_type = _coerce_int_like(head.data.get("actual_type_id"))
        if requested_type is not None and int(requested_type) == int(target_type_id):
            return True
        if actual_type is not None and int(actual_type) == int(target_type_id):
            return True
    return False


def _should_synthesize_reload_pressed_for_alt_swap(
    tick: CaptureTick,
    *,
    player_index: int,
) -> bool:
    before_player = _tick_before_player_snapshot(tick, player_index=int(player_index))
    if before_player is None:
        return False

    checkpoint_players = tick.checkpoint.players
    if int(player_index) < 0 or int(player_index) >= len(checkpoint_players):
        return False

    before_weapon_id = _coerce_int_like(before_player.get("weapon_id"))
    if before_weapon_id is None or int(before_weapon_id) <= 0:
        return False

    checkpoint_weapon_id = int(checkpoint_players[int(player_index)].weapon_id)
    if int(checkpoint_weapon_id) == int(before_weapon_id):
        return False

    alt_weapon_raw = before_player.get("alt_weapon")
    if not isinstance(alt_weapon_raw, dict):
        return False
    alt_weapon = cast(Mapping[object, object], alt_weapon_raw)
    alt_weapon_id = _coerce_int_like(alt_weapon.get("weapon_id"))
    if alt_weapon_id is None or int(alt_weapon_id) <= 0:
        return False

    return int(checkpoint_weapon_id) == int(alt_weapon_id)


def _before_player_ammo_snapshot(before_player: Mapping[object, object]) -> float | None:
    before_ammo = _finite_float_or_none(before_player.get("ammo_f32"))
    if before_ammo is None:
        before_ammo = _f32_from_i32_bits_or_none(before_player.get("ammo_i32"))
    if before_ammo is None:
        before_ammo = _finite_float_or_none(before_player.get("ammo"))
    return before_ammo


def _before_player_clip_size_snapshot(before_player: Mapping[object, object]) -> float | None:
    clip_size = _finite_float_or_none(before_player.get("clip_size_f32"))
    if clip_size is None:
        clip_size = _f32_from_i32_bits_or_none(before_player.get("clip_size_i32"))
    if clip_size is None:
        clip_size = _finite_float_or_none(before_player.get("clip_size"))
    return clip_size


def _should_synthesize_fire_down_from_fractional_ammo_drain(
    *,
    tick: CaptureTick,
    player_index: int,
    fire_down_raw: object | None,
    fire_pressed_raw: object | None,
) -> bool:
    if bool(fire_down_raw) or bool(fire_pressed_raw):
        return False

    before_player = _tick_before_player_snapshot(tick, player_index=int(player_index))
    if before_player is None:
        return False
    checkpoint_players = tick.checkpoint.players
    if int(player_index) < 0 or int(player_index) >= len(checkpoint_players):
        return False

    before_weapon_id = _coerce_int_like(before_player.get("weapon_id"))
    if before_weapon_id is None or int(before_weapon_id) <= 0:
        return False
    checkpoint_weapon_id = int(checkpoint_players[int(player_index)].weapon_id)
    if int(checkpoint_weapon_id) != int(before_weapon_id):
        return False
    if int(checkpoint_weapon_id) not in _FRACTIONAL_AMMO_DRAIN_WEAPON_IDS:
        return False

    before_reload_active = _coerce_int_like(before_player.get("reload_active_i32"))
    before_reload_timer = _finite_float_or_none(before_player.get("reload_timer"))

    before_ammo = _before_player_ammo_snapshot(before_player)
    if before_ammo is None:
        return False
    after_ammo = float(checkpoint_players[int(player_index)].ammo)
    if float(before_ammo) > float(after_ammo) + 1e-6:
        if before_reload_active is not None and int(before_reload_active) > 0:
            return False
        if before_reload_timer is not None and float(before_reload_timer) > 0.0:
            return False
        return True

    before_clip_size = _before_player_clip_size_snapshot(before_player)
    if before_clip_size is None or float(before_clip_size) <= 0.0:
        return False
    if not (float(after_ammo) > float(before_ammo) + 1e-6):
        return False
    if before_reload_active is None or int(before_reload_active) <= 0:
        return False
    if before_reload_timer is None or float(before_reload_timer) <= 0.0:
        return False
    # Native continuous particle-fire weapons can finish reload and consume one
    # fractional ammo step in the same tick.
    return float(after_ammo) < float(before_clip_size) - 1e-6


def _is_fractional_weapon_fire_sfx_caller(caller: object) -> bool:
    if not isinstance(caller, str):
        return False
    caller_s = caller.strip().lower()
    for suffix in _FRACTIONAL_WEAPON_FIRE_SFX_CALLER_SUFFIXES:
        if caller_s.endswith(str(suffix)):
            return True
    return False


def _should_synthesize_fire_down_from_fractional_weapon_fire_sfx(
    *,
    tick: CaptureTick,
    player_index: int,
    player_count: int,
    fire_down_raw: object | None,
    fire_pressed_raw: object | None,
) -> bool:
    if bool(fire_down_raw) or bool(fire_pressed_raw):
        return False
    if int(player_count) != 1 or int(player_index) != 0:
        return False

    before_player = _tick_before_player_snapshot(tick, player_index=int(player_index))
    if before_player is None:
        return False
    checkpoint_players = tick.checkpoint.players
    if int(player_index) < 0 or int(player_index) >= len(checkpoint_players):
        return False

    before_weapon_id = _coerce_int_like(before_player.get("weapon_id"))
    if before_weapon_id is None or int(before_weapon_id) <= 0:
        return False
    checkpoint_weapon_id = int(checkpoint_players[int(player_index)].weapon_id)
    if int(checkpoint_weapon_id) != int(before_weapon_id):
        return False
    if int(checkpoint_weapon_id) not in _FRACTIONAL_AMMO_DRAIN_WEAPON_IDS:
        return False

    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadSfx):
            continue
        kind = head.data.get("kind")
        if isinstance(kind, str) and kind.strip().lower() != "sfx_play_panned":
            continue
        if _is_fractional_weapon_fire_sfx_caller(head.data.get("caller")):
            return True
    return False


def _should_synthesize_fire_down_from_player_fire_event(
    *,
    tick: CaptureTick,
    player_index: int,
    player_count: int,
    fire_down_raw: object | None,
    fire_pressed_raw: object | None,
) -> bool:
    if bool(fire_down_raw) or bool(fire_pressed_raw):
        return False
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadPlayerFire):
            continue
        if not _player_fire_head_matches_player(
            head,
            player_index=int(player_index),
            player_count=int(player_count),
        ):
            continue
        shot_cooldown_after = _finite_float_or_none(head.data.get("shot_cooldown_after"))
        if shot_cooldown_after is not None and float(shot_cooldown_after) <= 0.0:
            # Perk/proc-driven projectile bursts can emit `player_fire` debug rows
            # without a real trigger pull (`shot_cooldown_after` stays 0).
            continue
        return True
    return False


def _player_fire_head_matches_player(
    head: CaptureEventHeadPlayerFire,
    *,
    player_index: int,
    player_count: int,
) -> bool:
    fired_player_index = _coerce_int_like(head.data.get("player_index"))
    if fired_player_index is not None:
        return int(fired_player_index) == int(player_index)
    owner_id = _coerce_int_like(head.data.get("owner_id"))
    if owner_id is None:
        return False
    owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
    return owner_player_index is not None and int(owner_player_index) == int(player_index)


def _tick_player_has_only_zero_cooldown_player_fire_events(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
) -> bool:
    matched = False
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadPlayerFire):
            continue
        if not _player_fire_head_matches_player(
            head,
            player_index=int(player_index),
            player_count=int(player_count),
        ):
            continue
        matched = True
        shot_cooldown_after = _finite_float_or_none(head.data.get("shot_cooldown_after"))
        if shot_cooldown_after is None:
            return False
        if float(shot_cooldown_after) > 0.0:
            return False
    return matched


def _should_synthesize_fire_pressed_from_primary_edge(
    *,
    tick: CaptureTick,
    player_index: int,
    player_count: int,
    aim_scheme: int | None,
    sample: CaptureInputApprox | None,
    fire_down_raw: object | None,
    fire_pressed_raw: object | None,
) -> bool:
    if fire_pressed_raw is not None:
        return False
    if bool(fire_down_raw):
        return False
    if int(player_count) != 1 or int(player_index) != 0:
        return False
    if aim_scheme is None:
        return False
    if int(aim_scheme) != int(_AIM_SCHEME_COMPUTER):
        return False
    if sample is None:
        return False
    sample_reload_active = _coerce_int_like(sample.reload_active)
    if sample_reload_active is not None and int(sample_reload_active) <= 0:
        return False
    true_calls = int(tick.input_queries.stats.primary_edge.true_calls)
    return int(true_calls) > 0


def _should_synthesize_computer_fire_down(
    *,
    tick: CaptureTick,
    player_index: int,
    player_count: int,
    aim_scheme: int | None,
    sample: CaptureInputApprox | None,
    fire_down_raw: object | None,
    fire_pressed_raw: object | None,
    ammo_dropped_since_previous_checkpoint: bool,
    weapon_id_hint: int | None,
    previous_weapon_id_hint: int | None,
) -> bool:
    if aim_scheme is not None and int(aim_scheme) != int(_AIM_SCHEME_COMPUTER):
        return False
    if bool(fire_down_raw) or bool(fire_pressed_raw):
        return False

    player_projectile_spawn_count = _tick_player_projectile_spawn_count(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    )
    player_secondary_spawn_count = _tick_player_secondary_projectile_spawn_count(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    )
    player_projectile_spawned = int(player_projectile_spawn_count) > 0
    player_secondary_spawned = int(player_secondary_spawn_count) > 0
    if not player_projectile_spawned and not player_secondary_spawned:
        return False
    if bool(ammo_dropped_since_previous_checkpoint):
        return True
    if bool(player_secondary_spawned):
        return True
    if _tick_player_has_only_zero_cooldown_player_fire_events(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    ):
        # If native reports only zero-cooldown `player_fire` rows for this player,
        # treat the projectile spawns as proc-driven and avoid synthesizing fire.
        return False
    if _tick_player_projectile_bonus_apply(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    ):
        if weapon_id_hint is not None and _tick_player_weapon_projectile_spawned(
            tick,
            player_index=int(player_index),
            player_count=int(player_count),
            weapon_id=int(weapon_id_hint),
        ):
            return True
        return False
    if weapon_id_hint is None:
        return _tick_player_projectile_type_spawned(
            tick,
            player_index=int(player_index),
            player_count=int(player_count),
            projectile_type_id=int(_PROJECTILE_TYPE_FIRE_BULLETS),
        )
    if _tick_player_weapon_projectile_spawned(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
        weapon_id=int(weapon_id_hint),
    ):
        return True
    if previous_weapon_id_hint is not None and _tick_player_weapon_projectile_spawned(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
        weapon_id=int(previous_weapon_id_hint),
    ):
        return True
    return _tick_player_projectile_type_spawned(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
        projectile_type_id=int(_PROJECTILE_TYPE_FIRE_BULLETS),
    )


def _infer_status_snapshot(capture: CaptureFile) -> ReplayStatusSnapshot:
    unlock_index = -1
    unlock_index_full = -1
    usage_counts: tuple[int, ...] = ()

    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        status = tick.checkpoint.status
        if int(unlock_index) < 0 and int(status.quest_unlock_index) >= 0:
            unlock_index = int(status.quest_unlock_index)
        if int(unlock_index_full) < 0 and int(status.quest_unlock_index_full) >= 0:
            unlock_index_full = int(status.quest_unlock_index_full)
        if not usage_counts and status.weapon_usage_counts:
            usage_counts = tuple(int(value) & 0xFFFFFFFF for value in status.weapon_usage_counts)
        if int(unlock_index) >= 0 and int(unlock_index_full) >= 0 and usage_counts:
            break

    if int(unlock_index) < 0 or int(unlock_index_full) < 0:
        raise ValueError(
            "cannot infer replay status unlock indices from capture checkpoint status telemetry",
        )

    counts = list(usage_counts[:WEAPON_USAGE_COUNT])
    if len(counts) < WEAPON_USAGE_COUNT:
        counts.extend([0] * (WEAPON_USAGE_COUNT - len(counts)))

    return ReplayStatusSnapshot(
        quest_unlock_index=int(unlock_index),
        quest_unlock_index_full=int(unlock_index_full),
        weapon_usage_counts=tuple(int(value) & 0xFFFFFFFF for value in counts),
    )


def _normalize_capture_move_components(move_dx: float, move_dy: float) -> tuple[float, float]:
    x = float(move_dx)
    y = float(move_dy)
    if not math.isfinite(x):
        x = 0.0
    if not math.isfinite(y):
        y = 0.0
    mag_sq = x * x + y * y
    if mag_sq > 1.0:
        mag = math.sqrt(mag_sq)
        if mag > 1e-9:
            inv = 1.0 / mag
            x *= inv
            y *= inv
    return (max(-1.0, min(1.0, x)), max(-1.0, min(1.0, y)))


def _crt_rand_step(state: int) -> tuple[int, int]:
    next_state = (int(state) * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MOD_MASK
    return int(next_state), int((next_state >> 16) & 0x7FFF)


def _seed_matches_rng_marks(seed: int, *, rng_head: list[int], rand_calls: object, rand_last: object) -> bool:
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


def infer_capture_seed(capture: CaptureFile) -> int:
    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        seed_from_state = _infer_seed_from_rng_state_before(tick)
        if seed_from_state is not None:
            return int(seed_from_state)
    raise ValueError(
        "cannot infer replay seed from capture: missing rng `state_before_u32` telemetry; "
        "pass an explicit seed override",
    )


def build_capture_dt_frame_overrides(capture: CaptureFile, *, tick_rate: int = 60) -> dict[int, float]:
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
        frame_dt_ms = _tick_frame_dt_ms(tick)
        if frame_dt_ms is not None:
            dt_frame = float(frame_dt_ms) / 1000.0
            if math.isfinite(dt_frame) and dt_frame > 0.0:
                explicit_overrides[int(tick_index)] = float(dt_frame)

        elapsed_ms = int(tick.checkpoint.elapsed_ms)
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

    out.update(explicit_overrides)

    for tick_index in list(out.keys()):
        if int(tick_index) in explicit_overrides:
            continue
        if math.isclose(float(out[tick_index]), float(nominal_dt), rel_tol=1e-9, abs_tol=1e-9):
            del out[tick_index]

    return out


def build_capture_dt_frame_ms_i32_overrides(capture: CaptureFile) -> dict[int, int]:
    out: dict[int, int] = {}
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        dt_ms_i32 = _tick_frame_dt_ms_i32(tick)
        if dt_ms_i32 is None:
            continue
        dt_ms_i32 = int(dt_ms_i32)
        if dt_ms_i32 <= 0:
            continue
        out[int(tick_index)] = int(dt_ms_i32)
    return out


def build_capture_inter_tick_rand_draws_overrides(capture: CaptureFile) -> dict[int, int] | None:
    quest_capture = any(
        int(tick.game_mode_id) == int(GameMode.QUESTS)
        or str(tick.mode_hint).strip() == "quest_mode_update"
        for tick in capture.ticks
    )
    out: dict[int, int] = {}
    first_in_tick_rand_tick: int | None = None
    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        tick_index = int(tick.tick_index)
        calls = _coerce_int_like(tick.checkpoint.rng_marks.rand_outside_before_calls)
        if calls is None or int(calls) < 0:
            continue
        out[int(tick_index)] = int(calls)

        if quest_capture and first_in_tick_rand_tick is None:
            in_tick_calls_candidates = [
                _coerce_int_like(tick.rng.calls),
                _coerce_int_like(tick.checkpoint.rng_marks.rand_calls),
            ]
            in_tick_calls = max((int(value) for value in in_tick_calls_candidates if value is not None), default=None)
            if in_tick_calls is not None and int(in_tick_calls) > 0:
                first_in_tick_rand_tick = int(tick_index)

    if out:
        first_tick_index = min(out)
        # Inferred replay seed already matches the first sampled tick state.
        out[int(first_tick_index)] = 0
        if quest_capture:
            if first_in_tick_rand_tick is None:
                for tick_index in tuple(out):
                    out[int(tick_index)] = 0
            else:
                for tick_index in tuple(out):
                    if int(tick_index) <= int(first_in_tick_rand_tick):
                        # In quest split captures we often infer the replay seed from
                        # the first tick with in-tick RNG telemetry. That seed already
                        # reflects this tick's pre-step outside-before draws.
                        out[int(tick_index)] = 0
        return out
    return None


def _tick_before_player_snapshot(tick: CaptureTick, *, player_index: int) -> Mapping[object, object] | None:
    before = tick.before
    if before is None:
        return None
    players = before.players
    if not isinstance(players, list):
        return None
    if int(player_index) < 0 or int(player_index) >= len(players):
        return None
    raw_player = players[int(player_index)]
    if not isinstance(raw_player, dict):
        return None
    return cast(Mapping[object, object], raw_player)


def _before_player_bonus_timers_ms(player: Mapping[object, object] | None) -> dict[str, int] | None:
    if player is None:
        return None
    raw_bonus_timers = player.get("bonus_timers")
    if not isinstance(raw_bonus_timers, dict):
        return None
    bonus_timers = cast(Mapping[object, object], raw_bonus_timers)
    out: dict[str, int] = {}
    for key in ("speed_bonus", "shield", "fire_bullets"):
        timer_seconds = _finite_float_or_none(bonus_timers.get(str(key)))
        if timer_seconds is None:
            continue
        out[str(key)] = max(0, int(round(float(timer_seconds) * 1000.0)))
    if not out:
        return None
    return out


def _before_player_perk_timers(player: Mapping[object, object] | None) -> dict[str, float] | None:
    if player is None:
        return None
    raw_perk_timers = player.get("perk_timers")
    if not isinstance(raw_perk_timers, dict):
        return None
    perk_timers = cast(Mapping[object, object], raw_perk_timers)
    out: dict[str, float] = {}
    for key in ("hot_tempered", "man_bomb", "living_fortress", "fire_cough"):
        timer_seconds = _finite_float_or_none(perk_timers.get(str(key)))
        if timer_seconds is None:
            continue
        out[str(key)] = max(0.0, float(timer_seconds))
    if not out:
        return None
    return out


def _before_global_bonus_timers_ms(tick: CaptureTick) -> dict[str, int] | None:
    before = tick.before
    if before is None or not isinstance(before.globals, dict):
        return None
    globals_map = cast(Mapping[object, object], before.globals)
    out: dict[str, int] = {}
    for bonus_id, globals_key in (
        (int(BonusId.WEAPON_POWER_UP), "bonus_weapon_power_up_timer"),
        (int(BonusId.REFLEX_BOOST), "bonus_reflex_boost_timer"),
        (int(BonusId.ENERGIZER), "bonus_energizer_timer"),
        (int(BonusId.DOUBLE_EXPERIENCE), "bonus_double_xp_timer"),
        (int(BonusId.FREEZE), "bonus_freeze_timer"),
    ):
        timer_seconds = _finite_float_or_none(globals_map.get(str(globals_key)))
        if timer_seconds is None:
            continue
        out[str(int(bonus_id))] = max(0, int(round(float(timer_seconds) * 1000.0)))
    if not out:
        return None
    return out


def _before_global_perk_intervals(tick: CaptureTick) -> dict[str, float] | None:
    before = tick.before
    if before is None or not isinstance(before.globals, dict):
        return None
    globals_map = cast(Mapping[object, object], before.globals)
    out: dict[str, float] = {}
    for perk_key, globals_key in _PERK_INTERVAL_GLOBAL_KEYS.items():
        interval_seconds = _finite_float_or_none(globals_map.get(str(globals_key)))
        if interval_seconds is None:
            continue
        out[str(perk_key)] = max(0.0, float(interval_seconds))
    if not out:
        return None
    return out


def _checkpoint_player_perk_active(
    tick: CaptureTick,
    *,
    player_index: int,
    perk_id: int,
) -> bool | None:
    player_nonzero_counts = tick.checkpoint.perk.player_nonzero_counts
    if int(player_index) < 0 or int(player_index) >= len(player_nonzero_counts):
        return None
    rows = player_nonzero_counts[int(player_index)]
    for row in rows:
        if len(row) < 2:
            continue
        row_perk_id = _coerce_int_like(row[0])
        row_count = _coerce_int_like(row[1])
        if row_perk_id is None or row_count is None:
            continue
        if int(row_perk_id) != int(perk_id):
            continue
        return int(row_count) > 0
    return False


def _infer_bootstrap_perk_intervals(capture: CaptureFile, *, tick_rate: int) -> dict[str, float]:
    ticks = sorted(capture.ticks, key=lambda item: int(item.tick_index))
    if len(ticks) < 2:
        return {}

    dt_by_tick = build_capture_dt_frame_overrides(capture, tick_rate=max(1, int(tick_rate)))
    default_dt = 1.0 / float(max(1, int(tick_rate)))
    out: dict[str, float] = {}

    # Perk thresholds are global values; infer each initial interval from the
    # first observed timer wrap (`before_t + dt - before_(t+1)`).
    for idx, tick in enumerate(ticks[:-1]):
        next_tick = ticks[idx + 1]
        if int(next_tick.tick_index) <= int(tick.tick_index):
            continue
        before_player = _tick_before_player_snapshot(tick, player_index=0)
        after_player = _tick_before_player_snapshot(next_tick, player_index=0)
        before_timers = _before_player_perk_timers(before_player)
        after_timers = _before_player_perk_timers(after_player)
        if before_timers is None or after_timers is None:
            continue
        tick_key = int(tick.tick_index)
        next_tick_key = int(next_tick.tick_index)
        if tick_key in dt_by_tick:
            dt_frame = float(dt_by_tick[tick_key])
        elif next_tick_key in dt_by_tick:
            dt_frame = float(dt_by_tick[next_tick_key])
        else:
            dt_frame = float(default_dt)
        # `man_bomb` timer frequently drops to zero from movement gating while the
        # perk remains active; those drops are not interval wraps and produce
        # false interval inference (for example ~1.30s). Keep bootstrap default
        # (`4.0`) unless the capture explicitly provides global interval telemetry.
        for key in ("hot_tempered", "fire_cough"):
            if key in out:
                continue
            perk_id = _PERK_INTERVAL_PERK_IDS.get(str(key))
            if perk_id is not None:
                perk_active_now = _checkpoint_player_perk_active(
                    tick,
                    player_index=0,
                    perk_id=int(perk_id),
                )
                perk_active_next = _checkpoint_player_perk_active(
                    next_tick,
                    player_index=0,
                    perk_id=int(perk_id),
                )
                # Ignore timer drops when both snapshots explicitly report the
                # perk inactive; these are reset artifacts, not interval wraps.
                if perk_active_now is False and perk_active_next is False:
                    continue
            before_value = _finite_float_or_none(before_timers.get(str(key)))
            after_value = _finite_float_or_none(after_timers.get(str(key)))
            if before_value is None or after_value is None:
                continue
            if float(after_value) + 1e-6 >= float(before_value):
                continue
            inferred_interval = float(before_value) + float(dt_frame) - float(after_value)
            if not math.isfinite(inferred_interval) or float(inferred_interval) <= 0.0:
                continue
            out[str(key)] = float(inferred_interval)
        if len(out) >= 3:
            break
    return out


def _f32_from_i32_bits_or_none(value: object) -> float | None:
    bits = _coerce_int_like(value)
    if bits is None:
        return None
    candidate = float(_f32_from_u32(int(bits)))
    if not math.isfinite(candidate):
        return None
    return float(candidate)


def _capture_bootstrap_payload(
    tick: CaptureTick,
    *,
    digital_move_enabled_by_player: list[bool] | None = None,
    perk_intervals: Mapping[str, float] | None = None,
) -> dict[str, object]:
    perk = tick.checkpoint.perk
    players: list[dict[str, object]] = []
    for player_index, player in enumerate(tick.checkpoint.players):
        before_player = _tick_before_player_snapshot(tick, player_index=int(player_index))
        pos_x = float(player.pos.x)
        pos_y = float(player.pos.y)
        health = float(player.health)
        weapon_id = int(player.weapon_id)
        ammo = float(player.ammo)
        experience = int(player.experience)
        level = int(player.level)
        player_bonus_timers_ms = {str(key): int(value) for key, value in player.bonus_timers.items()}

        if before_player is not None:
            before_pos_x = _finite_float_or_none(before_player.get("pos_x"))
            before_pos_y = _finite_float_or_none(before_player.get("pos_y"))
            before_health = _finite_float_or_none(before_player.get("health"))
            before_weapon_id = _coerce_int_like(before_player.get("weapon_id"))
            before_ammo = _finite_float_or_none(before_player.get("ammo_f32"))
            if before_ammo is None:
                before_ammo = _finite_float_or_none(before_player.get("ammo"))
            before_experience = _coerce_int_like(before_player.get("experience"))
            before_level = _coerce_int_like(before_player.get("level"))
            before_player_bonus_timers_ms = _before_player_bonus_timers_ms(before_player)
            before_player_perk_timers = _before_player_perk_timers(before_player)

            if before_pos_x is not None:
                pos_x = float(before_pos_x)
            if before_pos_y is not None:
                pos_y = float(before_pos_y)
            if before_health is not None:
                health = float(before_health)
            if before_weapon_id is not None and int(before_weapon_id) > 0:
                weapon_id = int(before_weapon_id)
            if before_ammo is not None:
                ammo = float(before_ammo)
            if before_experience is not None:
                experience = int(before_experience)
            if before_level is not None and int(before_level) > 0:
                level = int(before_level)
            if before_player_bonus_timers_ms is not None:
                player_bonus_timers_ms = dict(before_player_bonus_timers_ms)

        player_payload: dict[str, object] = {
            "pos": {"x": float(pos_x), "y": float(pos_y)},
            "health": float(health),
            "weapon_id": int(weapon_id),
            "ammo": float(ammo),
            "experience": int(experience),
            "level": int(level),
            "bonus_timers_ms": dict(player_bonus_timers_ms),
        }

        if before_player is not None:
            clip_size = _finite_float_or_none(before_player.get("clip_size_f32"))
            reload_active = _coerce_int_like(before_player.get("reload_active_i32"))
            reload_timer = _finite_float_or_none(before_player.get("reload_timer"))
            reload_timer_max = _finite_float_or_none(before_player.get("reload_timer_max"))
            shot_cooldown = _finite_float_or_none(before_player.get("shot_cooldown"))
            spread_heat = _finite_float_or_none(before_player.get("spread_heat"))
            aim_x = _finite_float_or_none(before_player.get("aim_x"))
            aim_y = _finite_float_or_none(before_player.get("aim_y"))
            aim_heading = _finite_float_or_none(before_player.get("aim_heading"))

            if clip_size is not None:
                player_payload["clip_size"] = max(0, int(clip_size))
            if reload_active is not None:
                player_payload["reload_active"] = bool(reload_active)
            if reload_timer is not None:
                player_payload["reload_timer"] = max(0.0, float(reload_timer))
            if reload_timer_max is not None:
                player_payload["reload_timer_max"] = max(0.0, float(reload_timer_max))
            if shot_cooldown is not None:
                player_payload["shot_cooldown"] = max(0.0, float(shot_cooldown))
            if spread_heat is not None:
                player_payload["spread_heat"] = max(0.0, float(spread_heat))
            if aim_x is not None and aim_y is not None:
                aim_payload: dict[str, float] = {"x": float(aim_x), "y": float(aim_y)}
                if aim_heading is not None:
                    aim_payload["heading"] = float(aim_heading)
                player_payload["aim"] = dict(aim_payload)

            alt_weapon_raw = before_player.get("alt_weapon")
            if isinstance(alt_weapon_raw, dict):
                alt_weapon = cast(Mapping[object, object], alt_weapon_raw)
                alt_weapon_id = _coerce_int_like(alt_weapon.get("weapon_id"))
                alt_clip_size = _finite_float_or_none(alt_weapon.get("clip_size_f32"))
                if alt_clip_size is None:
                    alt_clip_size = _f32_from_i32_bits_or_none(alt_weapon.get("clip_size_i32"))
                alt_ammo = _finite_float_or_none(alt_weapon.get("ammo_f32"))
                if alt_ammo is None:
                    alt_ammo = _f32_from_i32_bits_or_none(alt_weapon.get("ammo_i32"))
                alt_reload_active = _coerce_int_like(alt_weapon.get("reload_active_i32"))
                alt_reload_timer = _finite_float_or_none(alt_weapon.get("reload_timer"))
                alt_shot_cooldown = _finite_float_or_none(alt_weapon.get("shot_cooldown"))
                alt_reload_timer_max = _finite_float_or_none(alt_weapon.get("reload_timer_max"))
                alt_payload: dict[str, object] = {}
                if alt_weapon_id is not None and int(alt_weapon_id) > 0:
                    alt_payload["weapon_id"] = int(alt_weapon_id)
                if alt_clip_size is not None:
                    alt_payload["clip_size"] = max(0, int(alt_clip_size))
                if alt_ammo is not None:
                    alt_payload["ammo"] = float(alt_ammo)
                if alt_reload_active is not None:
                    alt_payload["reload_active"] = bool(alt_reload_active)
                if alt_reload_timer is not None:
                    alt_payload["reload_timer"] = max(0.0, float(alt_reload_timer))
                if alt_shot_cooldown is not None:
                    alt_payload["shot_cooldown"] = max(0.0, float(alt_shot_cooldown))
                if alt_reload_timer_max is not None:
                    alt_payload["reload_timer_max"] = max(0.0, float(alt_reload_timer_max))
                if alt_payload:
                    player_payload["alt_weapon"] = dict(alt_payload)
            if before_player_perk_timers is not None:
                player_payload["perk_timers"] = dict(before_player_perk_timers)

        players.append(dict(player_payload))

    elapsed_ms = int(tick.checkpoint.elapsed_ms)
    perk_pending = int(tick.checkpoint.perk_pending)
    before_globals: Mapping[object, object] | None = None
    if tick.before is not None and isinstance(tick.before.globals, dict):
        before_globals = cast(Mapping[object, object], tick.before.globals)
        before_elapsed_ms = _coerce_int_like(before_globals.get("time_played_ms"))
        if before_elapsed_ms is not None and int(before_elapsed_ms) >= 0:
            elapsed_ms = int(before_elapsed_ms)
        before_perk_pending = _coerce_int_like(before_globals.get("perk_pending_count"))
        if before_perk_pending is not None and int(before_perk_pending) >= 0:
            perk_pending = int(before_perk_pending)

    score_xp = int(tick.checkpoint.score_xp)
    if players:
        player0_xp = _coerce_int_like(players[0].get("experience"))
        if player0_xp is not None and int(player0_xp) >= 0:
            score_xp = int(player0_xp)

    bonus_timers_ms = dict(tick.checkpoint.bonus_timers)
    before_global_bonus_timers_ms = _before_global_bonus_timers_ms(tick)
    if before_global_bonus_timers_ms is not None:
        bonus_timers_ms.update(before_global_bonus_timers_ms)

    payload: dict[str, object] = {
        "tick_index": int(tick.tick_index),
        "elapsed_ms": int(elapsed_ms),
        "score_xp": int(score_xp),
        "perk_pending": int(perk_pending),
        "perk": {
            "pending_count": int(perk.pending_count),
            "choices_dirty": bool(perk.choices_dirty),
            "choices": [int(value) for value in perk.choices],
            "player_nonzero_counts": [
                [[int(perk_id), int(count)] for perk_id, count in player_counts]
                for player_counts in perk.player_nonzero_counts
            ],
        },
        "bonus_timers_ms": dict(bonus_timers_ms),
        "players": players,
        "digital_move_enabled_by_player": (
            [bool(value) for value in digital_move_enabled_by_player]
            if digital_move_enabled_by_player is not None
            else []
        ),
    }
    perk_intervals_payload: dict[str, float] = {}
    before_global_perk_intervals = _before_global_perk_intervals(tick)
    if before_global_perk_intervals is not None:
        perk_intervals_payload.update(
            {
                str(key): float(value)
                for key, value in before_global_perk_intervals.items()
                if math.isfinite(float(value)) and float(value) > 0.0
            },
        )
    if perk_intervals is not None:
        perk_intervals_payload.update(
            {
                str(key): float(value)
                for key, value in perk_intervals.items()
                if math.isfinite(float(value)) and float(value) > 0.0
            },
        )
    if perk_intervals_payload:
        payload["perk_intervals"] = dict(perk_intervals_payload)
    quest_session_payload = _tick_quest_session_bootstrap_payload(tick)
    if quest_session_payload is not None:
        payload["quest_session"] = dict(quest_session_payload)
    return payload


def _event_payload_object(payload: list[object]) -> dict[str, object] | None:
    if not payload:
        return None
    try:
        return msgspec.convert(payload[0], type=dict[str, object], strict=False)
    except msgspec.ValidationError:
        return None


def capture_bootstrap_payload_from_event_payload(payload: list[object]) -> dict[str, object] | None:
    return _event_payload_object(payload)


def capture_perk_apply_id_from_event_payload(payload: list[object]) -> int | None:
    parsed = capture_perk_apply_from_event_payload(payload)
    if parsed is None:
        return None
    perk_id, _ = parsed
    return int(perk_id)


def capture_perk_apply_from_event_payload(payload: list[object]) -> tuple[int, bool] | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    try:
        parsed = msgspec.convert(event_payload, type=_CapturePerkApplyPayload, strict=False)
    except msgspec.ValidationError:
        return None
    return int(parsed.perk_id), bool(parsed.outside_before)


def capture_perk_apply_pending_bounds_from_event_payload(payload: list[object]) -> tuple[int | None, int | None]:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return (None, None)
    try:
        parsed = msgspec.convert(event_payload, type=_CapturePerkApplyPayload, strict=False)
    except msgspec.ValidationError:
        return (None, None)
    pending_before = _coerce_int_like(parsed.pending_before)
    pending_after = _coerce_int_like(parsed.pending_after)
    return (
        int(pending_before) if pending_before is not None and int(pending_before) >= 0 else None,
        int(pending_after) if pending_after is not None and int(pending_after) >= 0 else None,
    )


def capture_perk_pending_from_event_payload(payload: list[object]) -> int | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    try:
        parsed = msgspec.convert(event_payload, type=_CapturePerkPendingPayload, strict=False)
    except msgspec.ValidationError:
        return None
    return int(parsed.perk_pending)


def capture_creature_spawns_from_event_payload(
    payload: list[object],
) -> tuple[tuple[int, float, float, float], ...] | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    spawns_raw = event_payload.get("spawns")
    if not isinstance(spawns_raw, list):
        return None

    out: list[tuple[int, float, float, float]] = []
    for row in spawns_raw:
        if not isinstance(row, dict):
            return None
        row_obj = cast(dict[str, object], row)
        template_id = _coerce_int_like(row_obj.get("template_id"))
        heading = _finite_float_or_none(row_obj.get("heading"))
        pos_raw = row_obj.get("pos")
        if template_id is None or heading is None or not isinstance(pos_raw, dict):
            return None
        pos_obj = cast(dict[str, object], pos_raw)
        pos_x = _finite_float_or_none(pos_obj.get("x"))
        pos_y = _finite_float_or_none(pos_obj.get("y"))
        if pos_x is None or pos_y is None:
            return None
        out.append((int(template_id), float(pos_x), float(pos_y), float(heading)))
    return tuple(out)


def capture_creature_spawn_added_head_from_event_payload(
    payload: list[object],
) -> tuple[tuple[int, float | None, float | None, int | None, int | None], ...] | None:
    rows = capture_creature_spawn_added_head_rows_from_event_payload(payload)
    if rows is None:
        return None

    out: list[tuple[int, float | None, float | None, int | None, int | None]] = []
    for row in rows:
        index = _coerce_int_like(row.get("index"))
        if index is None or int(index) < 0:
            return None
        heading = _finite_float_or_none(row.get("heading"))
        target_heading = _finite_float_or_none(row.get("target_heading"))
        ai_mode = _coerce_int_like(row.get("ai_mode"))
        link_index = _coerce_int_like(row.get("link_index"))
        out.append((int(index), heading, target_heading, ai_mode, link_index))
    return tuple(out)


def capture_creature_spawn_added_head_rows_from_event_payload(
    payload: list[object],
) -> tuple[dict[str, object], ...] | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    rows_raw = event_payload.get("added_head")
    if rows_raw is None:
        return ()
    if not isinstance(rows_raw, list):
        return None

    out: list[dict[str, object]] = []
    for row in rows_raw:
        if not isinstance(row, dict):
            return None
        row_obj = cast(dict[str, object], row)
        index = _coerce_int_like(row_obj.get("index"))
        if index is None or int(index) < 0:
            return None

        row_out: dict[str, object] = {"index": int(index)}
        heading = _finite_float_or_none(row_obj.get("heading"))
        target_heading = _finite_float_or_none(row_obj.get("target_heading"))
        ai_mode = _coerce_int_like(row_obj.get("ai_mode"))
        link_index = _coerce_int_like(row_obj.get("link_index"))
        hp = _finite_float_or_none(row_obj.get("hp"))
        hitbox_size = _finite_float_or_none(row_obj.get("hitbox_size"))
        orbit_angle = _finite_float_or_none(row_obj.get("orbit_angle"))
        orbit_radius = _finite_float_or_none(row_obj.get("orbit_radius"))
        flags = _coerce_int_like(row_obj.get("flags"))
        type_id = _coerce_int_like(row_obj.get("type_id"))
        pos_raw = row_obj.get("pos")

        if heading is not None:
            row_out["heading"] = float(heading)
        if target_heading is not None:
            row_out["target_heading"] = float(target_heading)
        if ai_mode is not None:
            row_out["ai_mode"] = int(ai_mode)
        if link_index is not None:
            row_out["link_index"] = int(link_index)
        if hp is not None:
            row_out["hp"] = float(hp)
        if hitbox_size is not None:
            row_out["hitbox_size"] = float(hitbox_size)
        if orbit_angle is not None:
            row_out["orbit_angle"] = float(orbit_angle)
        if orbit_radius is not None:
            row_out["orbit_radius"] = float(orbit_radius)
        if flags is not None:
            row_out["flags"] = int(flags)
        if type_id is not None:
            row_out["type_id"] = int(type_id)
        if pos_raw is not None:
            if not isinstance(pos_raw, dict):
                return None
            pos_obj = cast(dict[str, object], pos_raw)
            pos_x = _finite_float_or_none(pos_obj.get("x"))
            pos_y = _finite_float_or_none(pos_obj.get("y"))
            if pos_x is None or pos_y is None:
                return None
            row_out["pos"] = {"x": float(pos_x), "y": float(pos_y)}

        out.append(row_out)
    return tuple(out)


def capture_state_transitions_from_event_payload(
    payload: list[object],
) -> tuple[tuple[int, int | None, int | None], ...] | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    transitions_raw = event_payload.get("transitions")
    if not isinstance(transitions_raw, list):
        return None

    out: list[tuple[int, int | None, int | None]] = []
    for row in transitions_raw:
        if not isinstance(row, dict):
            return None
        row_obj = cast(dict[str, object], row)
        target_state = _coerce_int_like(row_obj.get("target_state"))
        if target_state is None:
            return None
        before_state = _coerce_int_like(row_obj.get("before_state"))
        after_state = _coerce_int_like(row_obj.get("after_state"))
        out.append(
            (
                int(target_state),
                int(before_state) if before_state is not None else None,
                int(after_state) if after_state is not None else None,
            ),
        )
    return tuple(out)


def apply_capture_bootstrap_payload(
    payload: dict[str, object],
    *,
    state: object,
    players: list[object],
) -> int | None:
    from ..weapon_runtime import weapon_assign_player

    state_obj = cast(_BootstrapState, state)

    elapsed_value = _int_or(payload.get("elapsed_ms"), -1)
    elapsed_ms: int | None = int(elapsed_value) if int(elapsed_value) >= 0 else None

    players_raw = payload.get("players")
    if isinstance(players_raw, list):
        for idx, raw_player in enumerate(players_raw):
            if idx >= len(players):
                break
            if not isinstance(raw_player, dict):
                continue
            raw_player_map = cast("dict[str, object]", raw_player)
            player = cast(_BootstrapPlayer, players[idx])

            weapon_id = _int_or(raw_player_map.get("weapon_id"), int(player.weapon_id))
            if int(weapon_id) > 0:
                try:
                    if int(player.weapon_id) != int(weapon_id):
                        weapon_assign_player(player, int(weapon_id), state=state)  # ty:ignore[invalid-argument-type]
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid bootstrap weapon assignment payload for player[{idx}]") from exc

            pos_raw = raw_player_map.get("pos")
            if isinstance(pos_raw, dict):
                pos_map = cast("dict[str, object]", pos_raw)
                px = _float_or(pos_map.get("x"), float(player.pos.x))
                py = _float_or(pos_map.get("y"), float(player.pos.y))
                if math.isfinite(px) and math.isfinite(py):
                    player.pos = Vec2(float(px), float(py))

            health = _float_or(raw_player_map.get("health"), float(player.health))
            ammo = _float_or(raw_player_map.get("ammo"), float(player.ammo))
            experience = _int_or(raw_player_map.get("experience"), int(player.experience))
            level = _int_or(raw_player_map.get("level"), int(player.level))

            player.health = float(health)
            player.ammo = float(ammo)
            player.experience = int(experience)
            if int(level) > 0:
                player.level = int(level)

            clip_size = _coerce_int_like(raw_player_map.get("clip_size"))
            if clip_size is not None and int(clip_size) >= 0:
                player.clip_size = int(clip_size)

            reload_active = _coerce_int_like(raw_player_map.get("reload_active"))
            if reload_active is not None:
                player.reload_active = bool(reload_active)

            reload_timer = _finite_float_or_none(raw_player_map.get("reload_timer"))
            if reload_timer is not None:
                player.reload_timer = max(0.0, float(reload_timer))

            reload_timer_max = _finite_float_or_none(
                raw_player_map.get("reload_timer_max"),
            )
            if reload_timer_max is not None:
                player.reload_timer_max = max(0.0, float(reload_timer_max))

            shot_cooldown = _finite_float_or_none(
                raw_player_map.get("shot_cooldown"),
            )
            if shot_cooldown is not None:
                player.shot_cooldown = max(0.0, float(shot_cooldown))

            spread_heat = _finite_float_or_none(raw_player_map.get("spread_heat"))
            if spread_heat is not None:
                player.spread_heat = max(0.0, float(spread_heat))

            aim_raw = raw_player_map.get("aim")
            if isinstance(aim_raw, dict):
                aim_map = cast("dict[str, object]", aim_raw)
                aim_x = _finite_float_or_none(aim_map.get("x"))
                aim_y = _finite_float_or_none(aim_map.get("y"))
                if aim_x is not None and aim_y is not None:
                    player.aim = Vec2(float(aim_x), float(aim_y))
                aim_heading = _finite_float_or_none(aim_map.get("heading"))
                if aim_heading is not None:
                    player.aim_heading = float(aim_heading)
                    player.aim_dir = Vec2.from_heading(float(aim_heading))

            alt_weapon_raw = raw_player_map.get("alt_weapon")
            if isinstance(alt_weapon_raw, dict):
                alt_weapon_map = cast("dict[str, object]", alt_weapon_raw)
                alt_weapon_id = _coerce_int_like(
                    alt_weapon_map.get("weapon_id"),
                )
                alt_clip_size = _coerce_int_like(
                    alt_weapon_map.get("clip_size"),
                )
                alt_ammo = _finite_float_or_none(alt_weapon_map.get("ammo"))
                alt_reload_active = _coerce_int_like(
                    alt_weapon_map.get("reload_active"),
                )
                alt_reload_timer = _finite_float_or_none(
                    alt_weapon_map.get("reload_timer"),
                )
                alt_reload_timer_max = _finite_float_or_none(
                    alt_weapon_map.get("reload_timer_max"),
                )
                alt_shot_cooldown = _finite_float_or_none(
                    alt_weapon_map.get("shot_cooldown"),
                )
                if alt_weapon_id is not None:
                    player.alt_weapon_id = int(alt_weapon_id) if int(alt_weapon_id) > 0 else None
                if alt_clip_size is not None and int(alt_clip_size) >= 0:
                    player.alt_clip_size = int(alt_clip_size)
                if alt_ammo is not None:
                    player.alt_ammo = float(alt_ammo)
                if alt_reload_active is not None:
                    player.alt_reload_active = bool(alt_reload_active)
                if alt_reload_timer is not None:
                    player.alt_reload_timer = max(0.0, float(alt_reload_timer))
                if alt_reload_timer_max is not None:
                    player.alt_reload_timer_max = max(0.0, float(alt_reload_timer_max))
                if alt_shot_cooldown is not None:
                    player.alt_shot_cooldown = max(0.0, float(alt_shot_cooldown))

            player_timers_raw = raw_player_map.get("bonus_timers_ms")
            if isinstance(player_timers_raw, dict):
                player_timers = cast("dict[str, object]", player_timers_raw)
                try:
                    shield_ms = _coerce_int_like(player_timers.get("shield"))
                    fire_bullets_ms = _coerce_int_like(
                        player_timers.get("fire_bullets"),
                    )
                    speed_bonus_ms = _coerce_int_like(
                        player_timers.get("speed_bonus"),
                    )
                    if shield_ms is not None:
                        player.shield_timer = max(0.0, float(shield_ms) / 1000.0)
                    if fire_bullets_ms is not None:
                        player.fire_bullets_timer = max(0.0, float(fire_bullets_ms) / 1000.0)
                    if speed_bonus_ms is not None:
                        player.speed_bonus_timer = max(0.0, float(speed_bonus_ms) / 1000.0)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid bootstrap bonus_timers_ms payload for player[{idx}]") from exc

            player_perk_timers_raw = raw_player_map.get("perk_timers")
            if isinstance(player_perk_timers_raw, dict):
                player_perk_timers = cast("dict[str, object]", player_perk_timers_raw)
                try:
                    hot_tempered_timer = _finite_float_or_none(
                        player_perk_timers.get("hot_tempered"),
                    )
                    man_bomb_timer = _finite_float_or_none(
                        player_perk_timers.get("man_bomb"),
                    )
                    living_fortress_timer = _finite_float_or_none(
                        (
                            player_perk_timers["living_fortress"]
                            if "living_fortress" in player_perk_timers
                            else None
                        ),
                    )
                    fire_cough_timer = _finite_float_or_none(
                        player_perk_timers.get("fire_cough"),
                    )
                    if hot_tempered_timer is not None:
                        player.hot_tempered_timer = max(0.0, float(hot_tempered_timer))
                    if man_bomb_timer is not None:
                        player.man_bomb_timer = max(0.0, float(man_bomb_timer))
                    if living_fortress_timer is not None:
                        player.living_fortress_timer = max(0.0, float(living_fortress_timer))
                    if fire_cough_timer is not None:
                        player.fire_cough_timer = max(0.0, float(fire_cough_timer))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid bootstrap perk_timers payload for player[{idx}]") from exc

    perk_payload = payload.get("perk")
    pending = _int_or(payload.get("perk_pending"), int(state_obj.perk_selection.pending_count))
    perk_choices = [int(perk_id) for perk_id in state_obj.perk_selection.choices]
    perk_choices_dirty = bool(state_obj.perk_selection.choices_dirty)
    perk_player_nonzero_counts: list[list[tuple[int, int]]] = []
    has_perk_player_nonzero_counts = False
    if isinstance(perk_payload, dict):
        perk_payload_map = cast(Mapping[object, object], perk_payload)
        perk_pending = _int_or(perk_payload_map.get("pending_count"), pending)
        if int(perk_pending) >= 0:
            pending = int(perk_pending)
        raw_choices = perk_payload_map.get("choices")
        if isinstance(raw_choices, list):
            parsed_choices: list[int] = []
            for value in raw_choices:
                perk_id = _coerce_int_like(value)
                if perk_id is None:
                    continue
                parsed_choices.append(int(perk_id))
            perk_choices = parsed_choices
        raw_choices_dirty = perk_payload_map.get("choices_dirty")
        if isinstance(raw_choices_dirty, bool):
            perk_choices_dirty = bool(raw_choices_dirty)
        raw_player_nonzero_counts = perk_payload_map.get("player_nonzero_counts")
        if isinstance(raw_player_nonzero_counts, list):
            parsed_all_players: list[list[tuple[int, int]]] = []
            for raw_player_counts in raw_player_nonzero_counts:
                parsed_player_counts: list[tuple[int, int]] = []
                if isinstance(raw_player_counts, list):
                    for raw_pair in raw_player_counts:
                        if not isinstance(raw_pair, list) or len(raw_pair) < 2:
                            continue
                        perk_id = _coerce_int_like(raw_pair[0])
                        count = _coerce_int_like(raw_pair[1])
                        if perk_id is None or count is None:
                            continue
                        parsed_player_counts.append((int(perk_id), int(count)))
                parsed_all_players.append(parsed_player_counts)
            perk_player_nonzero_counts = parsed_all_players
            has_perk_player_nonzero_counts = True

    if int(pending) >= 0:
        state_obj.perk_selection.pending_count = int(pending)
        state_obj.perk_selection.choices = [int(perk_id) for perk_id in perk_choices]
        state_obj.perk_selection.choices_dirty = bool(perk_choices_dirty)

    if has_perk_player_nonzero_counts:
        capture_counts_known = any(bool(player_counts) for player_counts in perk_player_nonzero_counts)
        state_obj.perk_selection.capture_player_perk_counts_known = bool(capture_counts_known)
        for player_index, player_perk_counts in enumerate(perk_player_nonzero_counts):
            if player_index >= len(players):
                break
            player = cast(_BootstrapPlayer, players[int(player_index)])
            perk_counts = player.perk_counts
            for idx in range(len(perk_counts)):
                perk_counts[idx] = 0
            for perk_id, count in player_perk_counts:
                perk_idx = int(perk_id)
                if 0 <= perk_idx < len(perk_counts):
                    perk_counts[perk_idx] = int(count)

    timers_raw = payload.get("bonus_timers_ms")
    if isinstance(timers_raw, dict):
        weapon_power_up_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.WEAPON_POWER_UP))))  # ty:ignore[invalid-argument-type]
        reflex_boost_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.REFLEX_BOOST))))  # ty:ignore[invalid-argument-type]
        energizer_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.ENERGIZER))))  # ty:ignore[invalid-argument-type]
        double_xp_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.DOUBLE_EXPERIENCE))))  # ty:ignore[invalid-argument-type]
        freeze_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.FREEZE))))  # ty:ignore[invalid-argument-type]
        if weapon_power_up_ms is not None:
            state_obj.bonuses.weapon_power_up = max(0.0, float(weapon_power_up_ms) / 1000.0)
        if reflex_boost_ms is not None:
            state_obj.bonuses.reflex_boost = max(0.0, float(reflex_boost_ms) / 1000.0)
        if energizer_ms is not None:
            state_obj.bonuses.energizer = max(0.0, float(energizer_ms) / 1000.0)
        if double_xp_ms is not None:
            state_obj.bonuses.double_experience = max(0.0, float(double_xp_ms) / 1000.0)
        if freeze_ms is not None:
            state_obj.bonuses.freeze = max(0.0, float(freeze_ms) / 1000.0)
        state_obj.time_scale_active = float(state_obj.bonuses.reflex_boost) > 0.0

    perk_intervals_raw = payload.get("perk_intervals")
    if isinstance(perk_intervals_raw, dict):
        perk_intervals_map = cast(Mapping[object, object], perk_intervals_raw)
        man_bomb_interval = _finite_float_or_none(perk_intervals_map.get("man_bomb"))
        fire_cough_interval = _finite_float_or_none(perk_intervals_map.get("fire_cough"))
        hot_tempered_interval = _finite_float_or_none(perk_intervals_map.get("hot_tempered"))
        if man_bomb_interval is not None:
            state_obj.perk_intervals.man_bomb = max(0.0, float(man_bomb_interval))
        if fire_cough_interval is not None:
            state_obj.perk_intervals.fire_cough = max(0.0, float(fire_cough_interval))
        if hot_tempered_interval is not None:
            state_obj.perk_intervals.hot_tempered = max(0.0, float(hot_tempered_interval))

    return elapsed_ms


def _perk_apply_rows_in_tick(tick: CaptureTick) -> tuple[tuple[int, bool, int | None, int | None], ...]:
    out: list[tuple[int, bool, int | None, int | None]] = []

    for item in tick.perk_apply_outside_before.head:
        perk_id = item.perk_id
        if perk_id is None or int(perk_id) <= 0:
            continue
        pending_before = _coerce_int_like(item.pending_before)
        pending_after = _coerce_int_like(item.pending_after)
        out.append(
            (
                int(perk_id),
                True,
                int(pending_before) if pending_before is not None and int(pending_before) >= 0 else None,
                int(pending_after) if pending_after is not None and int(pending_after) >= 0 else None,
            ),
        )

    for item in tick.perk_apply_in_tick:
        perk_id = item.perk_id
        if perk_id is None or int(perk_id) <= 0:
            continue
        out.append((int(perk_id), False, None, None))

    if not tick.perk_apply_in_tick:
        for head in tick.event_heads:
            if isinstance(head, CaptureEventHeadPerkApply):
                if head.perk_id is not None and int(head.perk_id) > 0:
                    out.append((int(head.perk_id), False, None, None))

    deduped: list[tuple[int, bool, int | None, int | None]] = []
    seen: set[int] = set()
    for perk_id, outside_before, pending_before, pending_after in out:
        if int(perk_id) in seen:
            continue
        seen.add(int(perk_id))
        deduped.append((int(perk_id), bool(outside_before), pending_before, pending_after))
    return tuple(deduped)


def _tick_creature_spawn_rows(tick: CaptureTick) -> tuple[dict[str, object], ...]:
    out: list[dict[str, object]] = []
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadCreatureSpawn):
            continue
        data: dict[str, object]
        if isinstance(head.data, dict):
            data = head.data
        else:
            data = {}
        caller_static = data.get("caller_static")
        caller_static_s = str(caller_static).strip().lower() if isinstance(caller_static, str) else ""
        if caller_static_s not in _QUEST_CAPTURE_SPAWN_CALLERS:
            # Keep quest original-capture replay on a known caller set and skip
            # unrelated/noisy spawn hooks.
            continue
        template_id = _coerce_int_like(data.get("template_id"))
        heading = _finite_float_or_none(data.get("heading"))
        pos_raw = data.get("pos")
        if template_id is None or heading is None or not isinstance(pos_raw, dict):
            continue
        pos_obj = cast(dict[str, object], pos_raw)
        pos_x = _finite_float_or_none(pos_obj.get("x"))
        pos_y = _finite_float_or_none(pos_obj.get("y"))
        if pos_x is None or pos_y is None:
            continue
        out.append(
            {
                "template_id": int(template_id),
                "pos": {"x": float(pos_x), "y": float(pos_y)},
                "heading": float(heading),
            },
        )
    return tuple(out)


def _tick_creature_spawn_added_rows(tick: CaptureTick) -> tuple[dict[str, object], ...]:
    out: list[dict[str, object]] = []
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadCreatureLifecycle):
            continue
        data: dict[str, object]
        if isinstance(head.data, dict):
            data = head.data
        else:
            data = {}
        added_head = data.get("added_head")
        if not isinstance(added_head, list):
            continue
        for raw_row in added_head:
            if not isinstance(raw_row, dict):
                continue
            row = cast(dict[str, object], raw_row)
            index = _coerce_int_like(row.get("index"))
            if index is None or int(index) < 0:
                continue
            heading = _finite_float_or_none(row.get("heading"))
            target_heading = _finite_float_or_none(row.get("target_heading"))
            ai_mode = _coerce_int_like(row.get("ai_mode"))
            link_index = _coerce_int_like(row.get("link_index"))
            hp = _finite_float_or_none(row.get("hp"))
            hitbox_size = _finite_float_or_none(row.get("hitbox_size"))
            orbit_angle = _finite_float_or_none(row.get("orbit_angle"))
            orbit_radius = _finite_float_or_none(row.get("orbit_radius"))
            flags = _coerce_int_like(row.get("flags"))
            type_id = _coerce_int_like(row.get("type_id"))
            pos_raw = row.get("pos")
            row_out: dict[str, object] = {"index": int(index)}
            if heading is not None:
                row_out["heading"] = float(heading)
            if target_heading is not None:
                row_out["target_heading"] = float(target_heading)
            if ai_mode is not None:
                row_out["ai_mode"] = int(ai_mode)
            if link_index is not None:
                row_out["link_index"] = int(link_index)
            if hp is not None:
                row_out["hp"] = float(hp)
            if hitbox_size is not None:
                row_out["hitbox_size"] = float(hitbox_size)
            if orbit_angle is not None:
                row_out["orbit_angle"] = float(orbit_angle)
            if orbit_radius is not None:
                row_out["orbit_radius"] = float(orbit_radius)
            if flags is not None:
                row_out["flags"] = int(flags)
            if type_id is not None:
                row_out["type_id"] = int(type_id)
            if isinstance(pos_raw, dict):
                pos_obj = cast(dict[str, object], pos_raw)
                pos_x = _finite_float_or_none(pos_obj.get("x"))
                pos_y = _finite_float_or_none(pos_obj.get("y"))
                if pos_x is not None and pos_y is not None:
                    row_out["pos"] = {"x": float(pos_x), "y": float(pos_y)}
            out.append(row_out)
    return tuple(out)


def _tick_state_transition_rows(tick: CaptureTick) -> tuple[dict[str, int], ...]:
    out: list[dict[str, int]] = []
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadStateTransition):
            continue
        data: dict[str, object]
        if isinstance(head.data, dict):
            data = head.data
        else:
            data = {}
        target_state = _coerce_int_like(data.get("target_state"))
        if target_state is None:
            continue
        row: dict[str, int] = {"target_state": int(target_state)}
        before_raw = data.get("before")
        if isinstance(before_raw, dict):
            before_obj = cast(dict[str, object], before_raw)
            before_state = _coerce_int_like(before_obj.get("id"))
            if before_state is not None:
                row["before_state"] = int(before_state)
        after_raw = data.get("after")
        if isinstance(after_raw, dict):
            after_obj = cast(dict[str, object], after_raw)
            after_state = _coerce_int_like(after_obj.get("id"))
            if after_state is not None:
                row["after_state"] = int(after_state)
        out.append(row)
    return tuple(out)


def _has_terminal_state_transition(rows: tuple[dict[str, int], ...]) -> bool:
    for row in rows:
        if "target_state" in row and int(row["target_state"]) == 12:
            return True
    return False


def _tick_perk_pending_count(tick: CaptureTick) -> int | None:
    pending = int(tick.checkpoint.perk_pending)
    if pending >= 0:
        return int(pending)

    snapshot_pending = int(tick.checkpoint.perk.pending_count)
    if snapshot_pending >= 0:
        return int(snapshot_pending)

    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadPerkDelta):
            continue
        pending_value = _coerce_int_like(head.data.get("perk_pending_count"))
        if pending_value is not None and int(pending_value) >= 0:
            return int(pending_value)
    return None


def convert_capture_to_checkpoints(capture: CaptureFile, *, replay_sha256: str = "") -> ReplayCheckpoints:
    checkpoints: list[ReplayCheckpoint] = []
    for tick in capture.ticks:
        ckpt = tick.checkpoint
        checkpoints.append(
            ReplayCheckpoint(
                tick_index=int(tick.tick_index),
                rng_state=int(ckpt.rng_state),
                elapsed_ms=int(ckpt.elapsed_ms),
                score_xp=int(ckpt.score_xp),
                kills=int(ckpt.kills),
                creature_count=int(ckpt.creature_count),
                perk_pending=int(ckpt.perk_pending),
                players=[_replay_player(player) for player in ckpt.players],
                bonus_timers={str(key): int(value) for key, value in ckpt.bonus_timers.items()},
                state_hash=str(ckpt.state_hash),
                command_hash=str(ckpt.command_hash),
                rng_marks=_rng_marks_int_map(tick),
                deaths=[_replay_death(item) for item in ckpt.deaths],
                perk=_replay_perk(ckpt.perk),
                events=_replay_events(ckpt.events),
            ),
        )

    return ReplayCheckpoints(
        version=CHECKPOINTS_FORMAT_VERSION,
        replay_sha256=str(replay_sha256),
        sample_rate=_capture_sample_rate(capture),
        checkpoints=checkpoints,
    )


def convert_capture_to_replay(
    capture: CaptureFile,
    *,
    seed: int | None = None,
    player_count: int | None = None,
    tick_rate: int = 60,
    world_size: float = 1024.0,
    game_mode_id: int | None = None,
    aim_scheme_overrides_by_player: Mapping[int, int] | None = None,
) -> Replay:
    resolved_seed = infer_capture_seed(capture) if seed is None else int(seed)
    resolved_player_count = _infer_player_count(capture) if player_count is None else int(player_count)
    if int(resolved_player_count) <= 0:
        raise ValueError(f"replay player_count must be > 0 (got {resolved_player_count})")
    digital_move_enabled_by_player = _infer_digital_move_enabled_by_player(
        capture,
        player_count=int(resolved_player_count),
    )
    resolved_mode_id = _infer_game_mode_id(capture) if game_mode_id is None else int(game_mode_id)
    resolved_quest_level = _infer_quest_level(capture, game_mode_id=int(resolved_mode_id))
    status_snapshot = _infer_status_snapshot(capture)

    if capture.ticks:
        max_tick_index = max(max(0, int(tick.tick_index)) for tick in capture.ticks)
        total_ticks = int(max_tick_index) + 1
    else:
        total_ticks = 0

    inputs: list[list[list[float | int | list[float]]]] = [
        [[0.0, 0.0, [0.0, 0.0], 0] for _ in range(int(resolved_player_count))] for _ in range(total_ticks)
    ]
    previous_checkpoint_ammo: list[float | None] = [None for _ in range(int(resolved_player_count))]
    previous_checkpoint_weapon_id: list[int | None] = [None for _ in range(int(resolved_player_count))]
    normalized_aim_scheme_overrides = dict(aim_scheme_overrides_by_player or {})

    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        tick_index = int(tick.tick_index)
        if tick_index < 0 or tick_index >= total_ticks:
            continue
        approx_by_player = {int(sample.player_index): sample for sample in tick.input_approx}
        keys_by_player = {int(row.player_index): row for row in tick.input_player_keys}
        checkpoint_players = tick.checkpoint.players
        for player_index in range(int(resolved_player_count)):
            sample = approx_by_player.get(int(player_index))
            key_row = keys_by_player.get(int(player_index))
            if normalized_aim_scheme_overrides:
                aim_scheme_value = _coerce_player_int(
                    normalized_aim_scheme_overrides,
                    player_index=int(player_index),
                )
            else:
                aim_scheme_value = None
            if aim_scheme_value is None:
                aim_scheme_value = _tick_player_aim_scheme(tick, player_index=int(player_index))
            fire_down_raw = None
            fire_pressed_raw = None
            reload_pressed_raw = None
            move_forward_pressed: bool | None = None
            move_backward_pressed: bool | None = None
            turn_left_pressed: bool | None = None
            turn_right_pressed: bool | None = None
            use_digital_move = False
            ammo_dropped_since_previous_checkpoint = False

            checkpoint_ammo: float | None = None
            checkpoint_weapon_id: int | None = None
            weapon_id_hint: int | None = None
            previous_weapon_id_hint: int | None = previous_checkpoint_weapon_id[int(player_index)]
            if 0 <= int(player_index) < len(checkpoint_players):
                checkpoint_ammo = float(checkpoint_players[int(player_index)].ammo)
                checkpoint_weapon_id = int(checkpoint_players[int(player_index)].weapon_id)
                weapon_id_hint = int(checkpoint_weapon_id)
                previous_ammo = previous_checkpoint_ammo[int(player_index)]
                if previous_ammo is not None and float(checkpoint_ammo) < float(previous_ammo) - 1e-6:
                    ammo_dropped_since_previous_checkpoint = True
            sample_weapon_id = _coerce_int_like(sample.weapon_id) if sample is not None else None
            if sample_weapon_id is not None:
                weapon_id_hint = int(sample_weapon_id)

            if sample is not None or key_row is not None:
                move_forward_raw = key_row.move_forward_pressed if key_row is not None else None
                move_backward_raw = key_row.move_backward_pressed if key_row is not None else None
                turn_left_raw = key_row.turn_left_pressed if key_row is not None else None
                turn_right_raw = key_row.turn_right_pressed if key_row is not None else None
                sample_move_dx = float(sample.move_dx) if sample is not None else 0.0
                sample_move_dy = float(sample.move_dy) if sample is not None else 0.0
                has_digital_move = (
                    move_forward_raw is not None
                    or move_backward_raw is not None
                    or turn_left_raw is not None
                    or turn_right_raw is not None
                )
                use_digital_move = bool(
                    has_digital_move
                    and 0 <= int(player_index) < len(digital_move_enabled_by_player)
                    and bool(digital_move_enabled_by_player[int(player_index)]),
                )
                if use_digital_move:
                    turn_left = bool(turn_left_raw)
                    turn_right = bool(turn_right_raw)
                    move_forward = bool(move_forward_raw)
                    move_backward = bool(move_backward_raw)
                    move_forward_pressed = bool(move_forward)
                    move_backward_pressed = bool(move_backward)
                    turn_left_pressed = bool(turn_left)
                    turn_right_pressed = bool(turn_right)
                    move_x = float(turn_right) - float(turn_left)
                    move_y = float(move_backward) - float(move_forward)
                    if turn_left and turn_right:
                        # `input_player_keys` collapses multiple key-query sites in
                        # `player_update`. When move forward/backward is also active,
                        # a later branch can override turn intent with left-biased
                        # precedence; without move keys the initial turn branch stays
                        # right-biased.
                        move_x = -1.0 if (move_forward or move_backward) else 1.0
                    if move_forward and move_backward:
                        # Same collapse behavior for move intent: with turn keys in
                        # play, the later branch can resolve toward forward.
                        move_y = -1.0 if (turn_left or turn_right) else 1.0
                else:
                    move_x, move_y = _normalize_capture_move_components(sample_move_dx, sample_move_dy)
                    move_forward_pressed = None
                    move_backward_pressed = None
                    turn_left_pressed = None
                    turn_right_pressed = None

                if sample is not None:
                    aim_x_raw = float(sample.aim_x)
                    aim_y_raw = float(sample.aim_y)
                    has_aim_xy = math.isfinite(aim_x_raw) and math.isfinite(aim_y_raw)
                    use_heading_fallback = (
                        (not has_aim_xy or (aim_x_raw == 0.0 and aim_y_raw == 0.0))
                        and sample.aim_heading is not None
                    )
                else:
                    aim_x_raw = 0.0
                    aim_y_raw = 0.0
                    has_aim_xy = False
                    use_heading_fallback = False

                if use_heading_fallback:
                    if sample is None or sample.aim_heading is None:
                        continue
                    players = tick.checkpoint.players
                    if player_index < len(players):
                        player_pos_capture = players[player_index].pos
                        player_pos = Vec2(float(player_pos_capture.x), float(player_pos_capture.y))
                    else:
                        player_pos = Vec2()
                    aim_pos = player_pos + Vec2.from_heading(float(sample.aim_heading)) * 256.0
                    aim_x = float(aim_pos.x)
                    aim_y = float(aim_pos.y)
                elif has_aim_xy:
                    aim_x = float(aim_x_raw)
                    aim_y = float(aim_y_raw)
                else:
                    players = tick.checkpoint.players
                    if player_index < len(players):
                        player = players[player_index]
                        aim_x = float(player.pos.x)
                        aim_y = float(player.pos.y)
                    else:
                        aim_x = 0.0
                        aim_y = 0.0

                if key_row is not None:
                    fire_down_raw = key_row.fire_down
                    fire_pressed_raw = key_row.fire_pressed
                    reload_pressed_raw = key_row.reload_pressed
                if reload_pressed_raw is None and _should_synthesize_reload_pressed_for_alt_swap(
                    tick,
                    player_index=int(player_index),
                ):
                    reload_pressed_raw = True

                fire_down = bool(fire_down_raw) if fire_down_raw is not None else False
                fire_pressed = bool(fire_pressed_raw) if fire_pressed_raw is not None else False
                reload_pressed = bool(reload_pressed_raw) if reload_pressed_raw is not None else False
            else:
                move_x = 0.0
                move_y = 0.0
                players = tick.checkpoint.players
                if player_index < len(players):
                    player = players[player_index]
                    aim_x = float(player.pos.x)
                    aim_y = float(player.pos.y)
                else:
                    aim_x = 0.0
                    aim_y = 0.0
                fire_pressed = False
                fire_down = False
                reload_pressed = False
                fire_down_raw = None
                fire_pressed_raw = None
                reload_pressed_raw = None
                move_forward_pressed = None
                move_backward_pressed = None
                turn_left_pressed = None
                turn_right_pressed = None

            if _should_synthesize_computer_fire_down(
                tick=tick,
                player_index=int(player_index),
                player_count=int(resolved_player_count),
                aim_scheme=aim_scheme_value,
                sample=sample,
                fire_down_raw=fire_down_raw,
                fire_pressed_raw=fire_pressed_raw,
                ammo_dropped_since_previous_checkpoint=ammo_dropped_since_previous_checkpoint,
                weapon_id_hint=weapon_id_hint,
                previous_weapon_id_hint=previous_weapon_id_hint,
            ):
                fire_down = True
            if _should_synthesize_fire_pressed_from_primary_edge(
                tick=tick,
                player_index=int(player_index),
                player_count=int(resolved_player_count),
                aim_scheme=aim_scheme_value,
                sample=sample,
                fire_down_raw=fire_down_raw,
                fire_pressed_raw=fire_pressed_raw,
            ):
                fire_pressed = True
            if _should_synthesize_fire_down_from_player_fire_event(
                tick=tick,
                player_index=int(player_index),
                player_count=int(resolved_player_count),
                fire_down_raw=fire_down_raw,
                fire_pressed_raw=fire_pressed_raw,
            ):
                fire_down = True
            if _should_synthesize_fire_down_from_fractional_ammo_drain(
                tick=tick,
                player_index=int(player_index),
                fire_down_raw=fire_down_raw,
                fire_pressed_raw=fire_pressed_raw,
            ):
                fire_down = True
            if _should_synthesize_fire_down_from_fractional_weapon_fire_sfx(
                tick=tick,
                player_index=int(player_index),
                player_count=int(resolved_player_count),
                fire_down_raw=fire_down_raw,
                fire_pressed_raw=fire_pressed_raw,
            ):
                fire_down = True

            flags = pack_input_flags(
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
                move_mode=(
                    _coerce_int_like(sample.move_mode)
                    if sample is not None
                    else None
                ),
                aim_scheme=(
                    int(aim_scheme_value)
                    if aim_scheme_value is not None
                    else None
                ),
                move_forward_pressed=move_forward_pressed,
                move_backward_pressed=move_backward_pressed,
                turn_left_pressed=turn_left_pressed,
                turn_right_pressed=turn_right_pressed,
            )
            inputs[tick_index][player_index] = [float(move_x), float(move_y), [float(aim_x), float(aim_y)], int(flags)]
            if checkpoint_ammo is not None:
                previous_checkpoint_ammo[int(player_index)] = float(checkpoint_ammo)
            if checkpoint_weapon_id is not None:
                previous_checkpoint_weapon_id[int(player_index)] = int(checkpoint_weapon_id)

    events: list[object] = []
    if capture.ticks:
        bootstrap_perk_intervals = _infer_bootstrap_perk_intervals(capture, tick_rate=max(1, int(tick_rate)))
        first_tick = min(capture.ticks, key=lambda item: int(item.tick_index))
        bootstrap_tick = max(0, int(first_tick.tick_index))
        events.append(
            UnknownEvent(
                tick_index=int(bootstrap_tick),
                kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                payload=[
                    _capture_bootstrap_payload(
                        first_tick,
                        digital_move_enabled_by_player=digital_move_enabled_by_player,
                        perk_intervals=bootstrap_perk_intervals,
                    ),
                ],
            ),
        )

        sorted_ticks = sorted(capture.ticks, key=lambda item: int(item.tick_index))
        transition_rows_by_tick: dict[int, tuple[dict[str, int], ...]] = {}
        menu_open_ticks: set[int] = set()
        previous_pending: int | None = None
        for tick in sorted_ticks:
            state_transition_rows = _tick_state_transition_rows(tick)
            transition_rows_by_tick[int(tick.tick_index)] = state_transition_rows
            if state_transition_rows:
                events.append(
                    UnknownEvent(
                        tick_index=int(tick.tick_index),
                        kind=CAPTURE_STATE_TRANSITION_EVENT_KIND,
                        payload=[{"transitions": list(state_transition_rows)}],
                    ),
                )
                if int(resolved_mode_id) != int(GameMode.RUSH):
                    if any("target_state" in row and int(row["target_state"]) == 6 for row in state_transition_rows):
                        menu_tick = int(tick.tick_index)
                        if menu_tick not in menu_open_ticks:
                            events.append(PerkMenuOpenEvent(tick_index=menu_tick, player_index=0))
                            menu_open_ticks.add(menu_tick)

            if int(resolved_mode_id) == int(GameMode.QUESTS):
                spawn_rows = _tick_creature_spawn_rows(tick)
                added_rows = _tick_creature_spawn_added_rows(tick)
                if spawn_rows or added_rows:
                    spawn_payload: dict[str, object] = {"spawns": list(spawn_rows)}
                    if added_rows:
                        spawn_payload["added_head"] = list(added_rows)
                    events.append(
                        UnknownEvent(
                            tick_index=int(tick.tick_index),
                            kind=CAPTURE_CREATURE_SPAWN_EVENT_KIND,
                            payload=[spawn_payload],
                        ),
                    )

            captured_perk_apply_rows = list(_perk_apply_rows_in_tick(tick))
            if captured_perk_apply_rows:
                seen_perk_apply_ids: set[int] = set()
                for perk_id, outside_before, pending_before, pending_after in captured_perk_apply_rows:
                    if int(perk_id) <= 0 or int(perk_id) in seen_perk_apply_ids:
                        continue
                    seen_perk_apply_ids.add(int(perk_id))
                    payload: dict[str, object] = {
                        "perk_id": int(perk_id),
                        "outside_before": bool(outside_before),
                    }
                    if pending_before is not None:
                        payload["pending_before"] = int(pending_before)
                    if pending_after is not None:
                        payload["pending_after"] = int(pending_after)
                    events.append(
                        UnknownEvent(
                            tick_index=int(tick.tick_index),
                            kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                            payload=[payload],
                        ),
                    )

            pending = _tick_perk_pending_count(tick)
            if pending is None:
                continue
            pending_i = int(pending)
            if previous_pending is not None and pending_i < previous_pending:
                menu_tick = max(0, int(tick.tick_index) - 1)
                menu_tick_key = int(menu_tick)
                if menu_tick_key in transition_rows_by_tick:
                    menu_tick_rows = transition_rows_by_tick[menu_tick_key]
                else:
                    menu_tick_rows = ()
                suppress_menu_open = _has_terminal_state_transition(menu_tick_rows) or _has_terminal_state_transition(
                    state_transition_rows,
                )
                events.append(
                    UnknownEvent(
                        tick_index=int(menu_tick),
                        kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                        payload=[{"perk_pending": int(previous_pending)}],
                    ),
                )
                if not bool(suppress_menu_open):
                    menu_tick_i = int(menu_tick)
                    if menu_tick_i not in menu_open_ticks:
                        events.append(PerkMenuOpenEvent(tick_index=menu_tick_i, player_index=0))
                        menu_open_ticks.add(menu_tick_i)
                events.append(
                    UnknownEvent(
                        tick_index=int(tick.tick_index),
                        kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                        payload=[{"perk_pending": int(pending_i)}],
                    ),
                )
            previous_pending = int(pending_i)

    return Replay(
        header=ReplayHeader(
            game_mode_id=int(resolved_mode_id),
            seed=int(resolved_seed),
            quest_level=str(resolved_quest_level),
            tick_rate=max(1, int(tick_rate)),
            player_count=int(resolved_player_count),
            preserve_bugs=True,
            world_size=float(world_size),
            status=status_snapshot,
        ),
        inputs=inputs,
        events=list(events),  # ty:ignore[invalid-argument-type]
    )


def default_capture_replay_path(checkpoints_path: Path) -> Path:
    checkpoints_path = Path(checkpoints_path)
    name = checkpoints_path.name
    if name.endswith(".crd.chk"):
        stem = name[: -len(".crd.chk")]
    elif name.endswith(".checkpoints.json.gz"):
        stem = name[: -len(".checkpoints.json.gz")]
    elif name.endswith(".chk"):
        stem = name[: -len(".chk")]
    elif name.endswith(".json.gz"):
        stem = name[: -len(".json.gz")]
    elif name.endswith(".json"):
        stem = name[: -len(".json")]
    elif name.endswith(".crd"):
        stem = name[: -len(".crd")]
    else:
        stem = name
    return checkpoints_path.with_name(f"{stem}.crd")


def _validate_capture_path(path: Path) -> None:
    lower = str(path).lower()
    if lower.endswith(".json") or lower.endswith(".json.gz"):
        return
    raise CaptureError(f"capture path must end with .json or .json.gz: {path}")


def _validate_capture_format_version(capture: CaptureFile, path: Path) -> None:
    version = int(capture.capture_format_version)
    if int(version) == int(CAPTURE_FORMAT_VERSION):
        return
    raise CaptureError(
        "unsupported capture format version for "
        f"{path}: got {version}, expected {int(CAPTURE_FORMAT_VERSION)}",
    )


def _decode_capture_stream(raw: bytes, path: Path) -> CaptureFile | None:
    lines = raw.splitlines()
    if not lines:
        return None

    meta: CaptureFile | None = None
    ticks: list[CaptureTick] = []
    saw_stream_row = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            row_obj = msgspec.json.decode(line)
            row_obj = _decode_f32_tokens(row_obj)
            row = msgspec.convert(row_obj, type=_CaptureStreamRow, strict=True)
        except (msgspec.DecodeError, msgspec.ValidationError) as exc:
            raise CaptureError(f"invalid capture file: {path}") from exc

        if isinstance(row, _CaptureStreamMetaRow):
            meta = row.capture
            saw_stream_row = True
            continue

        if isinstance(row, _CaptureStreamTickRow):
            ticks.append(row.tick)
            saw_stream_row = True
            continue

    if not saw_stream_row or meta is None:
        return None

    meta.ticks = ticks
    return meta


def load_capture(path: Path) -> CaptureFile:
    path = Path(path)
    _validate_capture_path(path)

    raw = path.read_bytes()
    if raw.startswith(b"\x1f\x8b"):
        raw = gzip.decompress(raw)

    stream = _decode_capture_stream(raw, path)
    if stream is not None:
        _validate_capture_format_version(stream, path)
        return stream

    raise CaptureError(f"invalid capture file: {path}")


def dump_capture(path: Path, capture: CaptureFile) -> None:
    path = Path(path)
    _validate_capture_path(path)
    _validate_capture_format_version(capture, path)
    capture_obj = msgspec.to_builtins(capture)
    if not isinstance(capture_obj, dict):
        raise CaptureError("invalid capture object during serialization")
    ticks_obj = capture_obj.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    meta = dict(capture_obj)
    meta["ticks"] = []
    rows: list[bytes] = [msgspec.json.encode({"event": "capture_meta", "capture": meta})]
    rows.extend(msgspec.json.encode({"event": "tick", "tick": tick}) for tick in ticks)
    encoded = b"\n".join(rows) + b"\n"
    if str(path).lower().endswith(".gz"):
        path.write_bytes(gzip.compress(encoded))
    else:
        path.write_bytes(encoded)
