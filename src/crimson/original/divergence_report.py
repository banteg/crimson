from __future__ import annotations

import argparse
import bisect
import functools
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, TypedDict, cast

import msgspec

from crimson.bonuses import bonus_label
from crimson.game_modes import GameMode
from crimson.original.capture import (
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_dt_frame_overrides,
    build_capture_inter_tick_rand_draws_overrides,
    convert_capture_to_checkpoints,
    convert_capture_to_replay,
    load_capture,
    parse_player_int_overrides,
)
from crimson.original.diff import ReplayFieldDiff, checkpoint_field_diffs
from crimson.original.schema import (
    CaptureConfig,
    CaptureEventHeadBonusApply,
    CaptureEventHeadCreatureDamage,
    CaptureEventHeadCreatureUpdateMicro,
    CaptureEventHeadProjectileFindHit,
    CaptureEventHeadProjectileFindQuery,
    CaptureEventHeadSecondaryProjectileSpawn,
    CaptureEventHeadStateTransition,
    CaptureEventHeadWeaponAssign,
    CaptureFile,
    CaptureInputPlayerKeys,
    CaptureRngCallerCount,
    CaptureRngHeadEntry,
    CaptureTick,
)
from crimson.perks import perk_label
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.sim.driver.replay_runner import run_quest_replay, run_rush_replay, run_survival_replay
from crimson.weapons import WEAPON_BY_ID


@dataclass(frozen=True, slots=True)
class Divergence:
    tick_index: int
    kind: str
    field_diffs: tuple[ReplayFieldDiff, ...]
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None


@dataclass(frozen=True, slots=True)
class NativeFunctionRange:
    name: str
    start: int
    end: int | None


@dataclass(frozen=True, slots=True)
class FieldDriftOnset:
    field: str
    tick: int
    expected: object
    actual: object
    delta: float | int | None


@dataclass(frozen=True, slots=True)
class InvestigationLead:
    title: str
    evidence: tuple[str, ...]
    native_functions: tuple[str, ...] = ()
    code_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RunSummaryEvent:
    tick_index: int
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class DivergenceCategory:
    id: str
    evidence: tuple[str, ...]


RUN_SUMMARY_SHORT_KINDS = {
    "bonus_pickup",
    "weapon_assign",
    "perk_pick",
    "level_up",
    "state_transition",
}


NATIVE_FUNCTION_TO_PORT_PATHS: dict[str, tuple[str, ...]] = {
    "creature_update_all": (
        "src/crimson/creatures/runtime.py",
        "src/crimson/creatures/ai.py",
    ),
    "creature_apply_damage": (
        "src/crimson/creatures/damage.py",
        "src/crimson/creatures/runtime.py",
    ),
    "creature_find_in_radius": (
        "src/crimson/projectiles/pools.py",
        "src/crimson/creatures/runtime.py",
    ),
    "creature_handle_death": ("src/crimson/creatures/runtime.py",),
    "projectile_update": (
        "src/crimson/projectiles/pools.py",
        "src/crimson/sim/world_state.py",
    ),
    "player_update": (
        "src/crimson/gameplay.py",
        "src/crimson/weapons.py",
        "src/crimson/player_damage.py",
    ),
    "bonus_try_spawn_on_kill": (
        "src/crimson/bonuses/pool.py",
        "src/crimson/creatures/runtime.py",
    ),
    "fx_queue_add_random": (
        "src/crimson/effects.py",
        "src/crimson/sim/presentation_step.py",
    ),
    "fx_spawn_sprite": (
        "src/crimson/effects.py",
        "src/crimson/views/projectile_fx.py",
    ),
    "effect_spawn_blood_splatter": (
        "src/crimson/effects.py",
        "src/crimson/sim/presentation_step.py",
        "src/crimson/bonuses/fire_bullets.py",
    ),
}

RNG_STAGE_TO_PORT_PATHS: dict[str, tuple[str, ...]] = {
    "creatures": ("src/crimson/creatures/runtime.py", "src/crimson/creatures/ai.py"),
    "projectiles": ("src/crimson/projectiles/pools.py", "src/crimson/sim/world_state.py"),
    "secondary_projectiles": ("src/crimson/projectiles/pools.py", "src/crimson/sim/world_state.py"),
    "death_sfx_preplan": ("src/crimson/sim/world_state.py", "src/crimson/sim/presentation_step.py"),
    "world_step_tail": ("src/crimson/sim/world_state.py",),
    "survival_stage_spawns": ("src/crimson/creatures/spawn.py", "src/crimson/sim/sessions.py"),
    "survival_wave_spawns": ("src/crimson/creatures/spawn.py", "src/crimson/sim/sessions.py"),
    "rush_spawns": ("src/crimson/creatures/spawn.py", "src/crimson/sim/sessions.py"),
}

_CRT_RAND_MULT = 214013
_CRT_RAND_INC = 2531011
_CRT_RAND_MASK = 0xFFFFFFFF
_CRT_RAND_CALL_SEARCH_LIMIT = 4096
_JSON_OUT_AUTO = "__AUTO__"
_DEFAULT_JSON_OUT_PATH = Path("artifacts/frida/reports/divergence_report_latest.json")


class RngStreamAlignment(TypedDict):
    capture_head_len: int
    actual_calls: int | None
    prefix_match: int | None
    compared: int | None
    missing_tail: int | None
    first_mismatch_idx: int | None
    first_mismatch_reason: str | None
    first_mismatch_capture: int | None
    first_mismatch_actual: int | None
    first_mismatch_capture_state_before: int | None
    first_mismatch_capture_state_after: int | None
    first_mismatch_actual_state_before: int | None
    first_mismatch_actual_state_after: int | None
    first_mismatch_capture_caller_static: str | None
    first_mismatch_capture_branch_id: str | None
    first_mismatch_capture_seq: int | None


def _int_or(value: object, default: int = -1) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)  # ty:ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return int(default)


def _float_or(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)  # ty:ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return float(default)


def _capture_rng_rand_calls(tick: CaptureTick) -> int:
    calls = int(tick.checkpoint.rng_marks.rand_calls)
    if calls >= 0:
        return int(calls)
    return int(tick.rng.calls)


def _capture_rng_seq_first(tick: CaptureTick) -> int:
    if tick.checkpoint.rng_marks.rand_seq_first is not None:
        return int(tick.checkpoint.rng_marks.rand_seq_first)
    if tick.rng.seq_first is not None:
        return int(tick.rng.seq_first)
    return -1


def _capture_rng_seq_last(tick: CaptureTick) -> int:
    if tick.checkpoint.rng_marks.rand_seq_last is not None:
        return int(tick.checkpoint.rng_marks.rand_seq_last)
    if tick.rng.seq_last is not None:
        return int(tick.rng.seq_last)
    return -1


def _capture_rng_seed_epoch_enter(tick: CaptureTick) -> int:
    if tick.checkpoint.rng_marks.rand_seed_epoch_enter is not None:
        return int(tick.checkpoint.rng_marks.rand_seed_epoch_enter)
    if tick.rng.seed_epoch_enter is not None:
        return int(tick.rng.seed_epoch_enter)
    return -1


def _capture_rng_seed_epoch_last(tick: CaptureTick) -> int:
    if tick.checkpoint.rng_marks.rand_seed_epoch_last is not None:
        return int(tick.checkpoint.rng_marks.rand_seed_epoch_last)
    if tick.rng.seed_epoch_last is not None:
        return int(tick.rng.seed_epoch_last)
    return -1


def _capture_rng_outside_before_calls(tick: CaptureTick) -> int:
    calls = int(tick.checkpoint.rng_marks.rand_outside_before_calls)
    if calls >= 0:
        return int(calls)
    return int(tick.rng.outside_before_calls)


def _capture_rng_mirror_mismatch_total(tick: CaptureTick) -> int:
    total = int(tick.checkpoint.rng_marks.rand_mirror_mismatch_total)
    if total >= 0:
        return int(total)
    return int(tick.rng.mirror_mismatch_total)


def _capture_rng_callers(tick: CaptureTick) -> list[CaptureRngCallerCount]:
    callers = list(tick.checkpoint.rng_marks.rand_callers)
    if callers:
        return callers
    return list(tick.rng.callers)


def _capture_rng_head_rows(tick: CaptureTick) -> list[CaptureRngHeadEntry]:
    rows = list(tick.checkpoint.rng_marks.rand_head)
    if rows:
        return rows
    return list(tick.rng.head)


def _rng_value_15_from_entry(entry: CaptureRngHeadEntry) -> int | None:
    if entry.value_15 is not None:
        return int(entry.value_15) & 0x7FFF
    if entry.value is not None:
        return int(entry.value) & 0x7FFF
    return None


def _rng_branch_id(entry: CaptureRngHeadEntry) -> str | None:
    if entry.branch_id:
        return str(entry.branch_id)
    if entry.caller_static:
        return str(entry.caller_static)
    return None


def _rng_stream_rows_for_tick(tick: CaptureTick) -> list[CaptureRngHeadEntry]:
    return _capture_rng_head_rows(tick)


def _effective_capture_projectile_hit_count(tick: CaptureTick) -> int:
    capture_hits = int(tick.event_counts.projectile_find_hit)
    if capture_hits < 0:
        return -1
    owner_collision_count = int(tick.checkpoint.debug.spawn.event_count_projectile_find_query_owner_collision)
    if owner_collision_count < 0:
        return int(capture_hits)
    return max(0, int(capture_hits) - int(owner_collision_count))


def _capture_sample_rate(capture: CaptureFile) -> int:
    ticks = sorted(int(tick.tick_index) for tick in capture.ticks)
    if len(ticks) < 2:
        return 1
    deltas = [next_tick - tick for tick, next_tick in zip(ticks, ticks[1:]) if int(next_tick) > int(tick)]
    if not deltas:
        return 1
    deltas.sort()
    return max(1, int(deltas[len(deltas) // 2]))


def _fmt_opt_int(value: object, *, width: int = 0, unknown: str = "na") -> str:
    if value is None:
        return f"{unknown:>{width}}" if width > 0 else unknown
    try:
        ivalue = int(value)  # ty:ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return f"{unknown:>{width}}" if width > 0 else unknown
    return f"{ivalue:{width}d}" if width > 0 else str(ivalue)


def _resolve_json_out_path(value: str | None) -> Path | None:
    if value is None:
        return None
    if str(value) == _JSON_OUT_AUTO:
        return Path(_DEFAULT_JSON_OUT_PATH)
    return Path(value)


def _allow_one_tick_creature_count_lag(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
) -> bool:
    if not field_diffs:
        return False
    if any(str(diff.field) != "creature_count" for diff in field_diffs):
        return False

    expected_tick = expected_by_tick.get(int(tick))
    actual_tick = actual_by_tick.get(int(tick))
    if expected_tick is None or actual_tick is None:
        return False

    expected_count = int(expected_tick.creature_count)
    actual_count = int(actual_tick.creature_count)
    if expected_count < 0 or actual_count < 0:
        return False
    if abs(expected_count - actual_count) != 1:
        return False

    prev_expected = expected_by_tick.get(int(tick) - 1)
    prev_actual = actual_by_tick.get(int(tick) - 1)
    if (
        prev_expected is not None
        and prev_actual is not None
        and int(prev_expected.creature_count) == actual_count
        and int(prev_actual.creature_count) == int(prev_expected.creature_count)
    ):
        return True

    next_expected = expected_by_tick.get(int(tick) + 1)
    next_actual = actual_by_tick.get(int(tick) + 1)
    if (
        next_expected is not None
        and next_actual is not None
        and int(next_expected.creature_count) == actual_count
        and int(next_actual.creature_count) == int(next_expected.creature_count)
    ):
        return True

    return False


def _allow_one_tick_kills_lag(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
) -> bool:
    if not field_diffs:
        return False
    if any(str(diff.field) != "kills" for diff in field_diffs):
        return False

    expected_tick = expected_by_tick.get(int(tick))
    actual_tick = actual_by_tick.get(int(tick))
    prev_expected = expected_by_tick.get(int(tick) - 1)
    prev_actual = actual_by_tick.get(int(tick) - 1)
    next_expected = expected_by_tick.get(int(tick) + 1)
    next_actual = actual_by_tick.get(int(tick) + 1)
    if (
        expected_tick is None
        or actual_tick is None
        or prev_expected is None
        or prev_actual is None
        or next_expected is None
        or next_actual is None
    ):
        return False

    expected_kills = int(expected_tick.kills)
    actual_kills = int(actual_tick.kills)
    if expected_kills < 0 or actual_kills < 0:
        return False
    if abs(int(expected_kills) - int(actual_kills)) != 1:
        return False

    if int(prev_expected.kills) != int(prev_actual.kills):
        return False
    if int(next_expected.kills) != int(next_actual.kills):
        return False

    return True


def _allow_capture_sample_creature_count(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    capture_sample_creature_counts: dict[int, int],
    capture_active_corpse_below_despawn_ticks: set[int] | None = None,
) -> bool:
    if not field_diffs:
        return False
    if any(str(diff.field) != "creature_count" for diff in field_diffs):
        return False
    if not capture_sample_creature_counts:
        return False

    sample_count = capture_sample_creature_counts.get(int(tick))
    if sample_count is None or int(sample_count) < 0:
        return False

    expected_tick = expected_by_tick.get(int(tick))
    actual_tick = actual_by_tick.get(int(tick))
    if expected_tick is None or actual_tick is None:
        return False

    expected_count = int(expected_tick.creature_count)
    actual_count = int(actual_tick.creature_count)
    if expected_count < 0 or actual_count < 0:
        return False

    # Capture `creature_active_count` can transiently disagree with sampled
    # active slots. When our sim count matches the sampled list exactly and this
    # is the only field mismatch, keep scanning for a stronger divergence.
    if actual_count == int(sample_count) and expected_count != int(sample_count):
        return True

    # Some captures expose a one-tick lead/lag between checkpoint
    # `creature_active_count` and sampled creature slots.
    #
    # Pattern:
    # - current tick sample matches expected checkpoint count,
    # - replay count already stepped to the next sampled count,
    # - next tick keeps the same expected/actual counts.
    next_sample = capture_sample_creature_counts.get(int(tick) + 1)
    next_expected_tick = expected_by_tick.get(int(tick) + 1)
    next_actual_tick = actual_by_tick.get(int(tick) + 1)
    if (
        next_sample is not None
        and int(next_sample) >= 0
        and abs(expected_count - actual_count) == 1
        and expected_count == int(sample_count)
        and actual_count == int(next_sample)
        and next_expected_tick is not None
        and next_actual_tick is not None
        and int(next_expected_tick.creature_count) == expected_count
        and int(next_actual_tick.creature_count) == actual_count
    ):
        return True

    # Some captures sample creature slots before render-time corpse culling.
    # In those ticks, sampled active count can exceed replay by exactly one when a
    # corpse is already below the native despawn threshold (< -10.0 hitbox_size).
    if (
        expected_count == int(sample_count)
        and actual_count == int(sample_count) - 1
        and capture_active_corpse_below_despawn_ticks is not None
        and int(tick) in capture_active_corpse_below_despawn_ticks
    ):
        return True

    return False


def _load_capture_sample_creature_counts(path: Path) -> dict[int, int]:
    return _capture_sample_creature_counts(load_capture(path))


def _capture_sample_creature_counts(capture: CaptureFile) -> dict[int, int]:
    out: dict[int, int] = {}
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        if tick_index < 0:
            continue
        out[int(tick_index)] = int(len(tick.samples.creatures))
    return out


def _load_capture_active_corpse_below_despawn_ticks(path: Path) -> set[int]:
    return _capture_active_corpse_below_despawn_ticks(load_capture(path))


def _capture_active_corpse_below_despawn_ticks(capture: CaptureFile) -> set[int]:
    out: set[int] = set()
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        if tick_index < 0:
            continue
        for creature in tick.samples.creatures:
            if int(creature.active) == 0:
                continue
            if float(creature.hp) > 0.0:
                continue
            if float(creature.hitbox_size) < -10.0:
                out.add(int(tick_index))
                break
    return out


def _weapon_name(weapon_id: int) -> str:
    entry = WEAPON_BY_ID.get(int(weapon_id))
    name = entry.name if entry is not None else None
    if name is None:
        return f"Weapon {int(weapon_id)}"
    return f"{name} ({int(weapon_id)})"


def _bonus_name(bonus_id: int) -> str:
    if int(bonus_id) < 0:
        return f"Bonus {int(bonus_id)}"
    return f"{bonus_label(int(bonus_id))} ({int(bonus_id)})"


def _append_run_summary_event(
    out: list[RunSummaryEvent],
    *,
    seen: set[tuple[int, str, str]],
    tick: int,
    kind: str,
    detail: str,
) -> None:
    key = (int(tick), str(kind), str(detail))
    if key in seen:
        return
    seen.add(key)
    out.append(
        RunSummaryEvent(
            tick_index=int(tick),
            kind=str(kind),
            detail=str(detail),
        ),
    )


def _build_run_summary_events_from_raw_capture(path: Path) -> list[RunSummaryEvent]:
    events: list[RunSummaryEvent] = []
    seen: set[tuple[int, str, str]] = set()
    prev_levels: dict[int, int] = {}
    prev_perk_counts: dict[int, Counter[int]] = {}

    capture = load_capture(path)
    for tick_row in capture.ticks:
        tick = int(tick_row.tick_index)
        if tick < 0:
            continue

        for head in tick_row.event_heads:
            if isinstance(head, CaptureEventHeadBonusApply):
                player_index = int(head.data.player_index or 0)
                bonus_id = int(head.data.bonus_id or -1)
                detail = f"p{player_index} picked {_bonus_name(int(bonus_id))}"
                if int(bonus_id) == 3:
                    weapon_id = int(head.data.amount_i32) if head.data.amount_i32 is not None else -1
                    if weapon_id >= 0:
                        detail += f" -> {_weapon_name(int(weapon_id))}"
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="bonus_pickup",
                    detail=detail,
                )
                continue

            if isinstance(head, CaptureEventHeadWeaponAssign):
                player_index = int(head.data.player_index or 0)
                weapon_before = int(head.data.weapon_before) if head.data.weapon_before is not None else -1
                if head.data.weapon_after is not None:
                    weapon_after = int(head.data.weapon_after)
                elif head.data.weapon_id is not None:
                    weapon_after = int(head.data.weapon_id)
                else:
                    weapon_after = -1
                detail = (
                    f"p{player_index} weapon {_weapon_name(int(weapon_before))} -> {_weapon_name(int(weapon_after))}"
                )
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="weapon_assign",
                    detail=detail,
                )
                continue

            if isinstance(head, CaptureEventHeadStateTransition):
                before_state = int(head.data.before.id) if head.data.before.id is not None else -1
                if head.data.after.id is not None:
                    after_state = int(head.data.after.id)
                else:
                    after_state = int(head.data.target_state)
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="state_transition",
                    detail=f"state {before_state} -> {after_state}",
                )

        for player_index, player in enumerate(tick_row.checkpoint.players):
            level = int(player.level)
            if level < 0:
                continue
            prev_level = prev_levels.get(int(player_index))
            if prev_level is not None and int(level) > int(prev_level):
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="level_up",
                    detail=f"p{int(player_index)} level {int(prev_level)} -> {int(level)} (xp={int(player.experience)})",
                )
            prev_levels[int(player_index)] = int(level)

        for player_index, pairs in enumerate(tick_row.checkpoint.perk.player_nonzero_counts):
            counts = Counter()
            for pair in pairs:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    continue
                perk_id = _int_or(pair[0], -1)
                perk_count = _int_or(pair[1], 0)
                if perk_id < 0 or perk_count <= 0:
                    continue
                counts[int(perk_id)] = int(perk_count)
            player_key = int(player_index)
            if player_key in prev_perk_counts:
                previous = prev_perk_counts[player_key]
            else:
                previous = Counter()
            for perk_id, perk_count in sorted(counts.items()):
                previous_count = int(previous.get(int(perk_id), 0))
                if int(perk_count) <= int(previous_count):
                    continue
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="perk_pick",
                    detail=(
                        f"p{int(player_index)} perk {perk_label(int(perk_id))} ({int(perk_id)}) x{int(perk_count)}"
                    ),
                )
            prev_perk_counts[player_key] = counts

    events.sort(key=lambda item: (int(item.tick_index), str(item.kind), str(item.detail)))
    return events


def _build_run_summary_events_from_checkpoints(expected: list[ReplayCheckpoint]) -> list[RunSummaryEvent]:
    events: list[RunSummaryEvent] = []
    seen: set[tuple[int, str, str]] = set()
    prev_weapons: dict[int, int] = {}
    prev_levels: dict[int, int] = {}
    prev_perk_counts: dict[int, Counter[int]] = {}

    for checkpoint in expected:
        tick = int(checkpoint.tick_index)

        for player_index, player in enumerate(checkpoint.players):
            weapon_id = int(player.weapon_id)
            prev_weapon_id = prev_weapons.get(int(player_index))
            if prev_weapon_id is not None and int(prev_weapon_id) != int(weapon_id):
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="weapon_assign",
                    detail=(
                        f"p{int(player_index)} weapon "
                        f"{_weapon_name(int(prev_weapon_id))} -> {_weapon_name(int(weapon_id))}"
                    ),
                )
            prev_weapons[int(player_index)] = int(weapon_id)

            level = int(player.level)
            prev_level = prev_levels.get(int(player_index))
            if prev_level is not None and int(level) > int(prev_level):
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="level_up",
                    detail=f"p{int(player_index)} level {int(prev_level)} -> {int(level)} (xp={int(player.experience)})",
                )
            prev_levels[int(player_index)] = int(level)

        for player_index, pairs in enumerate(checkpoint.perk.player_nonzero_counts):
            counts = Counter()
            for pair in pairs:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    continue
                perk_id = _int_or(pair[0], -1)
                perk_count = _int_or(pair[1], 0)
                if perk_id < 0 or perk_count <= 0:
                    continue
                counts[int(perk_id)] = int(perk_count)
            player_key = int(player_index)
            if player_key in prev_perk_counts:
                previous = prev_perk_counts[player_key]
            else:
                previous = Counter()
            for perk_id, perk_count in sorted(counts.items()):
                perk_key = int(perk_id)
                if perk_key in previous:
                    previous_count = int(previous[perk_key])
                else:
                    previous_count = 0
                if int(perk_count) <= int(previous_count):
                    continue
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="perk_pick",
                    detail=(
                        f"p{int(player_index)} perk {perk_label(int(perk_id))} ({int(perk_id)}) x{int(perk_count)}"
                    ),
                )
            prev_perk_counts[player_key] = counts

    events.sort(key=lambda item: (int(item.tick_index), str(item.kind), str(item.detail)))
    return events


def _build_run_summary_events(capture_path: Path, *, expected: list[ReplayCheckpoint]) -> list[RunSummaryEvent]:
    try:
        events = _build_run_summary_events_from_raw_capture(capture_path)
    except (OSError, ValueError):
        events = []
    if events:
        return events
    return _build_run_summary_events_from_checkpoints(expected)


def _build_short_run_summary_events(events: list[RunSummaryEvent], *, max_rows: int = 24) -> list[RunSummaryEvent]:
    """Return a concise subset of run-summary events for quick mental-model checks."""

    if not events:
        return []
    limit = max(1, int(max_rows))
    out = [event for event in events if str(event.kind) in RUN_SUMMARY_SHORT_KINDS]
    if not out:
        out = list(events)
    return out[:limit]


def _build_focus_run_summary_events(
    events: list[RunSummaryEvent],
    *,
    focus_tick: int,
    before_rows: int = 8,
    after_rows: int = 4,
) -> list[RunSummaryEvent]:
    """Return short-kind events immediately around `focus_tick` for orientation."""

    if not events:
        return []

    before_limit = max(0, int(before_rows))
    after_limit = max(0, int(after_rows))
    if before_limit <= 0 and after_limit <= 0:
        return []

    short_events = [event for event in events if str(event.kind) in RUN_SUMMARY_SHORT_KINDS]
    source = short_events if short_events else list(events)
    ordered = sorted(source, key=lambda item: (int(item.tick_index), str(item.kind), str(item.detail)))

    before = [event for event in ordered if int(event.tick_index) <= int(focus_tick)]
    after = [event for event in ordered if int(event.tick_index) > int(focus_tick)]

    out: list[RunSummaryEvent] = []
    if before_limit > 0:
        out.extend(before[-before_limit:])
    if after_limit > 0:
        out.extend(after[:after_limit])
    return out


def _load_raw_tick_debug(path: Path, tick_indices: set[int] | None = None) -> dict[int, CaptureTick]:
    capture = load_capture(path)
    out: dict[int, CaptureTick] = {}
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        if tick_indices is not None and tick_index not in tick_indices:
            continue
        out[int(tick_index)] = tick
    return out


def _run_actual_checkpoints(
    capture: CaptureFile,
    *,
    max_ticks: int | None,
    seed: int | None,
    inter_tick_rand_draws: int,
    aim_scheme_overrides_by_player: Mapping[int, int] | None = None,
) -> tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], object]:
    expected = convert_capture_to_checkpoints(capture).checkpoints
    if max_ticks is not None:
        tick_cap = max(0, int(max_ticks))
        expected = [ckpt for ckpt in expected if int(ckpt.tick_index) < int(tick_cap)]

    replay = convert_capture_to_replay(
        capture,
        seed=seed,
        aim_scheme_overrides_by_player=aim_scheme_overrides_by_player,
    )
    dt_frame_overrides = build_capture_dt_frame_overrides(
        capture,
        tick_rate=int(replay.header.tick_rate),
    )
    dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(capture)
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected}
    inter_tick_rand_draws_by_tick = build_capture_inter_tick_rand_draws_overrides(capture)
    actual: list[ReplayCheckpoint] = []

    mode = int(replay.header.game_mode_id)

    if mode == int(GameMode.SURVIVAL):
        run_result = run_survival_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=False,
            trace_rng=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
            inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        )
    elif mode == int(GameMode.RUSH):
        run_result = run_rush_replay(
            replay,
            max_ticks=max_ticks,
            trace_rng=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
            inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        )
    elif mode == int(GameMode.QUESTS):
        run_result = run_quest_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=False,
            trace_rng=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
            inter_tick_rand_draws=max(0, int(inter_tick_rand_draws)),
            inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        )
    else:
        raise ValueError(f"unsupported game mode for original capture verification: {mode}")

    return expected, actual, run_result


def _find_first_divergence(
    expected: list[ReplayCheckpoint],
    actual: list[ReplayCheckpoint],
    *,
    float_abs_tol: float,
    max_field_diffs: int,
    capture_sample_creature_counts: dict[int, int] | None = None,
    capture_active_corpse_below_despawn_ticks: set[int] | None = None,
    raw_debug_by_tick: dict[int, CaptureTick] | None = None,
) -> Divergence | None:
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    sample_counts = capture_sample_creature_counts or {}
    corpse_below_despawn_ticks = capture_active_corpse_below_despawn_ticks or set()
    raw_by_tick = raw_debug_by_tick or {}

    for exp in expected:
        tick = int(exp.tick_index)
        act = actual_by_tick.get(tick)
        if act is None:
            return Divergence(
                tick_index=int(tick),
                kind="missing_checkpoint",
                field_diffs=(),
                expected=exp,
                actual=None,
            )

        tick_key = int(tick)
        raw_tick = raw_by_tick.get(tick_key)
        capture_stream_rows = [] if raw_tick is None else _rng_stream_rows_for_tick(raw_tick)
        capture_head_len = len(capture_stream_rows)
        if capture_head_len > 0 or capture_stream_rows:
            stream_alignment = _compute_rng_stream_alignment(
                act=act,
                capture_stream_rows=capture_stream_rows,
                capture_head_len=int(capture_head_len),
            )
            if (
                _int_or(stream_alignment.get("first_mismatch_idx"), -1) >= 0
                or _int_or(stream_alignment.get("missing_tail"), 0) > 0
            ):
                return Divergence(
                    tick_index=int(tick),
                    kind="rng_stream_mismatch",
                    field_diffs=(),
                    expected=exp,
                    actual=act,
                )

        exp_for_diff = replace(exp, elapsed_ms=-1)
        field_diffs = checkpoint_field_diffs(
            exp_for_diff,
            act,
            include_hash_fields=False,
            include_rng_fields=False,
            normalize_unknown=True,
            unknown_events_wildcard=True,
            max_diffs=max_field_diffs,
            float_abs_tol=float(float_abs_tol),
        )
        if _allow_one_tick_creature_count_lag(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
        ):
            continue
        if _allow_one_tick_kills_lag(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
        ):
            continue
        if _allow_capture_sample_creature_count(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
            capture_sample_creature_counts=sample_counts,
            capture_active_corpse_below_despawn_ticks=corpse_below_despawn_ticks,
        ):
            continue
        if field_diffs:
            return Divergence(
                tick_index=int(tick),
                kind="state_mismatch",
                field_diffs=tuple(field_diffs),
                expected=exp,
                actual=act,
            )

    return None


def _primary_rng_after(ckpt: ReplayCheckpoint) -> int:
    marks = ckpt.rng_marks
    stage_rank: dict[str, int] = {
        "after_world_step": 0,
        "after_stage_spawns": 1,
        "after_wave_spawns": 2,
        "after_rush_spawns": 3,
        "after_events": 4,
        "after_post_events": 5,
    }
    candidate_keys = tuple(key for key in stage_rank if key in marks)
    if not candidate_keys:
        return -1

    before = _rng_mark_with_fallback(marks, "before_events")
    if before >= 0:
        best_after: int | None = None
        best_calls = -1
        best_rank = -1
        for key in candidate_keys:
            after = _int_or(marks.get(key), -1)
            if after < 0:
                continue
            calls = _infer_rand_calls_between_states(before, after)
            if calls is None:
                continue
            if key in stage_rank:
                rank = int(stage_rank[key])
            else:
                rank = -1
            if int(calls) > int(best_calls) or (int(calls) == int(best_calls) and rank > best_rank):
                best_after = int(after)
                best_calls = int(calls)
                best_rank = int(rank)
        if best_after is not None:
            return int(best_after)

    for key in (
        "after_post_events",
        "after_events",
        "after_rush_spawns",
        "after_wave_spawns",
        "after_stage_spawns",
        "after_world_step",
    ):
        if key in marks:
            return _int_or(marks.get(key))
    return -1


def _rng_mark_with_fallback(marks: dict[str, int], key: str) -> int:
    if key in marks:
        return _int_or(marks.get(key), -1)
    if key in {"before_events", "after_events"}:
        return _int_or(marks.get("before_world_step"), -1)
    return -1


def _infer_rand_calls_between_states(
    before_state: int,
    after_state: int,
    *,
    max_calls: int = _CRT_RAND_CALL_SEARCH_LIMIT,
) -> int | None:
    before = _int_or(before_state, -1)
    after = _int_or(after_state, -1)
    if before < 0 or after < 0:
        return None

    state = int(before) & _CRT_RAND_MASK
    target = int(after) & _CRT_RAND_MASK
    if state == target:
        return 0

    limit = max(0, int(max_calls))
    for call_idx in range(1, limit + 1):
        state = (state * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MASK
        if state == target:
            return int(call_idx)
    return None


def _actual_rand_calls_for_checkpoint(ckpt: ReplayCheckpoint) -> int | None:
    before = _rng_mark_with_fallback(ckpt.rng_marks, "before_events")
    after = _primary_rng_after(ckpt)
    return _infer_rand_calls_between_states(before, after)


def _actual_rng_stream_rows_for_checkpoint(
    ckpt: ReplayCheckpoint,
    *,
    max_rows: int | None = None,
) -> tuple[list[dict[str, int]], int | None]:
    actual_calls = _actual_rand_calls_for_checkpoint(ckpt)
    if actual_calls is None:
        return [], None

    total_calls = max(0, int(actual_calls))
    before_state = _rng_mark_with_fallback(ckpt.rng_marks, "before_events")
    if before_state < 0:
        return [], int(total_calls)

    limit = int(total_calls) if max_rows is None else max(0, min(int(total_calls), int(max_rows)))
    state = int(before_state) & _CRT_RAND_MASK
    out: list[dict[str, int]] = []
    for idx in range(limit):
        state_before_u32 = int(state) & _CRT_RAND_MASK
        state_after_u32 = (int(state_before_u32) * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MASK
        value_15 = int((state_after_u32 >> 16) & 0x7FFF)
        out.append(
            {
                "tick_call_index": int(idx) + 1,
                "value_15": int(value_15),
                "state_before_u32": int(state_before_u32),
                "state_after_u32": int(state_after_u32),
            },
        )
        state = int(state_after_u32)
    return out, int(total_calls)


def _compute_rng_stream_alignment(
    *,
    act: ReplayCheckpoint,
    capture_stream_rows: list[CaptureRngHeadEntry],
    capture_head_len: int,
) -> RngStreamAlignment:
    capture_rows = list(capture_stream_rows)
    cap_len = max(int(capture_head_len), len(capture_rows))
    actual_rows, actual_calls = _actual_rng_stream_rows_for_checkpoint(
        act,
        max_rows=len(capture_rows),
    )
    if actual_calls is None:
        return {
            "capture_head_len": int(cap_len),
            "actual_calls": None,
            "prefix_match": None,
            "compared": None,
            "first_mismatch_idx": None,
            "first_mismatch_reason": None,
            "first_mismatch_capture": None,
            "first_mismatch_actual": None,
            "first_mismatch_capture_state_before": None,
            "first_mismatch_capture_state_after": None,
            "first_mismatch_actual_state_before": None,
            "first_mismatch_actual_state_after": None,
            "first_mismatch_capture_caller_static": None,
            "first_mismatch_capture_branch_id": None,
            "first_mismatch_capture_seq": None,
            "missing_tail": None,
        }

    actual_calls_i = max(0, int(actual_calls))
    if not actual_rows and capture_rows:
        return {
            "capture_head_len": int(cap_len),
            "actual_calls": int(actual_calls_i),
            "prefix_match": None,
            "compared": None,
            "first_mismatch_idx": None,
            "first_mismatch_reason": None,
            "first_mismatch_capture": None,
            "first_mismatch_actual": None,
            "first_mismatch_capture_state_before": None,
            "first_mismatch_capture_state_after": None,
            "first_mismatch_actual_state_before": None,
            "first_mismatch_actual_state_after": None,
            "first_mismatch_capture_caller_static": None,
            "first_mismatch_capture_branch_id": None,
            "first_mismatch_capture_seq": None,
            "missing_tail": max(0, int(cap_len) - int(actual_calls_i)),
        }

    compared = min(len(capture_rows), len(actual_rows))
    prefix = 0
    first_mismatch_idx: int | None = None
    first_mismatch_reason: str | None = None
    first_mismatch_capture: int | None = None
    first_mismatch_actual: int | None = None
    first_mismatch_capture_state_before: int | None = None
    first_mismatch_capture_state_after: int | None = None
    first_mismatch_actual_state_before: int | None = None
    first_mismatch_actual_state_after: int | None = None
    first_mismatch_capture_caller_static: str | None = None
    first_mismatch_capture_branch_id: str | None = None
    first_mismatch_capture_seq: int | None = None

    for idx in range(compared):
        capture_row = capture_rows[idx]
        actual_row = actual_rows[idx]

        capture_value = _rng_value_15_from_entry(capture_row)
        actual_value = int(actual_row["value_15"])
        capture_before = (
            None if capture_row.state_before_u32 is None else int(capture_row.state_before_u32) & 0xFFFFFFFF
        )
        capture_after = None if capture_row.state_after_u32 is None else int(capture_row.state_after_u32) & 0xFFFFFFFF
        actual_before = int(actual_row["state_before_u32"])
        actual_after = int(actual_row["state_after_u32"])

        mismatch_reason: str | None = None
        if capture_value is None:
            mismatch_reason = "capture_value_missing"
        elif int(capture_value) != int(actual_value):
            mismatch_reason = "value"
        elif capture_before is not None and int(capture_before) != int(actual_before):
            mismatch_reason = "state_before"
        elif capture_after is not None and int(capture_after) != int(actual_after):
            mismatch_reason = "state_after"

        if mismatch_reason is None:
            prefix += 1
            continue

        first_mismatch_idx = int(idx)
        first_mismatch_reason = str(mismatch_reason)
        first_mismatch_capture = int(capture_value) if capture_value is not None else None
        first_mismatch_actual = int(actual_value)
        first_mismatch_capture_state_before = int(capture_before) if capture_before is not None else None
        first_mismatch_capture_state_after = int(capture_after) if capture_after is not None else None
        first_mismatch_actual_state_before = int(actual_before)
        first_mismatch_actual_state_after = int(actual_after)
        if capture_row.caller_static:
            first_mismatch_capture_caller_static = str(capture_row.caller_static)
        branch_id = _rng_branch_id(capture_row)
        if branch_id:
            first_mismatch_capture_branch_id = branch_id
        elif first_mismatch_capture_caller_static is not None:
            first_mismatch_capture_branch_id = first_mismatch_capture_caller_static
        if capture_row.seq is not None and int(capture_row.seq) >= 0:
            first_mismatch_capture_seq = int(capture_row.seq)
        break

    return {
        "capture_head_len": int(cap_len),
        "actual_calls": int(actual_calls_i),
        "prefix_match": int(prefix),
        "compared": int(compared),
        "first_mismatch_idx": first_mismatch_idx,
        "first_mismatch_reason": first_mismatch_reason,
        "first_mismatch_capture": first_mismatch_capture,
        "first_mismatch_actual": first_mismatch_actual,
        "first_mismatch_capture_state_before": first_mismatch_capture_state_before,
        "first_mismatch_capture_state_after": first_mismatch_capture_state_after,
        "first_mismatch_actual_state_before": first_mismatch_actual_state_before,
        "first_mismatch_actual_state_after": first_mismatch_actual_state_after,
        "first_mismatch_capture_caller_static": first_mismatch_capture_caller_static,
        "first_mismatch_capture_branch_id": first_mismatch_capture_branch_id,
        "first_mismatch_capture_seq": first_mismatch_capture_seq,
        "missing_tail": max(0, int(cap_len) - int(actual_calls_i)),
    }


def _actual_rand_stage_calls(ckpt: ReplayCheckpoint) -> dict[str, int]:
    marks = ckpt.rng_marks
    stage_pairs: list[tuple[str, str, str]] = [
        ("before_events", "after_events", "events"),
        ("after_events", "ws_after_creatures", "creatures"),
        ("ws_after_creatures", "ws_after_projectiles", "projectiles"),
        ("ws_after_projectiles", "ws_after_secondary_projectiles", "secondary_projectiles"),
        ("ws_after_secondary_projectiles", "ws_after_death_sfx", "death_sfx_preplan"),
        ("ws_after_death_sfx", "after_world_step", "world_step_tail"),
    ]

    if "after_rush_spawns" in marks:
        stage_pairs.append(("after_world_step", "after_rush_spawns", "rush_spawns"))
    else:
        stage_pairs.append(("after_world_step", "after_stage_spawns", "survival_stage_spawns"))
        stage_pairs.append(("after_stage_spawns", "after_wave_spawns", "survival_wave_spawns"))

    out: dict[str, int] = {}
    for start_key, end_key, stage_name in stage_pairs:
        calls = _infer_rand_calls_between_states(
            _rng_mark_with_fallback(marks, start_key),
            _rng_mark_with_fallback(marks, end_key),
        )
        if calls is None:
            continue
        if stage_name == "events" and start_key not in marks and end_key not in marks:
            continue
        out[str(stage_name)] = int(calls)
    return out


@functools.lru_cache(maxsize=2)
def _load_native_function_ranges(ghidra_c_path: str) -> tuple[NativeFunctionRange, ...]:
    path = Path(ghidra_c_path)
    if not path.exists():
        return ()
    pattern = re.compile(r"/\*\s*(.*?)\s*@\s*([0-9A-Fa-f]{8})\s*\*/")
    starts: list[tuple[int, str]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = pattern.match(line.strip())
        if match is None:
            continue
        name = str(match.group(1)).strip()
        addr = int(str(match.group(2)), 16)
        starts.append((int(addr), str(name)))
    if not starts:
        return ()
    starts.sort(key=lambda item: int(item[0]))
    ranges: list[NativeFunctionRange] = []
    for idx, (start, name) in enumerate(starts):
        end: int | None = None
        if idx + 1 < len(starts):
            end = int(starts[idx + 1][0]) - 1
        ranges.append(NativeFunctionRange(name=str(name), start=int(start), end=end))
    return tuple(ranges)


def _parse_hex_u32(value: object) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return None
    try:
        return int(text, 16) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


def _resolve_native_function_for_addr(caller_static: object, ranges: tuple[NativeFunctionRange, ...]) -> str | None:
    addr = _parse_hex_u32(caller_static)
    if addr is None or not ranges:
        return None
    starts = [item.start for item in ranges]
    idx = bisect.bisect_right(starts, int(addr)) - 1
    if idx < 0:
        return None
    item = ranges[idx]
    if item.end is not None and int(addr) > int(item.end):
        return None
    return str(item.name)


def _rng_changed(ckpt: ReplayCheckpoint) -> bool:
    before = _rng_mark_with_fallback(ckpt.rng_marks, "before_events")
    after = _primary_rng_after(ckpt)
    return bool(before >= 0 and after >= 0 and before != after)


def _first_drift_onsets(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    focus_tick: int,
    float_abs_tol: float,
) -> dict[str, FieldDriftOnset]:
    onsets: dict[str, FieldDriftOnset] = {}
    ticks = sorted(set(expected_by_tick.keys()) & set(actual_by_tick.keys()))
    limit = int(focus_tick)
    for tick in ticks:
        if tick > limit:
            break
        exp = expected_by_tick[tick]
        act = actual_by_tick[tick]
        exp_player = exp.players[0] if exp.players else None
        act_player = act.players[0] if act.players else None

        if exp_player is not None and act_player is not None:
            px_exp = float(exp_player.pos.x)
            px_act = float(act_player.pos.x)
            if "players[0].pos.x" not in onsets and abs(px_exp - px_act) > float_abs_tol:
                onsets["players[0].pos.x"] = FieldDriftOnset(
                    field="players[0].pos.x",
                    tick=int(tick),
                    expected=px_exp,
                    actual=px_act,
                    delta=float(px_act - px_exp),
                )

            py_exp = float(exp_player.pos.y)
            py_act = float(act_player.pos.y)
            if "players[0].pos.y" not in onsets and abs(py_exp - py_act) > float_abs_tol:
                onsets["players[0].pos.y"] = FieldDriftOnset(
                    field="players[0].pos.y",
                    tick=int(tick),
                    expected=py_exp,
                    actual=py_act,
                    delta=float(py_act - py_exp),
                )

            ammo_exp = float(exp_player.ammo)
            ammo_act = float(act_player.ammo)
            if "players[0].ammo" not in onsets and abs(ammo_exp - ammo_act) > float_abs_tol:
                onsets["players[0].ammo"] = FieldDriftOnset(
                    field="players[0].ammo",
                    tick=int(tick),
                    expected=ammo_exp,
                    actual=ammo_act,
                    delta=float(ammo_act - ammo_exp),
                )

            health_exp = float(exp_player.health)
            health_act = float(act_player.health)
            if "players[0].health" not in onsets and abs(health_exp - health_act) > float_abs_tol:
                onsets["players[0].health"] = FieldDriftOnset(
                    field="players[0].health",
                    tick=int(tick),
                    expected=health_exp,
                    actual=health_act,
                    delta=float(health_act - health_exp),
                )

            weapon_exp = _int_or(exp_player.weapon_id)
            weapon_act = _int_or(act_player.weapon_id)
            if "players[0].weapon_id" not in onsets and weapon_exp != weapon_act:
                onsets["players[0].weapon_id"] = FieldDriftOnset(
                    field="players[0].weapon_id",
                    tick=int(tick),
                    expected=int(weapon_exp),
                    actual=int(weapon_act),
                    delta=int(weapon_act - weapon_exp),
                )

            xp_exp = _int_or(exp_player.experience)
            xp_act = _int_or(act_player.experience)
            if "players[0].experience" not in onsets and xp_exp != xp_act:
                onsets["players[0].experience"] = FieldDriftOnset(
                    field="players[0].experience",
                    tick=int(tick),
                    expected=int(xp_exp),
                    actual=int(xp_act),
                    delta=int(xp_act - xp_exp),
                )

        score_exp = int(exp.score_xp)
        score_act = int(act.score_xp)
        if "score_xp" not in onsets and score_exp != score_act:
            onsets["score_xp"] = FieldDriftOnset(
                field="score_xp",
                tick=int(tick),
                expected=int(score_exp),
                actual=int(score_act),
                delta=int(score_act - score_exp),
            )

        creatures_exp = int(exp.creature_count)
        creatures_act = int(act.creature_count)
        if "creature_count" not in onsets and creatures_exp != creatures_act:
            onsets["creature_count"] = FieldDriftOnset(
                field="creature_count",
                tick=int(tick),
                expected=int(creatures_exp),
                actual=int(creatures_act),
                delta=int(creatures_act - creatures_exp),
            )

        if len(onsets) >= 8:
            # All tracked domains have onsets; no need to continue scanning.
            break
    return onsets


def _raw_debug_row_for_tick(
    rows_by_tick: Mapping[int, CaptureTick],
    tick: int,
) -> CaptureTick | None:
    tick_key = int(tick)
    return rows_by_tick.get(tick_key)


def _ticks_rng_zero_but_changed(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, CaptureTick],
    start_tick: int,
    end_tick: int,
) -> list[int]:
    ticks: list[int] = []
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        act = actual_by_tick.get(tick)
        if act is None:
            continue
        raw_tick = _raw_debug_row_for_tick(raw_debug_by_tick, tick)
        expected_calls = _capture_rng_rand_calls(raw_tick) if raw_tick is not None else -1
        if expected_calls < 0:
            exp = expected_by_tick.get(tick)
            if exp is not None:
                expected_calls = _int_or(exp.rng_marks.get("rand_calls"), -1)
        if expected_calls != 0:
            continue
        if _rng_changed(act):
            ticks.append(int(tick))
    return ticks


def _aggregate_rng_callers(
    *,
    raw_debug_by_tick: dict[int, CaptureTick],
    ticks: list[int] | set[int],
) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for tick in ticks:
        raw_tick = _raw_debug_row_for_tick(raw_debug_by_tick, int(tick))
        if raw_tick is None:
            continue
        callers = _capture_rng_callers(raw_tick)
        for caller in callers:
            key = str(caller.caller_static)
            if not key:
                continue
            calls = int(caller.calls)
            if calls <= 0:
                continue
            if key in counts:
                counts[key] = int(counts[key]) + int(calls)
            else:
                counts[key] = int(calls)
    return sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0])))


def _aggregate_neighbor_rng_callers_for_ticks(
    *,
    raw_debug_by_tick: dict[int, CaptureTick],
    ticks: list[int],
    radius: int = 2,
) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    radius = max(0, int(radius))
    for tick in ticks:
        picked: list[tuple[str, int]] = []
        for offset in range(0, radius + 1):
            for signed in (-offset, offset) if offset > 0 else (0,):
                probe = int(tick) + int(signed)
                raw_tick = _raw_debug_row_for_tick(raw_debug_by_tick, probe)
                if raw_tick is None:
                    continue
                callers = _capture_rng_callers(raw_tick)
                if not callers:
                    continue
                for caller in callers:
                    key = str(caller.caller_static)
                    if not key:
                        continue
                    calls = int(caller.calls)
                    if calls <= 0:
                        continue
                    picked.append((key, int(calls)))
                if picked:
                    break
                if picked:
                    break
        for key, calls in picked:
            if key in counts:
                counts[key] = int(counts[key]) + int(calls)
            else:
                counts[key] = int(calls)
    return sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0])))


def _top_native_functions_from_callers(
    *,
    caller_counts: list[tuple[str, int]],
    native_ranges: tuple[NativeFunctionRange, ...],
    limit: int,
) -> list[tuple[str, int]]:
    fn_counts: dict[str, int] = {}
    for caller_static, calls in caller_counts:
        fn = _resolve_native_function_for_addr(caller_static, native_ranges)
        if fn is None:
            continue
        if fn in fn_counts:
            fn_counts[fn] = int(fn_counts[fn]) + int(calls)
        else:
            fn_counts[fn] = int(calls)
    ranked = sorted(fn_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return ranked[: max(1, int(limit))]


def _find_first_rng_head_shortfall(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, CaptureTick],
    start_tick: int,
    end_tick: int,
) -> dict[str, object] | None:
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        exp = expected_by_tick.get(int(tick))
        act = actual_by_tick.get(int(tick))
        if exp is None or act is None:
            continue
        raw_tick = _raw_debug_row_for_tick(raw_debug_by_tick, int(tick))
        if raw_tick is None:
            continue
        capture_stream_rows = _rng_stream_rows_for_tick(raw_tick)
        expected_head_len = len(capture_stream_rows)
        if expected_head_len <= 0:
            continue
        align = _compute_rng_stream_alignment(
            act=act,
            capture_stream_rows=capture_stream_rows,
            capture_head_len=int(expected_head_len),
        )
        actual_rand_calls_i = _int_or(align.get("actual_calls"), -1)
        if actual_rand_calls_i < 0:
            continue
        first_mismatch_idx = align.get("first_mismatch_idx")
        missing_tail = _int_or(align.get("missing_tail"), 0)
        if first_mismatch_idx is None and int(missing_tail) <= 0:
            continue
        expected_rand_calls = _int_or(
            _capture_rng_rand_calls(raw_tick),
            _int_or(exp.rng_marks.get("rand_calls"), -1),
        )
        caller_counts = _aggregate_rng_callers(
            raw_debug_by_tick=raw_debug_by_tick,
            ticks=[int(tick)],
        )
        seq_first = _capture_rng_seq_first(raw_tick)
        seq_last = _capture_rng_seq_last(raw_tick)
        seed_epoch_enter = _capture_rng_seed_epoch_enter(raw_tick)
        seed_epoch_last = _capture_rng_seed_epoch_last(raw_tick)
        return {
            "tick": int(tick),
            "expected_head_len": int(expected_head_len),
            "actual_rand_calls": int(actual_rand_calls_i),
            "missing_draws": max(0, int(expected_head_len) - int(actual_rand_calls_i)),
            "stream_prefix_match": align.get("prefix_match"),
            "stream_compared": align.get("compared"),
            "stream_first_mismatch_idx": first_mismatch_idx,
            "stream_first_mismatch_reason": align.get("first_mismatch_reason"),
            "stream_first_mismatch_capture": align.get("first_mismatch_capture"),
            "stream_first_mismatch_actual": align.get("first_mismatch_actual"),
            "stream_first_mismatch_capture_state_before": align.get("first_mismatch_capture_state_before"),
            "stream_first_mismatch_capture_state_after": align.get("first_mismatch_capture_state_after"),
            "stream_first_mismatch_actual_state_before": align.get("first_mismatch_actual_state_before"),
            "stream_first_mismatch_actual_state_after": align.get("first_mismatch_actual_state_after"),
            "stream_first_mismatch_capture_caller_static": align.get("first_mismatch_capture_caller_static"),
            "stream_first_mismatch_capture_branch_id": align.get("first_mismatch_capture_branch_id"),
            "stream_first_mismatch_capture_seq": align.get("first_mismatch_capture_seq"),
            "stream_missing_tail": int(missing_tail),
            "expected_rand_calls": int(expected_rand_calls),
            "caller_counts": caller_counts,
            "seq_first": int(seq_first),
            "seq_last": int(seq_last),
            "seed_epoch_enter": int(seed_epoch_enter),
            "seed_epoch_last": int(seed_epoch_last),
        }
    return None


def _find_first_projectile_hit_shortfall(
    *,
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, CaptureTick],
    start_tick: int,
    end_tick: int,
) -> dict[str, object] | None:
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        raw_tick = _raw_debug_row_for_tick(raw_debug_by_tick, int(tick))
        if raw_tick is None:
            continue
        capture_hits_raw = int(raw_tick.event_counts.projectile_find_hit)
        if capture_hits_raw < 0:
            continue
        capture_hits = _effective_capture_projectile_hit_count(raw_tick)
        act = actual_by_tick.get(int(tick))
        if act is None:
            continue
        actual_hits = _int_or(act.events.hit_count, -1)
        if actual_hits < 0:
            continue
        if int(capture_hits) <= int(actual_hits):
            continue
        caller_counts = [
            {"key": str(item.key), "count": int(item.count)}
            for item in raw_tick.checkpoint.debug.spawn.top_projectile_find_hit_callers
        ]
        if not caller_counts:
            reduced: dict[str, int] = {}
            for head in raw_tick.event_heads:
                if not isinstance(head, CaptureEventHeadProjectileFindHit):
                    continue
                key = head.data.caller_static
                if not key:
                    continue
                key_str = str(key)
                if key_str in reduced:
                    reduced[key_str] = int(reduced[key_str]) + 1
                else:
                    reduced[key_str] = 1
            caller_counts = [
                {"key": key, "count": count}
                for key, count in sorted(reduced.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ]
        query_caller_counts = [
            {"key": str(item.key), "count": int(item.count)}
            for item in raw_tick.checkpoint.debug.spawn.top_projectile_find_query_callers
        ]
        if not query_caller_counts:
            reduced_query: dict[str, int] = {}
            for head in raw_tick.event_heads:
                if not isinstance(head, CaptureEventHeadProjectileFindQuery):
                    continue
                key = head.data.caller_static
                if not key:
                    continue
                key_str = str(key)
                if key_str in reduced_query:
                    reduced_query[key_str] = int(reduced_query[key_str]) + 1
                else:
                    reduced_query[key_str] = 1
            query_caller_counts = [
                {"key": key, "count": count}
                for key, count in sorted(reduced_query.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ]
        return {
            "tick": int(tick),
            "capture_hits_raw": int(capture_hits_raw),
            "capture_hits": int(capture_hits),
            "actual_hits": int(actual_hits),
            "missing_hits": int(capture_hits) - int(actual_hits),
            "capture_corpse_hits": sum(
                1
                for head in raw_tick.event_heads
                if isinstance(head, CaptureEventHeadProjectileFindHit) and bool(head.data.corpse_hit)
            ),
            "caller_counts": caller_counts,
            "query_counts": int(raw_tick.event_counts.projectile_find_query),
            "query_miss_count": int(raw_tick.checkpoint.debug.spawn.event_count_projectile_find_query_miss),
            "query_owner_collision_count": int(
                raw_tick.checkpoint.debug.spawn.event_count_projectile_find_query_owner_collision,
            ),
            "query_caller_counts": query_caller_counts,
        }
    return None


def _port_paths_for_native_functions(function_names: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for name in function_names:
        name_key = str(name)
        if name_key in NATIVE_FUNCTION_TO_PORT_PATHS:
            candidate_paths = NATIVE_FUNCTION_TO_PORT_PATHS[name_key]
        else:
            candidate_paths = ()
        for path in candidate_paths:
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return tuple(out)


def _merge_paths(*groups: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for path in group:
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return tuple(out)


def _extract_player_input_keys(raw: CaptureTick | None, player_index: int = 0) -> CaptureInputPlayerKeys | None:
    if raw is None:
        return None
    for item in raw.input_player_keys:
        if int(item.player_index) == int(player_index):
            return item
    return None


def _input_has_opposite_direction_conflict(player_keys: CaptureInputPlayerKeys | None) -> bool:
    if player_keys is None:
        return False
    left = player_keys.turn_left_pressed
    right = player_keys.turn_right_pressed
    forward = player_keys.move_forward_pressed
    backward = player_keys.move_backward_pressed
    horizontal_conflict = isinstance(left, bool) and isinstance(right, bool) and left and right
    vertical_conflict = isinstance(forward, bool) and isinstance(backward, bool) and forward and backward
    return bool(horizontal_conflict or vertical_conflict)


def _find_input_conflict_ticks(
    *,
    raw_debug_by_tick: dict[int, CaptureTick],
    start_tick: int,
    end_tick: int,
    player_index: int = 0,
) -> list[int]:
    ticks: list[int] = []
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        raw = _raw_debug_row_for_tick(raw_debug_by_tick, int(tick))
        keys = _extract_player_input_keys(raw, player_index=player_index)
        if keys and _input_has_opposite_direction_conflict(keys):
            ticks.append(int(tick))
    return ticks


def _build_investigation_leads(
    *,
    divergence: Divergence,
    focus_tick: int,
    lookback_ticks: int,
    float_abs_tol: float,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, CaptureTick],
    native_ranges: tuple[NativeFunctionRange, ...],
    capture_config: CaptureConfig | Mapping[str, object] | None = None,
) -> list[InvestigationLead]:
    leads: list[InvestigationLead] = []
    lookback_start = max(0, int(focus_tick) - max(1, int(lookback_ticks)))
    onsets = _first_drift_onsets(
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        focus_tick=int(focus_tick),
        float_abs_tol=float(float_abs_tol),
    )

    focus_exp = expected_by_tick.get(int(focus_tick))
    focus_act = actual_by_tick.get(int(focus_tick))
    focus_raw = _raw_debug_row_for_tick(raw_debug_by_tick, int(focus_tick))
    if capture_config is None:
        micro_cap = -1
    elif isinstance(capture_config, Mapping):
        config_map = cast("Mapping[str, object]", capture_config)
        micro_cap = _int_or(config_map.get("creature_micro_max_head_per_tick"), -1)
    else:
        micro_cap = int(capture_config.creature_micro_max_head_per_tick)
    samples_missing = focus_raw is None
    if samples_missing:
        leads.append(
            InvestigationLead(
                title="Capture lacks entity samples at the focus tick",
                evidence=(
                    (
                        "focus tick has no `samples` payload in the capture; geometry-level comparison "
                        "for creatures/projectiles is unavailable on this run"
                    ),
                    (
                        "use the latest capture script defaults (full-detail per tick) so "
                        "`samples.secondary_projectiles` and `samples.creatures` are present at divergence ticks"
                    ),
                ),
                native_functions=(),
                code_paths=(
                    "scripts/frida/gameplay_diff_capture.js",
                    "docs/frida/gameplay-diff-capture.md",
                ),
            ),
        )
    else:
        creature_micro_count = -1 if focus_raw is None else int(focus_raw.event_counts.creature_update_micro)
        if creature_micro_count <= 0:
            leads.append(
                InvestigationLead(
                    title="Capture lacks creature-update micro telemetry at the focus tick",
                    evidence=(
                        (
                            "focus tick has no `creature_update_micro` event heads; per-creature movement "
                            "turn/target internals are unavailable for root-cause analysis"
                        ),
                        (
                            "re-capture with the current gameplay_diff_capture defaults; "
                            "creature micro telemetry is expected to be on by default "
                            "(captures missing it are usually older script revisions or legacy override runs)"
                        ),
                    ),
                    native_functions=(
                        "creature_update_all",
                        "angle_approach",
                    ),
                    code_paths=(
                        "scripts/frida/gameplay_diff_capture.js",
                        "docs/frida/gameplay-diff-capture.md",
                    ),
                ),
            )
        elif micro_cap > 0 and creature_micro_count >= micro_cap:
            leads.append(
                InvestigationLead(
                    title="Capture creature-update micro telemetry likely head-capped at focus tick",
                    evidence=(
                        (
                            "focus tick creature_update_micro_count hit the configured head cap: "
                            f"count={int(creature_micro_count)} cap={int(micro_cap)}"
                        ),
                        (
                            "slot-level movement ancestry near the frontier can be truncated when the cap is hit, "
                            "which can hide the first causative branch split"
                        ),
                        (
                            "treat this as movement-telemetry saturation and compare divergence category/signatures "
                            "across captures rather than absolute tick alignment"
                        ),
                    ),
                    native_functions=(
                        "creature_update_all",
                        "angle_approach",
                    ),
                    code_paths=(
                        "scripts/frida/gameplay_diff_capture.js",
                        "docs/frida/gameplay-diff-capture.md",
                        "docs/frida/differential-playbook.md",
                    ),
                ),
            )

    rng_head_shortfall = _find_first_rng_head_shortfall(
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_by_tick,
        start_tick=int(lookback_start),
        end_tick=int(focus_tick),
    )
    if rng_head_shortfall is not None:
        shortfall_tick = _int_or(rng_head_shortfall.get("tick"), -1)
        expected_head_len = _int_or(rng_head_shortfall.get("expected_head_len"), -1)
        actual_rand_calls = _int_or(rng_head_shortfall.get("actual_rand_calls"), -1)
        missing_draws = _int_or(rng_head_shortfall.get("missing_draws"), -1)
        stream_prefix_match = _int_or(rng_head_shortfall.get("stream_prefix_match"), -1)
        stream_compared = _int_or(rng_head_shortfall.get("stream_compared"), -1)
        stream_first_mismatch_idx = _int_or(rng_head_shortfall.get("stream_first_mismatch_idx"), -1)
        stream_first_mismatch_reason = str(rng_head_shortfall.get("stream_first_mismatch_reason") or "").strip()
        stream_first_mismatch_capture = _int_or(rng_head_shortfall.get("stream_first_mismatch_capture"), -1)
        stream_first_mismatch_actual = _int_or(rng_head_shortfall.get("stream_first_mismatch_actual"), -1)
        stream_first_mismatch_capture_state_before = _int_or(
            rng_head_shortfall.get("stream_first_mismatch_capture_state_before"),
            -1,
        )
        stream_first_mismatch_capture_state_after = _int_or(
            rng_head_shortfall.get("stream_first_mismatch_capture_state_after"),
            -1,
        )
        stream_first_mismatch_actual_state_before = _int_or(
            rng_head_shortfall.get("stream_first_mismatch_actual_state_before"),
            -1,
        )
        stream_first_mismatch_actual_state_after = _int_or(
            rng_head_shortfall.get("stream_first_mismatch_actual_state_after"),
            -1,
        )
        stream_first_mismatch_capture_branch_id = str(
            rng_head_shortfall.get("stream_first_mismatch_capture_branch_id") or "",
        ).strip()
        stream_first_mismatch_capture_seq = _int_or(
            rng_head_shortfall.get("stream_first_mismatch_capture_seq"),
            -1,
        )
        stream_missing_tail = _int_or(rng_head_shortfall.get("stream_missing_tail"), -1)
        expected_rand_calls = _int_or(rng_head_shortfall.get("expected_rand_calls"), -1)
        seq_first = _int_or(rng_head_shortfall.get("seq_first"), -1)
        seq_last = _int_or(rng_head_shortfall.get("seq_last"), -1)
        seed_epoch_enter = _int_or(rng_head_shortfall.get("seed_epoch_enter"), -1)
        seed_epoch_last = _int_or(rng_head_shortfall.get("seed_epoch_last"), -1)
        caller_counts = (
            rng_head_shortfall.get("caller_counts") if isinstance(rng_head_shortfall.get("caller_counts"), list) else []
        )
        top_native = _top_native_functions_from_callers(
            caller_counts=caller_counts,  # ty:ignore[invalid-argument-type]
            native_ranges=native_ranges,
            limit=5,
        )
        native_names = tuple(name for name, _calls in top_native)
        native_text = ", ".join(f"{name} x{calls}" for name, calls in top_native)
        top_callers = ", ".join(f"{addr} x{calls}" for addr, calls in caller_counts[:6])  # ty:ignore[not-subscriptable]

        evidence = [
            f"first pre-focus tick with RNG stream drift: tick={int(shortfall_tick)}",
            (
                "this means rewrite followed a different RNG branch before the focus mismatch, "
                "so later gameplay RNG decisions can diverge even if sampled state still matches"
            ),
        ]
        if stream_first_mismatch_idx >= 0:
            evidence.append(
                "capture-vs-rewrite RNG stream diverges at "
                f"idx={int(stream_first_mismatch_idx)} (capture={int(stream_first_mismatch_capture)}, "
                f"rewrite={int(stream_first_mismatch_actual)}) with prefix_match="
                f"{int(stream_prefix_match)}/{int(stream_compared)}",
            )
            if stream_first_mismatch_reason:
                evidence.append(f"first mismatch reason: {stream_first_mismatch_reason}")
            if stream_first_mismatch_capture_state_before >= 0 or stream_first_mismatch_actual_state_before >= 0:
                evidence.append(
                    "first mismatch state_before: "
                    f"capture={int(stream_first_mismatch_capture_state_before)} "
                    f"rewrite={int(stream_first_mismatch_actual_state_before)}",
                )
            if stream_first_mismatch_capture_state_after >= 0 or stream_first_mismatch_actual_state_after >= 0:
                evidence.append(
                    "first mismatch state_after: "
                    f"capture={int(stream_first_mismatch_capture_state_after)} "
                    f"rewrite={int(stream_first_mismatch_actual_state_after)}",
                )
            if stream_first_mismatch_capture_branch_id:
                evidence.append(
                    "capture branch_id at first mismatch: "
                    f"{stream_first_mismatch_capture_branch_id}"
                    + (
                        f" (seq={int(stream_first_mismatch_capture_seq)})"
                        if stream_first_mismatch_capture_seq >= 0
                        else ""
                    ),
                )
        if stream_missing_tail > 0:
            evidence.append(
                f"capture RNG head exceeds rewrite stream at that tick: capture_head_len={int(expected_head_len)} "
                f"rewrite_calls={int(actual_rand_calls)} missing_tail={int(stream_missing_tail)}",
            )
        if missing_draws > 0 and stream_first_mismatch_idx < 0:
            evidence.append(
                f"first pre-focus RNG-head shortfall details: expected_head_len={int(expected_head_len)} "
                f"actual_rand_calls={int(actual_rand_calls)} missing={int(missing_draws)}",
            )
        if expected_rand_calls >= 0 and expected_head_len >= 0:
            evidence.append(
                f"capture rand_calls at that tick: {int(expected_rand_calls)} (head_len={int(expected_head_len)})",
            )
        if seq_first >= 0 or seq_last >= 0:
            evidence.append(
                f"capture RNG sequence range at shortfall tick: seq_first={int(seq_first)} seq_last={int(seq_last)}",
            )
        if seed_epoch_enter >= 0 or seed_epoch_last >= 0:
            evidence.append(
                f"capture RNG seed epoch at shortfall tick: enter={int(seed_epoch_enter)} leave={int(seed_epoch_last)}",
            )
        if top_callers:
            evidence.append(f"dominant native caller_static at shortfall tick: {top_callers}")
        if native_text:
            evidence.append(f"resolved native functions at shortfall tick: {native_text}")

        fallback_native = (
            "projectile_update",
            "effect_spawn_blood_splatter",
            "fx_queue_add_random",
        )
        effective_native = native_names if native_names else fallback_native
        lead_title = "Pre-focus RNG-head shortfall indicates missing RNG-consuming branch"
        if stream_first_mismatch_idx >= 0:
            lead_title = "Pre-focus RNG stream mismatch indicates branch divergence"
        leads.append(
            InvestigationLead(
                title=lead_title,
                evidence=tuple(evidence),
                native_functions=tuple(effective_native),
                code_paths=_merge_paths(
                    _port_paths_for_native_functions(effective_native),
                    (
                        "src/crimson/projectiles/pools.py",
                        "src/crimson/sim/presentation_step.py",
                        "src/crimson/effects.py",
                    ),
                ),
            ),
        )

    projectile_hit_shortfall = _find_first_projectile_hit_shortfall(
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_by_tick,
        start_tick=int(lookback_start),
        end_tick=int(focus_tick),
    )
    if projectile_hit_shortfall is not None:
        shortfall_tick = _int_or(projectile_hit_shortfall.get("tick"), -1)
        capture_hits = _int_or(projectile_hit_shortfall.get("capture_hits"), -1)
        capture_hits_raw = _int_or(projectile_hit_shortfall.get("capture_hits_raw"), capture_hits)
        actual_hits = _int_or(projectile_hit_shortfall.get("actual_hits"), -1)
        missing_hits = _int_or(projectile_hit_shortfall.get("missing_hits"), -1)
        corpse_hits = _int_or(projectile_hit_shortfall.get("capture_corpse_hits"), -1)
        query_counts = _int_or(projectile_hit_shortfall.get("query_counts"), -1)
        query_miss_count = _int_or(projectile_hit_shortfall.get("query_miss_count"), -1)
        query_owner_collision_count = _int_or(projectile_hit_shortfall.get("query_owner_collision_count"), -1)
        caller_counts_raw = (
            projectile_hit_shortfall.get("caller_counts")
            if isinstance(projectile_hit_shortfall.get("caller_counts"), list)
            else []
        )
        caller_counts: list[tuple[str, int]] = []
        for item in caller_counts_raw:  # ty:ignore[not-iterable]
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if key is None:
                key = item.get("caller_static")
            if key is None:
                continue
            caller_counts.append((str(key), _int_or(item.get("count"), _int_or(item.get("calls"), 1))))
        caller_counts = sorted(caller_counts, key=lambda entry: (-int(entry[1]), str(entry[0])))
        top_callers = ", ".join(f"{addr} x{calls}" for addr, calls in caller_counts[:6])
        query_caller_counts_raw = (
            projectile_hit_shortfall.get("query_caller_counts")
            if isinstance(projectile_hit_shortfall.get("query_caller_counts"), list)
            else []
        )
        query_caller_counts: list[tuple[str, int]] = []
        for item in query_caller_counts_raw:  # ty:ignore[not-iterable]
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if key is None:
                key = item.get("caller_static")
            if key is None:
                continue
            query_caller_counts.append((str(key), _int_or(item.get("count"), _int_or(item.get("calls"), 1))))
        query_caller_counts = sorted(query_caller_counts, key=lambda entry: (-int(entry[1]), str(entry[0])))
        top_query_callers = ", ".join(f"{addr} x{calls}" for addr, calls in query_caller_counts[:6])
        top_native = _top_native_functions_from_callers(
            caller_counts=caller_counts,
            native_ranges=native_ranges,
            limit=5,
        )
        native_names = tuple(name for name, _calls in top_native)
        native_text = ", ".join(f"{name} x{calls}" for name, calls in top_native)

        evidence = [
            (
                f"first tick where native effective projectile hit resolves exceed rewrite hits: tick={int(shortfall_tick)} "
                f"(capture_effective_hits={int(capture_hits)}, capture_raw_hits={int(capture_hits_raw)}, "
                f"actual_hits={int(actual_hits)}, missing={int(missing_hits)})"
            ),
            (
                "this points to a missing rewrite hit-resolution path after excluding owner-collision projectile_find "
                "queries from capture-side hit totals"
            ),
        ]
        if query_counts >= 0:
            evidence.append(f"capture projectile_find queries at that tick: {int(query_counts)}")
        if query_miss_count >= 0:
            evidence.append(f"capture projectile_find query misses at that tick: {int(query_miss_count)}")
        if query_owner_collision_count >= 0:
            evidence.append(
                f"capture projectile_find owner-collision queries at that tick: {int(query_owner_collision_count)}",
            )
        if corpse_hits >= 0:
            evidence.append(f"capture projectile hit resolves marked as corpse hits at that tick: {int(corpse_hits)}")
        if top_query_callers:
            evidence.append(f"dominant projectile_find_query caller_static at shortfall tick: {top_query_callers}")
        if top_callers:
            evidence.append(f"dominant projectile_find_hit caller_static at shortfall tick: {top_callers}")
        if native_text:
            evidence.append(f"resolved native functions at shortfall tick: {native_text}")

        fallback_native = ("projectile_update", "creature_find_in_radius", "fx_queue_add_random")
        effective_native = native_names if native_names else fallback_native
        leads.append(
            InvestigationLead(
                title="Native projectile hit resolves exceed rewrite hit events",
                evidence=tuple(evidence),
                native_functions=tuple(effective_native),
                code_paths=_merge_paths(
                    _port_paths_for_native_functions(effective_native),
                    (
                        "src/crimson/projectiles/pools.py",
                        "src/crimson/sim/world_state.py",
                        "scripts/frida/gameplay_diff_capture.js",
                    ),
                ),
            ),
        )

    if focus_exp is not None and focus_act is not None:
        expected_rand_calls = _int_or(
            (_capture_rng_rand_calls(focus_raw) if focus_raw is not None else -1),
            _int_or(focus_exp.rng_marks.get("rand_calls"), -1),
        )
        actual_rand_calls = _actual_rand_calls_for_checkpoint(focus_act)
        focus_stream_rows = [] if focus_raw is None else _rng_stream_rows_for_tick(focus_raw)
        focus_head_len = len(focus_stream_rows)
        focus_stream = _compute_rng_stream_alignment(
            act=focus_act,
            capture_stream_rows=focus_stream_rows,
            capture_head_len=int(focus_head_len),
        )
        focus_stream_mismatch = (
            _int_or(focus_stream.get("first_mismatch_idx"), -1) >= 0 or _int_or(focus_stream.get("missing_tail"), 0) > 0
        )
        if expected_rand_calls >= 0 and actual_rand_calls is not None:
            rand_delta = int(actual_rand_calls) - int(expected_rand_calls)
            if abs(int(rand_delta)) >= 8 or focus_stream_mismatch:
                stage_calls = _actual_rand_stage_calls(focus_act)
                top_stages = sorted(
                    [(name, calls) for name, calls in stage_calls.items() if int(calls) > 0],
                    key=lambda item: (-int(item[1]), str(item[0])),
                )
                evidence = [
                    (
                        f"focus tick rand_calls differs: expected={int(expected_rand_calls)} "
                        f"actual={int(actual_rand_calls)} delta={int(rand_delta):+d}"
                    ),
                ]
                first_mismatch_idx = _int_or(focus_stream.get("first_mismatch_idx"), -1)
                missing_tail = _int_or(focus_stream.get("missing_tail"), 0)
                if first_mismatch_idx >= 0:
                    evidence.append(
                        "focus tick RNG stream mismatch: "
                        f"idx={int(first_mismatch_idx)} capture={_int_or(focus_stream.get('first_mismatch_capture'))} "
                        f"rewrite={_int_or(focus_stream.get('first_mismatch_actual'))} "
                        f"prefix_match={_int_or(focus_stream.get('prefix_match'))}/{_int_or(focus_stream.get('compared'))}",
                    )
                    mismatch_reason = str(focus_stream.get("first_mismatch_reason") or "").strip()
                    if mismatch_reason:
                        evidence.append(f"focus mismatch reason: {mismatch_reason}")
                    branch_id = str(focus_stream.get("first_mismatch_capture_branch_id") or "").strip()
                    if branch_id:
                        evidence.append(f"capture branch_id at focus mismatch: {branch_id}")
                elif missing_tail > 0:
                    evidence.append(
                        "focus tick RNG stream shortfall: "
                        f"capture_head_len={_int_or(focus_stream.get('capture_head_len'))} "
                        f"rewrite_calls={_int_or(focus_stream.get('actual_calls'))} "
                        f"missing_tail={int(missing_tail)}",
                    )
                if top_stages:
                    evidence.append(
                        "rewrite stage-local rand call totals: "
                        + ", ".join(f"{name}={calls}" for name, calls in top_stages[:6]),
                    )
                capture_deaths = -1 if focus_raw is None else int(focus_raw.checkpoint.debug.spawn.event_count_death)
                if int(capture_deaths) == 0 and len(focus_act.deaths) > 0:
                    evidence.append(
                        "capture has 0 creature_death events at focus tick while rewrite produced "
                        f"{len(focus_act.deaths)} death ledger entries",
                    )
                capture_damage = -1 if focus_raw is None else int(focus_raw.event_counts.creature_damage)
                if int(capture_damage) == 0 and len(focus_act.deaths) > 0:
                    evidence.append(
                        "capture has 0 creature_apply_damage events at focus tick while rewrite resolved a kill branch",
                    )

                focus_callers = [] if focus_raw is None else _capture_rng_callers(focus_raw)
                if focus_callers:
                    top = sorted(
                        [
                            (str(item.caller_static), int(item.calls))
                            for item in focus_callers
                            if item.caller_static
                        ],
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )[:6]
                    top_text = ", ".join(f"{addr} x{calls}" for addr, calls in top)
                    if top_text:
                        evidence.append(f"native rng_callers at focus tick: {top_text}")

                stage_paths: list[str] = []
                seen_paths: set[str] = set()
                for stage_name, _calls in top_stages:
                    stage_name_key = str(stage_name)
                    if stage_name_key in RNG_STAGE_TO_PORT_PATHS:
                        candidate_paths = RNG_STAGE_TO_PORT_PATHS[stage_name_key]
                    else:
                        candidate_paths = ()
                    for path in candidate_paths:
                        if path in seen_paths:
                            continue
                        seen_paths.add(path)
                        stage_paths.append(path)
                if not stage_paths:
                    stage_paths = list(
                        _port_paths_for_native_functions(
                            ("projectile_update", "creature_apply_damage", "creature_update_all"),
                        ),
                    )

                leads.append(
                    InvestigationLead(
                        title="Focus tick has a rewrite-only RNG burst",
                        evidence=tuple(evidence),
                        native_functions=("projectile_update", "creature_apply_damage", "creature_update_all"),
                        code_paths=tuple(stage_paths),
                    ),
                )

    rng_zero_ticks = _ticks_rng_zero_but_changed(
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_by_tick,
        start_tick=int(lookback_start),
        end_tick=int(focus_tick),
    )
    caller_counts = _aggregate_rng_callers(
        raw_debug_by_tick=raw_debug_by_tick,
        ticks=rng_zero_ticks[:32],
    )
    top_native = _top_native_functions_from_callers(
        caller_counts=caller_counts,
        native_ranges=native_ranges,
        limit=5,
    )

    if rng_zero_ticks:
        sample_ticks = ", ".join(str(tick) for tick in rng_zero_ticks[:8])
        if not caller_counts:
            caller_counts = _aggregate_neighbor_rng_callers_for_ticks(
                raw_debug_by_tick=raw_debug_by_tick,
                ticks=rng_zero_ticks[:32],
                radius=2,
            )
            top_native = _top_native_functions_from_callers(
                caller_counts=caller_counts,
                native_ranges=native_ranges,
                limit=5,
            )
        top_callers = ", ".join(f"{addr} x{calls}" for addr, calls in caller_counts[:6])
        native_names = tuple(name for name, _calls in top_native)
        native_text = ", ".join(f"{name} x{calls}" for name, calls in top_native)
        evidence = [
            (
                f"native reports rand_calls=0 but rewrite RNG state changes at tick(s): {sample_ticks}"
                + (" ..." if len(rng_zero_ticks) > 8 else "")
            ),
            (
                "this usually means rewrite-only RNG consumption in presentation/audio or a "
                "non-native gameplay branch crossing the same tick boundary"
            ),
        ]
        if top_callers:
            evidence.append(f"dominant native caller_static addresses on those ticks: {top_callers}")
        if native_text:
            evidence.append(f"resolved native functions from caller_static: {native_text}")
        zero_rand_damage_ticks: list[int] = []
        for tick in rng_zero_ticks:
            tick_row = _raw_debug_row_for_tick(raw_debug_by_tick, int(tick))
            if tick_row is None:
                continue
            if int(tick_row.event_counts.creature_damage) > 0:
                zero_rand_damage_ticks.append(int(tick))
        if zero_rand_damage_ticks:
            damage_sample = ", ".join(str(tick) for tick in zero_rand_damage_ticks[:8])
            evidence.append(
                "native creature_apply_damage hooks are present on zero-rand ticks: "
                + damage_sample
                + (" ..." if len(zero_rand_damage_ticks) > 8 else ""),
            )
        fallback_native = (
            "creature_update_all",
            "projectile_update",
            "player_update",
            "fx_queue_add_random",
        )
        effective_native = native_names if native_names else fallback_native
        leads.append(
            InvestigationLead(
                title="Unexpected RNG consumption outside native rand window",
                evidence=tuple(evidence),
                native_functions=tuple(effective_native),
                code_paths=_merge_paths(
                    _port_paths_for_native_functions(effective_native),
                    (
                        "src/crimson/sim/step_pipeline.py",
                        "src/crimson/sim/presentation_step.py",
                    ),
                ),
            ),
        )

    pos_onsets = [onsets[key] for key in ("players[0].pos.x", "players[0].pos.y") if key in onsets]
    xp_onset = onsets.get("players[0].experience")
    if pos_onsets:
        first_pos = min(pos_onsets, key=lambda onset: int(onset.tick))
        evidence = [
            (
                f"first position drift appears at tick={int(first_pos.tick)} "
                f"({first_pos.field}: expected={first_pos.expected!r} actual={first_pos.actual!r})"
            ),
        ]
        if xp_onset is not None and int(xp_onset.tick) > int(first_pos.tick):
            evidence.append(
                f"XP divergence begins later at tick={int(xp_onset.tick)} "
                f"(delta={xp_onset.delta!r}), suggesting movement/targeting drift is upstream",
            )
        leads.append(
            InvestigationLead(
                title="Upstream movement drift before gameplay outcome mismatch",
                evidence=tuple(evidence),
                native_functions=("creature_update_all",),
                code_paths=_port_paths_for_native_functions(("creature_update_all",)),
            ),
        )

    input_conflict_ticks = _find_input_conflict_ticks(
        raw_debug_by_tick=raw_debug_by_tick,
        start_tick=int(lookback_start),
        end_tick=int(focus_tick),
        player_index=0,
    )
    if input_conflict_ticks:
        sample = ", ".join(str(tick) for tick in input_conflict_ticks[:10])
        evidence = [
            (
                "capture reports opposite movement directions active in player_update "
                f"for player0 on tick(s): {sample}" + (" ..." if len(input_conflict_ticks) > 10 else "")
            ),
            "this can make replay reconstruction ambiguous if key-state telemetry is missing",
        ]
        leads.append(
            InvestigationLead(
                title="Input capture contains opposite-direction key conflicts",
                evidence=tuple(evidence),
                native_functions=("player_update",),
                code_paths=_port_paths_for_native_functions(("player_update",)),
            ),
        )

    if xp_onset is not None:
        score_onset = onsets.get("score_xp")
        evidence = [
            (
                f"first XP mismatch at tick={int(xp_onset.tick)}: "
                f"expected={xp_onset.expected!r} actual={xp_onset.actual!r} delta={xp_onset.delta!r}"
            ),
        ]
        if score_onset is not None and int(score_onset.tick) == int(xp_onset.tick):
            evidence.append("score_xp divergence starts on the same tick, indicating a gameplay award timing mismatch")
        focus_raw = _raw_debug_row_for_tick(raw_debug_by_tick, int(xp_onset.tick))
        focus_damage_count = 0 if focus_raw is None else int(focus_raw.event_counts.creature_damage)
        if focus_damage_count > 0:
            evidence.append(f"native creature_apply_damage count at XP-onset tick: {focus_damage_count}")
            damage_head = (
                [head.data for head in focus_raw.event_heads if isinstance(head, CaptureEventHeadCreatureDamage)]
                if focus_raw is not None
                else []
            )
            if damage_head:
                preview = []
                for item in damage_head[:4]:
                    preview.append(
                        "idx="
                        + str(int(item.creature_index))
                        + "/type="
                        + str(-1 if item.damage_type is None else int(item.damage_type))
                        + "/k="
                        + str(1 if bool(item.killed) else 0),
                    )
                if preview:
                    evidence.append("native creature_apply_damage head: " + ", ".join(preview))
        else:
            evidence.append("native creature_apply_damage count at XP-onset tick: 0")
        focus_callers = [] if focus_raw is None else _capture_rng_callers(focus_raw)
        if focus_callers:
            top = sorted(
                [
                    (str(item.caller_static), int(item.calls))
                    for item in focus_callers
                    if item.caller_static
                ],
                key=lambda item: (-int(item[1]), str(item[0])),
            )[:6]
            top_text = ", ".join(f"{addr} x{calls}" for addr, calls in top)
            if top_text:
                evidence.append(f"native rng_callers at XP-onset tick: {top_text}")
        names = ("projectile_update", "creature_apply_damage", "creature_update_all")
        leads.append(
            InvestigationLead(
                title="XP/score award divergence is a kill-resolution timing mismatch",
                evidence=tuple(evidence),
                native_functions=names,
                code_paths=_port_paths_for_native_functions(names),
            ),
        )

    if divergence.field_diffs:
        diff_fields = tuple(str(diff.field) for diff in divergence.field_diffs)
        evidence = [f"first mismatching fields at focus tick={int(divergence.tick_index)}: {', '.join(diff_fields)}"]
        leads.append(
            InvestigationLead(
                title="Direct divergence fields to instrument next",
                evidence=tuple(evidence),
                native_functions=(),
                code_paths=(),
            ),
        )

    return leads


def _classify_divergence_category(
    *,
    divergence: Divergence,
    leads: list[InvestigationLead],
    focus_raw: CaptureTick | None,
    focus_actual_ckpt: ReplayCheckpoint | None,
) -> DivergenceCategory:
    lead_titles = {lead.title for lead in leads}

    capture_hits_raw = -1 if focus_raw is None else int(focus_raw.event_counts.projectile_find_hit)
    capture_hits = -1 if focus_raw is None else _effective_capture_projectile_hit_count(focus_raw)
    capture_owner_collision_count = (
        -1 if focus_raw is None else int(focus_raw.checkpoint.debug.spawn.event_count_projectile_find_query_owner_collision)
    )
    actual_hits = _int_or(focus_actual_ckpt.events.hit_count if focus_actual_ckpt is not None else None, -1)
    if "Native projectile hit resolves exceed rewrite hit events" in lead_titles or (
        capture_hits >= 0 and actual_hits >= 0 and capture_hits > actual_hits
    ):
        return DivergenceCategory(
            id="rng.projectile_hit_resolution_shortfall",
            evidence=(
                (
                    "capture effective projectile hit resolves exceed rewrite hit events at focus "
                    f"(capture_effective_hits={int(capture_hits)}, capture_raw_hits={int(capture_hits_raw)}, "
                    f"owner_collision_queries={int(capture_owner_collision_count)}, rewrite_hits={int(actual_hits)})"
                ),
                "category is stable across dynamic runs and maps to projectile-hit/rng-consumption parity work",
            ),
        )

    if divergence.kind == "rng_stream_mismatch":
        focus_stream = (
            _compute_rng_stream_alignment(
                act=focus_actual_ckpt,
                capture_stream_rows=([] if focus_raw is None else _rng_stream_rows_for_tick(focus_raw)),
                capture_head_len=(0 if focus_raw is None else len(_rng_stream_rows_for_tick(focus_raw))),
            )
            if focus_actual_ckpt is not None and focus_raw is not None
            else cast(RngStreamAlignment, {})
        )
        missing_tail = _int_or(focus_stream.get("missing_tail"), 0)
        first_mismatch_idx = _int_or(focus_stream.get("first_mismatch_idx"), -1)
        if missing_tail > 0:
            return DivergenceCategory(
                id="rng.tail_shortfall",
                evidence=(
                    f"rewrite consumed fewer RNG draws than capture at focus (missing_tail={int(missing_tail)})",
                    "category emphasizes missing RNG-consuming branch paths before/at the frontier",
                ),
            )
        if first_mismatch_idx >= 0:
            return DivergenceCategory(
                id="rng.value_stream_mismatch",
                evidence=(
                    f"capture/rewrite RNG streams disagree at shared draw index {int(first_mismatch_idx)}",
                    "category emphasizes branch-selection/value-stream mismatch instead of draw-count shortfall",
                ),
            )
        if "Pre-focus RNG stream mismatch indicates branch divergence" in lead_titles:
            return DivergenceCategory(
                id="rng.prefocus_branch_divergence",
                evidence=(
                    "pre-focus RNG stream mismatch lead indicates branch divergence before the reported focus tick",
                    "category should be tracked by caller/callsite signatures across captures",
                ),
            )
        if "Pre-focus RNG-head shortfall indicates missing RNG-consuming branch" in lead_titles:
            return DivergenceCategory(
                id="rng.prefocus_consumption_shortfall",
                evidence=(
                    "pre-focus RNG-head shortfall lead indicates a missing RNG-consuming path before the focus tick",
                    "category should be tracked by dominant caller signatures across captures",
                ),
            )
        return DivergenceCategory(
            id="rng.stream_mismatch",
            evidence=("RNG stream mismatch without a more specific signature bucket",),
        )

    field_names = {str(diff.field) for diff in divergence.field_diffs}
    if any(name.startswith("players[0].pos.") for name in field_names):
        return DivergenceCategory(
            id="state.player_motion_precision_drift",
            evidence=(
                "first state mismatch includes player position drift fields",
                "category points to movement/input precision ancestry rather than downstream combat effects",
            ),
        )
    if any(name in {"score_xp", "players[0].experience", "players[0].level"} for name in field_names):
        return DivergenceCategory(
            id="state.progression_timing_drift",
            evidence=(
                "first state mismatch includes XP/score/level progression fields",
                "category points to progression timing/order divergence",
            ),
        )

    return DivergenceCategory(
        id=f"state.{divergence.kind}",
        evidence=("no specific divergence signature was detected; use the base divergence kind bucket",),
    )


def _build_window_rows(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, CaptureTick],
    focus_tick: int,
    window: int,
) -> list[dict[str, object]]:
    start = max(0, int(focus_tick) - int(window))
    end = int(focus_tick) + int(window)
    rows: list[dict[str, object]] = []
    for tick in range(start, end + 1):
        exp = expected_by_tick.get(tick)
        act = actual_by_tick.get(tick)
        if exp is None or act is None:
            continue
        raw = _raw_debug_row_for_tick(raw_debug_by_tick, int(tick))
        exp_player = exp.players[0] if exp.players else None
        act_player = act.players[0] if act.players else None
        before = _int_or(act.rng_marks.get("before_world_step"))
        after = _primary_rng_after(act)
        expected_rand_calls = (
            _capture_rng_rand_calls(raw) if raw is not None else _int_or(exp.rng_marks.get("rand_calls"))
        )
        actual_rand_calls = _actual_rand_calls_for_checkpoint(act)
        rand_calls_delta: int | None = None
        if expected_rand_calls >= 0 and actual_rand_calls is not None:
            rand_calls_delta = int(actual_rand_calls) - int(expected_rand_calls)
        rng_stream_rows = [] if raw is None else _rng_stream_rows_for_tick(raw)
        rng_head_len = len(rng_stream_rows)
        stream_align = _compute_rng_stream_alignment(
            act=act,
            capture_stream_rows=rng_stream_rows,
            capture_head_len=int(rng_head_len),
        )

        rows.append(
            {
                "tick": int(tick),
                "expected_weapon": _int_or(exp_player.weapon_id if exp_player is not None else -1),
                "actual_weapon": _int_or(act_player.weapon_id if act_player is not None else -1),
                "expected_ammo": _float_or(exp_player.ammo if exp_player is not None else 0.0),
                "actual_ammo": _float_or(act_player.ammo if act_player is not None else 0.0),
                "expected_xp": _int_or(exp_player.experience if exp_player is not None else -1),
                "actual_xp": _int_or(act_player.experience if act_player is not None else -1),
                "expected_score": int(exp.score_xp),
                "actual_score": int(act.score_xp),
                "expected_creatures": int(exp.creature_count),
                "actual_creatures": int(act.creature_count),
                "expected_rand_calls": int(expected_rand_calls),
                "actual_rand_calls": actual_rand_calls,
                "rand_calls_delta": rand_calls_delta,
                "rng_stream_prefix_match": stream_align.get("prefix_match"),
                "rng_stream_compared": stream_align.get("compared"),
                "rng_stream_first_mismatch_idx": stream_align.get("first_mismatch_idx"),
                "rng_stream_first_mismatch_reason": stream_align.get("first_mismatch_reason"),
                "rng_stream_first_mismatch_capture": stream_align.get("first_mismatch_capture"),
                "rng_stream_first_mismatch_actual": stream_align.get("first_mismatch_actual"),
                "rng_stream_first_mismatch_capture_branch_id": stream_align.get("first_mismatch_capture_branch_id"),
                "rng_stream_first_mismatch_capture_seq": stream_align.get("first_mismatch_capture_seq"),
                "rng_stream_missing_tail": stream_align.get("missing_tail"),
                "capture_rng_seq_first": (-1 if raw is None else _capture_rng_seq_first(raw)),
                "capture_rng_seq_last": (-1 if raw is None else _capture_rng_seq_last(raw)),
                "capture_rng_seed_epoch_enter": (-1 if raw is None else _capture_rng_seed_epoch_enter(raw)),
                "capture_rng_seed_epoch_last": (-1 if raw is None else _capture_rng_seed_epoch_last(raw)),
                "capture_rng_outside_before_calls": (-1 if raw is None else _capture_rng_outside_before_calls(raw)),
                "capture_rng_mirror_mismatch_total": (-1 if raw is None else _capture_rng_mirror_mismatch_total(raw)),
                "actual_ps_draws": _int_or(act.rng_marks.get("ps_draws_total")),
                "actual_rng_changed": bool(before >= 0 and after >= 0 and before != after),
                "expected_pickups": int(exp.events.pickup_count),
                "actual_pickups": int(act.events.pickup_count),
                "expected_sfx": int(exp.events.sfx_count),
                "actual_sfx": int(act.events.sfx_count),
                "capture_bonus_spawn_events": (
                    -1 if raw is None else int(raw.checkpoint.debug.spawn.event_count_bonus_spawn)
                ),
                "capture_death_events": (-1 if raw is None else int(raw.checkpoint.debug.spawn.event_count_death)),
                "capture_projectile_find_hits": (-1 if raw is None else int(raw.event_counts.projectile_find_hit)),
                "actual_deaths": int(len(act.deaths)),
                "actual_hits": int(act.events.hit_count),
            },
        )
    return rows


def _format_rng_stream_cell(row: dict[str, object], *, width: int = 14) -> str:
    prefix = _int_or(row.get("rng_stream_prefix_match"), -1)
    compared = _int_or(row.get("rng_stream_compared"), -1)
    mismatch_idx = _int_or(row.get("rng_stream_first_mismatch_idx"), -1)
    mismatch_reason = str(row.get("rng_stream_first_mismatch_reason") or "").strip()
    missing_tail = _int_or(row.get("rng_stream_missing_tail"), -1)
    if prefix < 0 or compared < 0:
        text = "na"
    elif mismatch_idx >= 0:
        reason_short = mismatch_reason[:1] if mismatch_reason else "x"
        text = f"{prefix}/{compared}/m{mismatch_idx}{reason_short}"
    elif missing_tail > 0:
        text = f"{prefix}/{compared}/t+{missing_tail}"
    else:
        text = f"{prefix}/{compared}/ok"
    return f"{text:>{width}}"


def _print_window(rows: list[dict[str, object]]) -> None:
    print()
    print(
        "tick  w(e/a)   ammo(e/a)  xp(e/a)   score(e/a)  creatures(e/a)"
        "  rand_calls(e/a/d)  rng_stream(p/c/status)  ps_draws(a)  rng_changed(a)  bonus_spawn(e)  deaths(e/a)  p_hits(e/a)  pickups(e/a)  sfx(e/a)",
    )
    for row in rows:
        expected_rand_calls = _int_or(row.get("expected_rand_calls"), -1)
        expected_rand_text = _fmt_opt_int(expected_rand_calls if expected_rand_calls >= 0 else None, width=6)
        actual_rand_text = _fmt_opt_int(row.get("actual_rand_calls"), width=6)
        rand_delta_text = _fmt_opt_int(row.get("rand_calls_delta"), width=6)
        rng_stream_text = _format_rng_stream_cell(row, width=16)
        print(
            f"{int(row['tick']):4d}  "  # ty:ignore[invalid-argument-type]
            f"{int(row['expected_weapon']):2d}/{int(row['actual_weapon']):2d}    "  # ty:ignore[invalid-argument-type]
            f"{float(row['expected_ammo']):6.2f}/{float(row['actual_ammo']):6.2f}  "  # ty:ignore[invalid-argument-type]
            f"{int(row['expected_xp']):5d}/{int(row['actual_xp']):5d}  "  # ty:ignore[invalid-argument-type]
            f"{int(row['expected_score']):6d}/{int(row['actual_score']):6d}  "  # ty:ignore[invalid-argument-type]
            f"{int(row['expected_creatures']):4d}/{int(row['actual_creatures']):4d}    "  # ty:ignore[invalid-argument-type]
            f"{expected_rand_text}/{actual_rand_text}/{rand_delta_text}     "
            f"{rng_stream_text}      "
            f"{int(row['actual_ps_draws']):6d}        "  # ty:ignore[invalid-argument-type]
            f"{'Y' if bool(row['actual_rng_changed']) else 'N':>1}           "
            f"{int(row['capture_bonus_spawn_events']):4d}       "  # ty:ignore[invalid-argument-type]
            f"{int(row['capture_death_events']):3d}/{int(row['actual_deaths']):3d}      "  # ty:ignore[invalid-argument-type]
            f"{int(row['capture_projectile_find_hits']):3d}/{int(row['actual_hits']):3d}      "  # ty:ignore[invalid-argument-type]
            f"{int(row['expected_pickups']):3d}/{int(row['actual_pickups']):3d}      "  # ty:ignore[invalid-argument-type]
            f"{int(row['expected_sfx']):3d}/{int(row['actual_sfx']):3d}",  # ty:ignore[invalid-argument-type]
        )


def _print_investigation_leads(leads: list[InvestigationLead]) -> None:
    if not leads:
        return
    print()
    print("investigation_leads:")
    for idx, lead in enumerate(leads, start=1):
        print(f"  {idx}. {lead.title}")
        for evidence in lead.evidence:
            print(f"     - {evidence}")
        if lead.native_functions:
            print(f"     - native_functions: {', '.join(lead.native_functions)}")
        if lead.code_paths:
            print(f"     - suggested_paths: {', '.join(lead.code_paths)}")


def _print_run_summary(events: list[RunSummaryEvent], *, max_rows: int = 120, title: str = "run_summary") -> None:
    if not events:
        print()
        print(f"{title}: (no significant events found)")
        return

    print()
    print(f"{title}:")
    limit = max(1, int(max_rows))
    for event in events[:limit]:
        print(f"  - tick={int(event.tick_index):5d} [{event.kind}] {event.detail}")
    if len(events) > limit:
        print(f"  ... truncated {len(events) - limit} additional events")


def build_parser(*, prog: str = "crimson") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=str(prog),
        description="Report the next original-capture divergence with context window + RNG diagnostics.",
    )
    parser.add_argument(
        "capture",
        type=Path,
        help="capture file (.json/.json.gz/.msgpack.zst)",
    )
    parser.add_argument("--window", type=int, default=20, help="ticks before/after focus tick to display")
    parser.add_argument("--max-ticks", type=int, default=None, help="optional replay tick cap")
    parser.add_argument("--seed", type=int, default=None, help="optional fixed replay seed override")
    parser.add_argument(
        "--aim-scheme-player",
        action="append",
        default=[],
        metavar="PLAYER=SCHEME",
        help=(
            "override replay reconstruction aim scheme for player index "
            "(repeatable; use for captures missing config_aim_scheme telemetry)"
        ),
    )
    parser.add_argument("--float-abs-tol", type=float, default=1e-3, help="absolute float tolerance")
    parser.add_argument("--max-field-diffs", type=int, default=16, help="max field diffs to show")
    parser.add_argument(
        "--inter-tick-rand-draws",
        type=int,
        default=1,
        help="extra rand draws between ticks (native console loop parity)",
    )
    parser.add_argument(
        "--focus-tick",
        type=int,
        default=None,
        help="override focus tick (default: first mismatch tick)",
    )
    parser.add_argument(
        "--lead-lookback",
        type=int,
        default=512,
        help="ticks to scan backward from focus when generating investigation leads",
    )
    parser.add_argument(
        "--ghidra-c",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_decompiled.c"),
        help="path to Ghidra decompiled C used for caller_static -> native function mapping",
    )
    parser.add_argument(
        "--run-summary",
        action="store_true",
        help="print a compact timeline of native run events (bonus/weapon/perk/state/level)",
    )
    parser.add_argument(
        "--run-summary-short",
        action="store_true",
        help="print a shorter native run timeline (bonus/weapon/perk/level/state highlights)",
    )
    parser.add_argument(
        "--run-summary-max-rows",
        type=int,
        default=120,
        help="max rows to print for --run-summary",
    )
    parser.add_argument(
        "--run-summary-short-max-rows",
        type=int,
        default=24,
        help="max rows to print for --run-summary-short",
    )
    parser.add_argument(
        "--run-summary-focus-context",
        action="store_true",
        help="print major timeline events immediately around the focus tick",
    )
    parser.add_argument(
        "--run-summary-focus-before",
        type=int,
        default=8,
        help="events at/before focus tick to print for --run-summary-focus-context",
    )
    parser.add_argument(
        "--run-summary-focus-after",
        type=int,
        default=4,
        help="events after focus tick to print for --run-summary-focus-context",
    )
    parser.add_argument(
        "--json-out",
        nargs="?",
        default=None,
        const=_JSON_OUT_AUTO,
        help=(
            "optional machine-readable report output path "
            "(default when flag is present: artifacts/frida/reports/divergence_report_latest.json)"
        ),
    )
    return parser


def main(argv: list[str] | None = None, *, session: Any | None = None) -> int:
    args = build_parser().parse_args(argv)
    capture_path = Path(args.capture)
    json_out_path = _resolve_json_out_path(args.json_out)
    try:
        aim_scheme_overrides = parse_player_int_overrides(
            args.aim_scheme_player,
            option_name="--aim-scheme-player",
        )
    except ValueError as exc:
        print(exc)
        return 2

    replay_key: object | None = None
    if session is not None:
        from .diagnostics_cache import replay_key_from_args

        replay_key = replay_key_from_args(args, aim_scheme_overrides=aim_scheme_overrides)
        capture = session.get_capture()
        sample_rate = int(session.get_sample_rate())
        expected, actual, run_result, replay = session.get_replay_outcome(replay_key)
        capture_sample_creature_counts = session.get_sample_creature_counts()
        raw_debug_all_by_tick = session.get_raw_debug_by_tick()
    else:
        capture = load_capture(capture_path)
        sample_rate = _capture_sample_rate(capture)
        expected, actual, run_result = _run_actual_checkpoints(
            capture,
            max_ticks=args.max_ticks,
            seed=args.seed,
            inter_tick_rand_draws=args.inter_tick_rand_draws,
            aim_scheme_overrides_by_player=aim_scheme_overrides,
        )
        capture_sample_creature_counts = _capture_sample_creature_counts(capture)
        raw_debug_all_by_tick = _load_raw_tick_debug(capture_path)
        replay = convert_capture_to_replay(
            capture,
            seed=args.seed,
            aim_scheme_overrides_by_player=aim_scheme_overrides,
        )
    capture_active_corpse_below_despawn_ticks = _capture_active_corpse_below_despawn_ticks(capture)
    divergence = _find_first_divergence(
        expected,
        actual,
        float_abs_tol=float(args.float_abs_tol),
        max_field_diffs=max(1, int(args.max_field_diffs)),
        capture_sample_creature_counts=capture_sample_creature_counts,
        capture_active_corpse_below_despawn_ticks=capture_active_corpse_below_despawn_ticks,
        raw_debug_by_tick=raw_debug_all_by_tick,
    )

    print(f"capture={capture_path}")
    print(
        f"ticks(expected/actual)={len(expected)}/{len(actual)}"
        f" sample_rate={int(sample_rate)} run_ticks={int(run_result.ticks)}"  # ty:ignore[unresolved-attribute]
        f" run_score_xp={int(run_result.score_xp)} run_kills={int(run_result.creature_kill_count)}",  # ty:ignore[unresolved-attribute]
    )

    print(
        f"mode={int(replay.header.game_mode_id)} tick_rate={int(replay.header.tick_rate)}"
        f" player_count={int(replay.header.player_count)} seed={int(replay.header.seed)}",
    )
    print(
        "status="
        f"(quest_unlock_index={int(replay.header.status.quest_unlock_index)}, "
        f"quest_unlock_index_full={int(replay.header.status.quest_unlock_index_full)}, "
        f"weapon_usage_counts_len={len(replay.header.status.weapon_usage_counts)})",
    )

    run_summary_events: list[RunSummaryEvent] = []
    run_summary_short_events: list[RunSummaryEvent] = []
    run_summary_focus_events: list[RunSummaryEvent] = []
    focus_tick_for_summary = (
        int(divergence.tick_index) if divergence is not None else (int(expected[-1].tick_index) if expected else 0)
    )
    if bool(args.run_summary) or bool(args.run_summary_short) or bool(args.run_summary_focus_context):
        if session is not None:
            run_summary_events = [
                RunSummaryEvent(
                    tick_index=int(item.tick_index),
                    kind=str(item.kind),
                    detail=str(item.detail),
                )
                for item in session.get_run_summary_events()
            ]
        else:
            run_summary_events = _build_run_summary_events(capture_path, expected=expected)
        if bool(args.run_summary_short):
            run_summary_short_events = _build_short_run_summary_events(
                run_summary_events,
                max_rows=max(1, int(args.run_summary_short_max_rows)),
            )
            _print_run_summary(
                run_summary_short_events,
                max_rows=max(1, int(args.run_summary_short_max_rows)),
                title="run_summary_short",
            )
        if bool(args.run_summary):
            _print_run_summary(
                run_summary_events,
                max_rows=max(1, int(args.run_summary_max_rows)),
                title="run_summary",
            )
        if bool(args.run_summary_focus_context):
            run_summary_focus_events = _build_focus_run_summary_events(
                run_summary_events,
                focus_tick=int(focus_tick_for_summary),
                before_rows=max(0, int(args.run_summary_focus_before)),
                after_rows=max(0, int(args.run_summary_focus_after)),
            )
            _print_run_summary(
                run_summary_focus_events,
                max_rows=max(
                    1, int(max(0, int(args.run_summary_focus_before)) + max(0, int(args.run_summary_focus_after))),
                ),
                title=f"run_summary_focus_context (focus_tick={int(focus_tick_for_summary)})",
            )

    if divergence is None:
        print("result=ok (no divergence found with current settings)")
        return 0

    focus_tick = int(args.focus_tick) if args.focus_tick is not None else int(divergence.tick_index)
    print()
    print(f"result=diverged kind={divergence.kind} tick={int(divergence.tick_index)} focus_tick={focus_tick}")
    if divergence.field_diffs:
        print("field_diffs:")
        for diff in divergence.field_diffs:
            print(f"  - {diff.field}: expected={diff.expected!r} actual={diff.actual!r}")

    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    window_ticks = set(range(max(0, focus_tick - int(args.window)), focus_tick + int(args.window) + 1))
    lead_ticks = set(range(max(0, focus_tick - int(args.lead_lookback)), focus_tick + 1))
    focused_debug_ticks = window_ticks | lead_ticks | {focus_tick}
    if session is not None:
        raw_debug_by_tick = session.get_raw_debug_by_tick(tick_indices=focused_debug_ticks)
    else:
        raw_debug_by_tick = {
            int(tick): row for tick, row in raw_debug_all_by_tick.items() if int(tick) in focused_debug_ticks
        }
    rows = _build_window_rows(
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_by_tick,
        focus_tick=focus_tick,
        window=int(args.window),
    )
    _print_window(rows)

    native_ranges = _load_native_function_ranges(str(args.ghidra_c))
    leads = _build_investigation_leads(
        divergence=divergence,
        focus_tick=int(focus_tick),
        lookback_ticks=int(args.lead_lookback),
        float_abs_tol=float(args.float_abs_tol),
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_by_tick,
        native_ranges=native_ranges,
        capture_config=capture.config,
    )
    _print_investigation_leads(leads)

    focus_raw = _raw_debug_row_for_tick(raw_debug_by_tick, focus_tick)
    focus_actual_ckpt = actual_by_tick.get(int(focus_tick))
    divergence_category = _classify_divergence_category(
        divergence=divergence,
        leads=leads,
        focus_raw=focus_raw,
        focus_actual_ckpt=focus_actual_ckpt,
    )
    print()
    print(f"divergence_category={divergence_category.id}")
    if divergence_category.evidence:
        print("category_evidence:")
        for line in divergence_category.evidence:
            print(f"  - {line}")
    if focus_raw or focus_actual_ckpt is not None:
        print()
        print("focus_capture_debug:")
    if focus_raw:
        print(
            "  "
            f"spawn_bonus_events={int(focus_raw.checkpoint.debug.spawn.event_count_bonus_spawn)} "
            f"spawn_death_events={int(focus_raw.checkpoint.debug.spawn.event_count_death)} "
            f"creature_damage_events={int(focus_raw.event_counts.creature_damage)} "
            f"rand_calls={int(_capture_rng_rand_calls(focus_raw))} "
            f"rand_last={focus_raw.rng.last_value!r}",
        )
        rng_seq_first = _capture_rng_seq_first(focus_raw)
        rng_seq_last = _capture_rng_seq_last(focus_raw)
        rng_seed_epoch_enter = _capture_rng_seed_epoch_enter(focus_raw)
        rng_seed_epoch_last = _capture_rng_seed_epoch_last(focus_raw)
        rng_outside_before_calls = _capture_rng_outside_before_calls(focus_raw)
        rng_mirror_mismatch_total = _capture_rng_mirror_mismatch_total(focus_raw)
        if (
            rng_seq_first >= 0
            or rng_seq_last >= 0
            or rng_seed_epoch_enter >= 0
            or rng_seed_epoch_last >= 0
            or rng_outside_before_calls >= 0
            or rng_mirror_mismatch_total >= 0
        ):
            print(
                "  "
                f"capture_rng_seq_range={int(rng_seq_first)}..{int(rng_seq_last)} "
                f"capture_rng_seed_epoch={int(rng_seed_epoch_enter)}..{int(rng_seed_epoch_last)} "
                f"capture_rng_outside_before_calls={int(rng_outside_before_calls)} "
                f"capture_rng_mirror_mismatch_total={int(rng_mirror_mismatch_total)}",
            )
        callers = _capture_rng_callers(focus_raw)
        if callers:
            print(f"  capture_rand_callers_top={callers[:6]!r}")
        top_bonus = list(focus_raw.checkpoint.debug.spawn.top_bonus_spawn_callers)
        if top_bonus:
            print(f"  capture_bonus_spawn_callers_top={top_bonus[:6]!r}")
        top_damage = list(focus_raw.checkpoint.debug.spawn.top_creature_damage_callers)
        if top_damage:
            print(f"  capture_creature_damage_callers_top={top_damage[:6]!r}")
        damage_head = [head.data for head in focus_raw.event_heads if isinstance(head, CaptureEventHeadCreatureDamage)]
        if damage_head:
            print(f"  capture_creature_damage_head={damage_head[:6]!r}")
        projectile_find_hit_count = int(focus_raw.event_counts.projectile_find_hit)
        projectile_find_hit_count_effective = _effective_capture_projectile_hit_count(focus_raw)
        if projectile_find_hit_count >= 0:
            print(
                "  "
                f"capture_projectile_find_hit_count={int(projectile_find_hit_count)} "
                f"capture_projectile_find_hit_count_effective={int(projectile_find_hit_count_effective)} "
                "capture_projectile_find_hit_corpse_count="
                + str(
                    sum(
                        1
                        for head in focus_raw.event_heads
                        if isinstance(head, CaptureEventHeadProjectileFindHit) and bool(head.data.corpse_hit)
                    ),
                ),
            )
        projectile_find_query_count = int(focus_raw.event_counts.projectile_find_query)
        if projectile_find_query_count >= 0:
            print(
                "  "
                f"capture_projectile_find_query_count={int(projectile_find_query_count)} "
                "capture_projectile_find_query_miss_count="
                f"{int(focus_raw.checkpoint.debug.spawn.event_count_projectile_find_query_miss)} "
                "capture_projectile_find_query_owner_collision_count="
                f"{int(focus_raw.checkpoint.debug.spawn.event_count_projectile_find_query_owner_collision)}",
            )
        top_projectile_queries = list(focus_raw.checkpoint.debug.spawn.top_projectile_find_query_callers)
        if top_projectile_queries:
            print(f"  capture_projectile_find_query_callers_top={top_projectile_queries[:6]!r}")
        top_projectile_hits = list(focus_raw.checkpoint.debug.spawn.top_projectile_find_hit_callers)
        if top_projectile_hits:
            print(f"  capture_projectile_find_hit_callers_top={top_projectile_hits[:6]!r}")
        projectile_find_query_head = [
            head.data for head in focus_raw.event_heads if isinstance(head, CaptureEventHeadProjectileFindQuery)
        ]
        if projectile_find_query_head:
            print(f"  capture_projectile_find_query_head={projectile_find_query_head[:6]!r}")
        projectile_find_hit_head = [
            head.data for head in focus_raw.event_heads if isinstance(head, CaptureEventHeadProjectileFindHit)
        ]
        if projectile_find_hit_head:
            print(f"  capture_projectile_find_hit_head={projectile_find_hit_head[:6]!r}")
        creature_update_micro_count = int(focus_raw.event_counts.creature_update_micro)
        if creature_update_micro_count >= 0:
            print(f"  capture_creature_update_micro_count={int(creature_update_micro_count)}")
        creature_update_micro_head = [
            head.data for head in focus_raw.event_heads if isinstance(head, CaptureEventHeadCreatureUpdateMicro)
        ]
        if creature_update_micro_head:
            print(f"  capture_creature_update_micro_head={creature_update_micro_head[:6]!r}")
        secondary_spawn_count = int(focus_raw.event_counts.secondary_projectile_spawn)
        if secondary_spawn_count > 0:
            print(f"  capture_secondary_projectile_spawn_count={secondary_spawn_count}")
        secondary_spawn_head = [
            head.data for head in focus_raw.event_heads if isinstance(head, CaptureEventHeadSecondaryProjectileSpawn)
        ]
        if secondary_spawn_head:
            print(f"  capture_secondary_projectile_spawn_head={secondary_spawn_head[:6]!r}")
        if focus_raw.checkpoint.debug.before_players:
            print(f"  before_player0={focus_raw.checkpoint.debug.before_players[0]!r}")
        player_keys = _extract_player_input_keys(focus_raw, player_index=0)
        if player_keys:
            print(f"  input_player_keys[0]={player_keys!r}")
        sample_counts = {
            "creatures": len(focus_raw.samples.creatures),
            "projectiles": len(focus_raw.samples.projectiles),
            "secondary_projectiles": len(focus_raw.samples.secondary_projectiles),
            "bonuses": len(focus_raw.samples.bonuses),
        }
        print(f"  sample_counts={sample_counts!r}")
        if focus_raw.samples.secondary_projectiles:
            print(f"  sample_secondary_head={focus_raw.samples.secondary_projectiles[:6]!r}")
        if focus_raw.samples.creatures:
            print(f"  sample_creatures_head={focus_raw.samples.creatures[:6]!r}")
    if focus_actual_ckpt is not None:
        actual_rand_calls = _actual_rand_calls_for_checkpoint(focus_actual_ckpt)
        stage_calls = _actual_rand_stage_calls(focus_actual_ckpt)
        focus_stream_rows = [] if focus_raw is None else _rng_stream_rows_for_tick(focus_raw)
        focus_stream = _compute_rng_stream_alignment(
            act=focus_actual_ckpt,
            capture_stream_rows=focus_stream_rows,
            capture_head_len=len(focus_stream_rows),
        )
        print(
            f"  rewrite_rand_calls={actual_rand_calls!r} rewrite_rand_stage_calls={stage_calls!r}",
        )
        print(
            "  "
            "rewrite_rng_stream_alignment="
            f"prefix_match={focus_stream.get('prefix_match')!r}/{focus_stream.get('compared')!r} "
            f"first_mismatch_idx={focus_stream.get('first_mismatch_idx')!r} "
            f"reason={focus_stream.get('first_mismatch_reason')!r} "
            f"capture_mismatch={focus_stream.get('first_mismatch_capture')!r} "
            f"rewrite_mismatch={focus_stream.get('first_mismatch_actual')!r} "
            f"capture_branch_id={focus_stream.get('first_mismatch_capture_branch_id')!r} "
            f"missing_tail={focus_stream.get('missing_tail')!r}",
        )
        if focus_actual_ckpt.deaths:
            death_head = [
                {
                    "creature_index": int(item.creature_index),
                    "type_id": int(item.type_id),
                    "xp_awarded": int(item.xp_awarded),
                    "owner_id": int(item.owner_id),
                }
                for item in focus_actual_ckpt.deaths[:6]
            ]
            print(f"  rewrite_deaths_head={death_head!r}")

    zero_rand_consumed = [
        row
        for row in rows
        if int(row["expected_rand_calls"]) == 0 and bool(row["actual_rng_changed"])  # ty:ignore[invalid-argument-type]
    ]
    if zero_rand_consumed:
        print()
        print(
            "hint: expected rand_calls=0 but actual RNG state changed on ticks: "
            + ", ".join(str(int(row["tick"])) for row in zero_rand_consumed[:12]),  # ty:ignore[invalid-argument-type]
        )

    if json_out_path is not None:
        payload = {
            "capture": str(capture_path),
            "summary": {
                "expected_count": len(expected),
                "actual_count": len(actual),
                "sample_rate": int(sample_rate),
                "run_ticks": int(run_result.ticks),  # ty:ignore[unresolved-attribute]
                "run_score_xp": int(run_result.score_xp),  # ty:ignore[unresolved-attribute]
                "run_kills": int(run_result.creature_kill_count),  # ty:ignore[unresolved-attribute]
            },
            "replay_header": {
                "game_mode_id": int(replay.header.game_mode_id),
                "tick_rate": int(replay.header.tick_rate),
                "player_count": int(replay.header.player_count),
                "seed": int(replay.header.seed),
                "status": asdict(replay.header.status),
            },
            "divergence": {
                "kind": divergence.kind,
                "tick_index": int(divergence.tick_index),
                "focus_tick": int(focus_tick),
                "field_diffs": [asdict(diff) for diff in divergence.field_diffs],
            },
            "divergence_category": asdict(divergence_category),
            "window_rows": rows,
            "investigation_leads": [asdict(lead) for lead in leads],
            "focus_capture_debug": (None if focus_raw is None else msgspec.to_builtins(focus_raw)),
            "focus_rewrite_debug": (
                {
                    "rand_calls": _actual_rand_calls_for_checkpoint(focus_actual_ckpt),
                    "rand_stage_calls": _actual_rand_stage_calls(focus_actual_ckpt),
                    "rand_stream_alignment": _compute_rng_stream_alignment(
                        act=focus_actual_ckpt,
                        capture_stream_rows=([] if focus_raw is None else _rng_stream_rows_for_tick(focus_raw)),
                        capture_head_len=(0 if focus_raw is None else len(_rng_stream_rows_for_tick(focus_raw))),
                    ),
                    "deaths": [
                        {
                            "creature_index": int(item.creature_index),
                            "type_id": int(item.type_id),
                            "xp_awarded": int(item.xp_awarded),
                            "owner_id": int(item.owner_id),
                        }
                        for item in (focus_actual_ckpt.deaths[:6] if focus_actual_ckpt.deaths else [])
                    ],
                }
                if focus_actual_ckpt is not None
                else {}
            ),
        }
        if bool(args.run_summary) or bool(args.run_summary_short) or bool(args.run_summary_focus_context):
            payload["run_summary_events"] = [asdict(event) for event in run_summary_events]
            payload["run_summary_short_events"] = [asdict(event) for event in run_summary_short_events]
            payload["run_summary_focus_context_events"] = [asdict(event) for event in run_summary_focus_events]
        json_out_path.parent.mkdir(parents=True, exist_ok=True)
        json_out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print()
        print(f"json_report={json_out_path}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
