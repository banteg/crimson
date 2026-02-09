from __future__ import annotations

import argparse
import bisect
from collections import Counter
import functools
import gzip
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
import re

from crimson.bonuses import bonus_label
from crimson.game_modes import GameMode
from crimson.perks import perk_label
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.diff import ReplayFieldDiff, checkpoint_field_diffs
from crimson.replay.original_capture import (
    OriginalCaptureSidecar,
    build_original_capture_dt_frame_overrides,
    convert_original_capture_to_checkpoints,
    convert_original_capture_to_replay,
    load_original_capture_sidecar,
)
from crimson.sim.runners import run_rush_replay, run_survival_replay
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
        "src/crimson/projectiles.py",
        "src/crimson/creatures/runtime.py",
    ),
    "creature_handle_death": ("src/crimson/creatures/runtime.py",),
    "projectile_update": (
        "src/crimson/projectiles.py",
        "src/crimson/sim/world_state.py",
    ),
    "player_update": (
        "src/crimson/gameplay.py",
        "src/crimson/weapons.py",
        "src/crimson/player_damage.py",
    ),
    "bonus_try_spawn_on_kill": (
        "src/crimson/bonuses.py",
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
        "src/crimson/features/bonuses/fire_bullets.py",
    ),
}

RNG_STAGE_TO_PORT_PATHS: dict[str, tuple[str, ...]] = {
    "creatures": ("src/crimson/creatures/runtime.py", "src/crimson/creatures/ai.py"),
    "projectiles": ("src/crimson/projectiles.py", "src/crimson/sim/world_state.py"),
    "secondary_projectiles": ("src/crimson/projectiles.py", "src/crimson/sim/world_state.py"),
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


def _int_or(value: object, default: int = -1) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _float_or(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _fmt_opt_int(value: object, *, width: int = 0, unknown: str = "na") -> str:
    if value is None:
        return f"{unknown:>{width}}" if width > 0 else unknown
    try:
        ivalue = int(value)
    except Exception:
        return f"{unknown:>{width}}" if width > 0 else unknown
    return f"{ivalue:{width}d}" if width > 0 else str(ivalue)


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


def _allow_capture_sample_creature_count(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    capture_sample_creature_counts: dict[int, int],
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

    # v2 capture `creature_active_count` can transiently disagree with sampled
    # active slots. When our sim count matches the sampled list exactly and this
    # is the only field mismatch, keep scanning for a stronger divergence.
    return actual_count == int(sample_count) and expected_count != int(sample_count)


def _iter_jsonl_objects(path: Path):
    open_fn = gzip.open if path.suffix == ".gz" else open
    with open_fn(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _load_capture_sample_creature_counts(path: Path) -> dict[int, int]:
    lower = str(path).lower()
    if not (lower.endswith(".jsonl") or lower.endswith(".jsonl.gz")):
        return {}

    out: dict[int, int] = {}
    for obj in _iter_jsonl_objects(path):
        if obj.get("event") != "tick":
            continue
        tick_index = _int_or(obj.get("tick_index"), -1)
        if tick_index < 0:
            continue
        samples = obj.get("samples")
        if not isinstance(samples, dict):
            continue
        creatures = samples.get("creatures")
        if not isinstance(creatures, list):
            continue
        out[int(tick_index)] = int(len(creatures))
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
        )
    )


def _parse_raw_player_perk_counts(checkpoint_obj: dict[str, object]) -> dict[int, Counter[int]]:
    perk_obj = checkpoint_obj.get("perk")
    if not isinstance(perk_obj, dict):
        return {}
    raw_counts = perk_obj.get("player_nonzero_counts")
    if not isinstance(raw_counts, list):
        return {}

    out: dict[int, Counter[int]] = {}
    for player_idx, player_counts in enumerate(raw_counts):
        if not isinstance(player_counts, list):
            continue
        counts = Counter()
        for pair in player_counts:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                perk_id = _int_or(pair[0], -1)
                perk_count = _int_or(pair[1], 0)
            elif isinstance(pair, dict):
                perk_id = _int_or(pair.get("perk_id"), -1)
                perk_count = _int_or(pair.get("count"), 0)
            else:
                continue
            if perk_id < 0 or perk_count <= 0:
                continue
            counts[int(perk_id)] = int(perk_count)
        if counts:
            out[int(player_idx)] = counts
    return out


def _build_run_summary_events_from_raw_capture(path: Path) -> list[RunSummaryEvent]:
    events: list[RunSummaryEvent] = []
    seen: set[tuple[int, str, str]] = set()
    prev_levels: dict[int, int] = {}
    prev_perk_counts: dict[int, Counter[int]] = {}

    for obj in _iter_jsonl_objects(path):
        if obj.get("event") != "tick":
            continue

        raw_checkpoint = obj.get("checkpoint")
        checkpoint_obj = raw_checkpoint if isinstance(raw_checkpoint, dict) else obj
        tick = _int_or(checkpoint_obj.get("tick_index"), _int_or(obj.get("tick_index"), -1))
        if tick < 0:
            continue

        event_heads = obj.get("event_heads")
        heads = event_heads if isinstance(event_heads, dict) else {}

        raw_bonus_apply = heads.get("bonus_apply")
        bonus_apply = raw_bonus_apply if isinstance(raw_bonus_apply, list) else []
        for item in bonus_apply:
            if not isinstance(item, dict):
                continue
            player_index = _int_or(item.get("player_index"), 0)
            bonus_id = _int_or(item.get("bonus_id"), -1)
            detail = f"p{player_index} picked {_bonus_name(int(bonus_id))}"
            if int(bonus_id) == 3:
                weapon_id = _int_or(item.get("amount_i32"), -1)
                if weapon_id >= 0:
                    detail += f" -> {_weapon_name(int(weapon_id))}"
            _append_run_summary_event(
                events,
                seen=seen,
                tick=int(tick),
                kind="bonus_pickup",
                detail=detail,
            )

        raw_weapon_assign = heads.get("weapon_assign")
        weapon_assign = raw_weapon_assign if isinstance(raw_weapon_assign, list) else []
        for item in weapon_assign:
            if not isinstance(item, dict):
                continue
            player_index = _int_or(item.get("player_index"), 0)
            weapon_before = _int_or(item.get("weapon_before"), -1)
            weapon_after = _int_or(item.get("weapon_after"), _int_or(item.get("weapon_id"), -1))
            detail = (
                f"p{player_index} weapon "
                f"{_weapon_name(int(weapon_before))} -> {_weapon_name(int(weapon_after))}"
            )
            _append_run_summary_event(
                events,
                seen=seen,
                tick=int(tick),
                kind="weapon_assign",
                detail=detail,
            )

        raw_state_transition = heads.get("state_transition")
        state_transition = raw_state_transition if isinstance(raw_state_transition, list) else []
        for item in state_transition:
            if not isinstance(item, dict):
                continue
            before_state = _int_or(
                (item.get("before") or {}).get("id") if isinstance(item.get("before"), dict) else None,
                -1,
            )
            after_state = _int_or(
                (item.get("after") or {}).get("id") if isinstance(item.get("after"), dict) else item.get("target_state"),
                _int_or(item.get("target_state"), -1),
            )
            _append_run_summary_event(
                events,
                seen=seen,
                tick=int(tick),
                kind="state_transition",
                detail=f"state {before_state} -> {after_state}",
            )

        players_raw = checkpoint_obj.get("players")
        players = players_raw if isinstance(players_raw, list) else []
        for player_index, player_obj in enumerate(players):
            if not isinstance(player_obj, dict):
                continue
            level = _int_or(player_obj.get("level"), -1)
            if level < 0:
                continue
            prev_level = prev_levels.get(int(player_index))
            if prev_level is not None and int(level) > int(prev_level):
                experience = _int_or(player_obj.get("experience"), -1)
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="level_up",
                    detail=f"p{int(player_index)} level {int(prev_level)} -> {int(level)} (xp={int(experience)})",
                )
            prev_levels[int(player_index)] = int(level)

        perk_counts = _parse_raw_player_perk_counts(checkpoint_obj)
        for player_index, player_counts in perk_counts.items():
            previous = prev_perk_counts.get(int(player_index), Counter())
            for perk_id, perk_count in sorted(player_counts.items()):
                previous_count = int(previous.get(int(perk_id), 0))
                if int(perk_count) <= int(previous_count):
                    continue
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick),
                    kind="perk_pick",
                    detail=(
                        f"p{int(player_index)} perk {perk_label(int(perk_id))} ({int(perk_id)}) "
                        f"x{int(perk_count)}"
                    ),
                )
            prev_perk_counts[int(player_index)] = Counter(player_counts)

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
            previous = prev_perk_counts.get(int(player_index), Counter())
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
                        f"p{int(player_index)} perk {perk_label(int(perk_id))} ({int(perk_id)}) "
                        f"x{int(perk_count)}"
                    ),
                )
            prev_perk_counts[int(player_index)] = counts

    events.sort(key=lambda item: (int(item.tick_index), str(item.kind), str(item.detail)))
    return events


def _build_run_summary_events(capture_path: Path, *, expected: list[ReplayCheckpoint]) -> list[RunSummaryEvent]:
    lower = capture_path.name.lower()
    if lower.endswith(".jsonl") or lower.endswith(".jsonl.gz"):
        events = _build_run_summary_events_from_raw_capture(capture_path)
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


def _load_raw_tick_debug(path: Path, tick_indices: set[int] | None = None) -> dict[int, dict[str, object]]:
    lower = path.name.lower()
    if not (lower.endswith(".jsonl") or lower.endswith(".jsonl.gz")):
        return {}

    out: dict[int, dict[str, object]] = {}
    for obj in _iter_jsonl_objects(path):
        if obj.get("event") != "tick":
            continue
        checkpoint = obj.get("checkpoint")
        ckpt = checkpoint if isinstance(checkpoint, dict) else obj
        tick = _int_or(ckpt.get("tick_index"), _int_or(obj.get("tick_index"), -1))
        if tick_indices is not None and tick not in tick_indices:
            continue

        rng_marks = ckpt.get("rng_marks")
        rng_obj = rng_marks if isinstance(rng_marks, dict) else {}
        rng_top = obj.get("rng")
        rng_top_obj = rng_top if isinstance(rng_top, dict) else {}
        debug = ckpt.get("debug")
        debug_obj = debug if isinstance(debug, dict) else {}
        spawn = debug_obj.get("spawn")
        spawn_obj = spawn if isinstance(spawn, dict) else {}
        before_players = debug_obj.get("before_players")
        before_players_obj = before_players if isinstance(before_players, list) else []
        if not before_players_obj:
            top_before = obj.get("before")
            top_before_obj = top_before if isinstance(top_before, dict) else {}
            top_before_players = top_before_obj.get("players")
            if isinstance(top_before_players, list):
                before_players_obj = top_before_players
        lifecycle = debug_obj.get("creature_lifecycle")
        lifecycle_obj = lifecycle if isinstance(lifecycle, dict) else {}
        event_counts = obj.get("event_counts")
        event_counts_obj = event_counts if isinstance(event_counts, dict) else {}
        event_heads = obj.get("event_heads")
        event_heads_obj = event_heads if isinstance(event_heads, dict) else {}
        samples = obj.get("samples")
        samples_obj = samples if isinstance(samples, dict) else {}
        sample_creatures = samples_obj.get("creatures")
        sample_creatures_obj = sample_creatures if isinstance(sample_creatures, list) else []
        sample_projectiles = samples_obj.get("projectiles")
        sample_projectiles_obj = sample_projectiles if isinstance(sample_projectiles, list) else []
        sample_secondary = samples_obj.get("secondary_projectiles")
        sample_secondary_obj = sample_secondary if isinstance(sample_secondary, list) else []
        sample_bonuses = samples_obj.get("bonuses")
        sample_bonuses_obj = sample_bonuses if isinstance(sample_bonuses, list) else []
        creature_damage_head = event_heads_obj.get("creature_damage")
        creature_damage_head_obj = creature_damage_head if isinstance(creature_damage_head, list) else []
        projectile_spawn_head = event_heads_obj.get("projectile_spawn")
        projectile_spawn_head_obj = projectile_spawn_head if isinstance(projectile_spawn_head, list) else []
        secondary_projectile_spawn_head = event_heads_obj.get("secondary_projectile_spawn")
        secondary_projectile_spawn_head_obj = (
            secondary_projectile_spawn_head if isinstance(secondary_projectile_spawn_head, list) else []
        )
        creature_death_head = event_heads_obj.get("creature_death")
        creature_death_head_obj = creature_death_head if isinstance(creature_death_head, list) else []
        bonus_spawn_head = event_heads_obj.get("bonus_spawn")
        bonus_spawn_head_obj = bonus_spawn_head if isinstance(bonus_spawn_head, list) else []
        projectile_find_hit_head = event_heads_obj.get("projectile_find_hit")
        projectile_find_hit_head_obj = projectile_find_hit_head if isinstance(projectile_find_hit_head, list) else []
        rng_callers_top = rng_top_obj.get("callers")
        rng_callers_top_obj = rng_callers_top if isinstance(rng_callers_top, list) else []
        rng_rand_calls = _int_or(rng_obj.get("rand_calls"))
        if rng_rand_calls < 0:
            rng_rand_calls = _int_or(rng_top_obj.get("calls"))
        rng_rand_last = rng_obj.get("rand_last")
        if rng_rand_last is None:
            rng_rand_last = rng_top_obj.get("last_value")
        rng_seq_first = _int_or(rng_obj.get("rand_seq_first"))
        if rng_seq_first < 0:
            rng_seq_first = _int_or(rng_top_obj.get("seq_first"))
        rng_seq_last = _int_or(rng_obj.get("rand_seq_last"))
        if rng_seq_last < 0:
            rng_seq_last = _int_or(rng_top_obj.get("seq_last"))
        rng_seed_epoch_enter = _int_or(rng_obj.get("rand_seed_epoch_enter"))
        if rng_seed_epoch_enter < 0:
            rng_seed_epoch_enter = _int_or(rng_top_obj.get("seed_epoch_enter"))
        rng_seed_epoch_last = _int_or(rng_obj.get("rand_seed_epoch_last"))
        if rng_seed_epoch_last < 0:
            rng_seed_epoch_last = _int_or(rng_top_obj.get("seed_epoch_last"))
        rng_outside_before_calls = _int_or(rng_obj.get("rand_outside_before_calls"))
        if rng_outside_before_calls < 0:
            rng_outside_before_calls = _int_or(rng_top_obj.get("outside_before_calls"))
        rng_mirror_mismatch_total = _int_or(rng_obj.get("rand_mirror_mismatch_total"))
        if rng_mirror_mismatch_total < 0:
            rng_mirror_mismatch_total = _int_or(rng_top_obj.get("mirror_mismatch_total"))
        rng_callers = rng_obj.get("rand_callers") if isinstance(rng_obj.get("rand_callers"), list) else []
        if not rng_callers:
            rng_callers = rng_callers_top_obj
        rng_head = rng_obj.get("rand_head")
        rng_head_obj = rng_head if isinstance(rng_head, list) else []
        if not rng_head_obj:
            rng_head_top = rng_top_obj.get("head")
            if isinstance(rng_head_top, list):
                rng_head_obj = rng_head_top

        sample_creatures_head: list[dict[str, object]] = []
        for item in sample_creatures_obj[:6]:
            if not isinstance(item, dict):
                continue
            pos_obj = item.get("pos") if isinstance(item.get("pos"), dict) else {}
            sample_creatures_head.append(
                {
                    "index": _int_or(item.get("index")),
                    "type_id": _int_or(item.get("type_id")),
                    "hp": _float_or(item.get("hp")),
                    "hitbox_size": _float_or(item.get("hitbox_size")),
                    "pos": {
                        "x": _float_or(pos_obj.get("x")),
                        "y": _float_or(pos_obj.get("y")),
                    },
                }
            )

        sample_secondary_head: list[dict[str, object]] = []
        for item in sample_secondary_obj[:6]:
            if not isinstance(item, dict):
                continue
            pos_obj = item.get("pos") if isinstance(item.get("pos"), dict) else {}
            sample_secondary_head.append(
                {
                    "index": _int_or(item.get("index")),
                    "type_id": _int_or(item.get("type_id")),
                    "target_id": _int_or(item.get("target_id")),
                    "life_timer": _float_or(item.get("life_timer")),
                    "pos": {
                        "x": _float_or(pos_obj.get("x")),
                        "y": _float_or(pos_obj.get("y")),
                    },
                }
            )

        out[int(tick)] = {
            "rng_rand_calls": rng_rand_calls,
            "rng_head_len": len(rng_head_obj),
            "rng_rand_last": rng_rand_last,
            "rng_seq_first": rng_seq_first,
            "rng_seq_last": rng_seq_last,
            "rng_seed_epoch_enter": rng_seed_epoch_enter,
            "rng_seed_epoch_last": rng_seed_epoch_last,
            "rng_outside_before_calls": rng_outside_before_calls,
            "rng_mirror_mismatch_total": rng_mirror_mismatch_total,
            "rng_callers": rng_callers,
            "spawn_bonus_count": _int_or(spawn_obj.get("event_count_bonus_spawn")),
            "spawn_death_count": _int_or(spawn_obj.get("event_count_death")),
            "spawn_top_bonus_callers": (
                spawn_obj.get("top_bonus_spawn_callers")
                if isinstance(spawn_obj.get("top_bonus_spawn_callers"), list)
                else []
            ),
            "creature_damage_count": _int_or(
                event_counts_obj.get("creature_damage"),
                _int_or(spawn_obj.get("event_count_creature_damage"), 0),
            ),
            "creature_damage_head": creature_damage_head_obj,
            "projectile_spawn_head": projectile_spawn_head_obj,
            "secondary_projectile_spawn_count": _int_or(event_counts_obj.get("secondary_projectile_spawn"), 0),
            "secondary_projectile_spawn_head": secondary_projectile_spawn_head_obj,
            "creature_death_head": creature_death_head_obj,
            "bonus_spawn_head": bonus_spawn_head_obj,
            "projectile_find_hit_count": _int_or(
                event_counts_obj.get("projectile_find_hit"),
                len(projectile_find_hit_head_obj),
            ),
            "projectile_find_hit_head": projectile_find_hit_head_obj,
            "projectile_find_hit_corpse_count": sum(
                1
                for item in projectile_find_hit_head_obj
                if isinstance(item, dict) and bool(item.get("corpse_hit"))
            ),
            "spawn_top_creature_damage_callers": (
                spawn_obj.get("top_creature_damage_callers")
                if isinstance(spawn_obj.get("top_creature_damage_callers"), list)
                else []
            ),
            "spawn_top_projectile_find_hit_callers": (
                spawn_obj.get("top_projectile_find_hit_callers")
                if isinstance(spawn_obj.get("top_projectile_find_hit_callers"), list)
                else []
            ),
            "lifecycle_before_hash": lifecycle_obj.get("before_hash"),
            "lifecycle_after_hash": lifecycle_obj.get("after_hash"),
            "lifecycle_before_count": _int_or(lifecycle_obj.get("before_count")),
            "lifecycle_after_count": _int_or(lifecycle_obj.get("after_count")),
            "before_player0": before_players_obj[0] if before_players_obj else None,
            "input_player_keys": obj.get("input_player_keys") if isinstance(obj.get("input_player_keys"), list) else [],
            "sample_streams_present": bool(samples_obj),
            "sample_counts": {
                "creatures": len(sample_creatures_obj) if isinstance(sample_creatures, list) else -1,
                "projectiles": len(sample_projectiles_obj) if isinstance(sample_projectiles, list) else -1,
                "secondary_projectiles": len(sample_secondary_obj) if isinstance(sample_secondary, list) else -1,
                "bonuses": len(sample_bonuses_obj) if isinstance(sample_bonuses, list) else -1,
            },
            "sample_creatures_head": sample_creatures_head,
            "sample_secondary_head": sample_secondary_head,
        }
    return out


def _run_actual_checkpoints(
    capture: OriginalCaptureSidecar,
    *,
    max_ticks: int | None,
    seed: int | None,
    inter_tick_rand_draws: int,
) -> tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], object]:
    expected = convert_original_capture_to_checkpoints(capture).checkpoints
    if max_ticks is not None:
        tick_cap = max(0, int(max_ticks))
        expected = [ckpt for ckpt in expected if int(ckpt.tick_index) < int(tick_cap)]

    replay = convert_original_capture_to_replay(capture, seed=seed)
    dt_frame_overrides = build_original_capture_dt_frame_overrides(
        capture,
        tick_rate=int(replay.header.tick_rate),
    )
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected}
    inter_tick_rand_draws_by_tick = {
        int(tick.tick_index): int(tick.rng_outside_before_calls)
        for tick in capture.ticks
        if int(tick.rng_outside_before_calls) >= 0
    }
    if inter_tick_rand_draws_by_tick:
        first_tick_index = min(inter_tick_rand_draws_by_tick)
        # The inferred replay seed already matches the first sampled tick RNG
        # entry state, so do not reapply pre-capture bootstrap draws here.
        inter_tick_rand_draws_by_tick[int(first_tick_index)] = 0
    if not inter_tick_rand_draws_by_tick:
        inter_tick_rand_draws_by_tick = None
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
) -> Divergence | None:
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    sample_counts = capture_sample_creature_counts or {}

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
        if _allow_capture_sample_creature_count(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
            capture_sample_creature_counts=sample_counts,
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
    for key in ("after_wave_spawns", "after_rush_spawns", "after_world_step"):
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
    except Exception:
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
            px_exp = float(getattr(exp_player, "pos").x)
            px_act = float(getattr(act_player, "pos").x)
            if "players[0].pos.x" not in onsets and abs(px_exp - px_act) > float_abs_tol:
                onsets["players[0].pos.x"] = FieldDriftOnset(
                    field="players[0].pos.x",
                    tick=int(tick),
                    expected=px_exp,
                    actual=px_act,
                    delta=float(px_act - px_exp),
                )

            py_exp = float(getattr(exp_player, "pos").y)
            py_act = float(getattr(act_player, "pos").y)
            if "players[0].pos.y" not in onsets and abs(py_exp - py_act) > float_abs_tol:
                onsets["players[0].pos.y"] = FieldDriftOnset(
                    field="players[0].pos.y",
                    tick=int(tick),
                    expected=py_exp,
                    actual=py_act,
                    delta=float(py_act - py_exp),
                )

            ammo_exp = float(getattr(exp_player, "ammo"))
            ammo_act = float(getattr(act_player, "ammo"))
            if "players[0].ammo" not in onsets and abs(ammo_exp - ammo_act) > float_abs_tol:
                onsets["players[0].ammo"] = FieldDriftOnset(
                    field="players[0].ammo",
                    tick=int(tick),
                    expected=ammo_exp,
                    actual=ammo_act,
                    delta=float(ammo_act - ammo_exp),
                )

            health_exp = float(getattr(exp_player, "health"))
            health_act = float(getattr(act_player, "health"))
            if "players[0].health" not in onsets and abs(health_exp - health_act) > float_abs_tol:
                onsets["players[0].health"] = FieldDriftOnset(
                    field="players[0].health",
                    tick=int(tick),
                    expected=health_exp,
                    actual=health_act,
                    delta=float(health_act - health_exp),
                )

            weapon_exp = _int_or(getattr(exp_player, "weapon_id"))
            weapon_act = _int_or(getattr(act_player, "weapon_id"))
            if "players[0].weapon_id" not in onsets and weapon_exp != weapon_act:
                onsets["players[0].weapon_id"] = FieldDriftOnset(
                    field="players[0].weapon_id",
                    tick=int(tick),
                    expected=int(weapon_exp),
                    actual=int(weapon_act),
                    delta=int(weapon_act - weapon_exp),
                )

            xp_exp = _int_or(getattr(exp_player, "experience"))
            xp_act = _int_or(getattr(act_player, "experience"))
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


def _ticks_rng_zero_but_changed(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, dict[str, object]],
    start_tick: int,
    end_tick: int,
) -> list[int]:
    ticks: list[int] = []
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        act = actual_by_tick.get(tick)
        if act is None:
            continue
        expected_calls = _int_or(raw_debug_by_tick.get(tick, {}).get("rng_rand_calls"), -1)
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
    raw_debug_by_tick: dict[int, dict[str, object]],
    ticks: list[int] | set[int],
) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for tick in ticks:
        callers = raw_debug_by_tick.get(int(tick), {}).get("rng_callers")
        if not isinstance(callers, list):
            continue
        for caller in callers:
            if not isinstance(caller, dict):
                continue
            key = caller.get("caller_static")
            if key is None:
                continue
            calls = _int_or(caller.get("calls"), 1)
            if calls <= 0:
                continue
            caller_key = str(key)
            counts[caller_key] = int(counts.get(caller_key, 0)) + int(calls)
    return sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0])))


def _aggregate_neighbor_rng_callers_for_ticks(
    *,
    raw_debug_by_tick: dict[int, dict[str, object]],
    ticks: list[int],
    radius: int = 2,
) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    radius = max(0, int(radius))
    for tick in ticks:
        picked: list[tuple[str, int]] = []
        for offset in range(0, radius + 1):
            for signed in ((-offset, offset) if offset > 0 else (0,)):
                probe = int(tick) + int(signed)
                callers = raw_debug_by_tick.get(probe, {}).get("rng_callers")
                if not isinstance(callers, list) or not callers:
                    continue
                for caller in callers:
                    if not isinstance(caller, dict):
                        continue
                    key = caller.get("caller_static")
                    if key is None:
                        continue
                    calls = _int_or(caller.get("calls"), 1)
                    if calls <= 0:
                        continue
                    picked.append((str(key), int(calls)))
                if picked:
                    break
            if picked:
                break
        for key, calls in picked:
            counts[key] = int(counts.get(key, 0)) + int(calls)
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
        fn_counts[fn] = int(fn_counts.get(fn, 0)) + int(calls)
    ranked = sorted(fn_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return ranked[: max(1, int(limit))]


def _find_first_rng_head_shortfall(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, dict[str, object]],
    start_tick: int,
    end_tick: int,
) -> dict[str, object] | None:
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        exp = expected_by_tick.get(int(tick))
        act = actual_by_tick.get(int(tick))
        if exp is None or act is None:
            continue
        expected_head_len = _int_or(raw_debug_by_tick.get(int(tick), {}).get("rng_head_len"), -1)
        if expected_head_len <= 0:
            continue
        actual_rand_calls = _actual_rand_calls_for_checkpoint(act)
        if actual_rand_calls is None:
            continue
        if int(actual_rand_calls) >= int(expected_head_len):
            continue
        expected_rand_calls = _int_or(
            raw_debug_by_tick.get(int(tick), {}).get("rng_rand_calls"),
            _int_or(exp.rng_marks.get("rand_calls"), -1),
        )
        caller_counts = _aggregate_rng_callers(
            raw_debug_by_tick=raw_debug_by_tick,
            ticks=[int(tick)],
        )
        seq_first = _int_or(raw_debug_by_tick.get(int(tick), {}).get("rng_seq_first"), -1)
        seq_last = _int_or(raw_debug_by_tick.get(int(tick), {}).get("rng_seq_last"), -1)
        seed_epoch_enter = _int_or(raw_debug_by_tick.get(int(tick), {}).get("rng_seed_epoch_enter"), -1)
        seed_epoch_last = _int_or(raw_debug_by_tick.get(int(tick), {}).get("rng_seed_epoch_last"), -1)
        return {
            "tick": int(tick),
            "expected_head_len": int(expected_head_len),
            "actual_rand_calls": int(actual_rand_calls),
            "missing_draws": int(expected_head_len) - int(actual_rand_calls),
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
    raw_debug_by_tick: dict[int, dict[str, object]],
    start_tick: int,
    end_tick: int,
) -> dict[str, object] | None:
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        raw = raw_debug_by_tick.get(int(tick), {})
        capture_hits = _int_or(raw.get("projectile_find_hit_count"), -1)
        if capture_hits < 0:
            continue
        act = actual_by_tick.get(int(tick))
        if act is None:
            continue
        actual_hits = _int_or(act.events.hit_count, -1)
        if actual_hits < 0:
            continue
        if int(capture_hits) <= int(actual_hits):
            continue
        caller_counts = raw.get("spawn_top_projectile_find_hit_callers")
        if not isinstance(caller_counts, list):
            caller_counts = []
        if not caller_counts:
            head = raw.get("projectile_find_hit_head")
            head_rows = head if isinstance(head, list) else []
            reduced: dict[str, int] = {}
            for item in head_rows:
                if not isinstance(item, dict):
                    continue
                key = item.get("caller_static")
                if key is None:
                    continue
                reduced[str(key)] = int(reduced.get(str(key), 0)) + 1
            caller_counts = [
                {"key": key, "count": count}
                for key, count in sorted(reduced.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ]
        return {
            "tick": int(tick),
            "capture_hits": int(capture_hits),
            "actual_hits": int(actual_hits),
            "missing_hits": int(capture_hits) - int(actual_hits),
            "capture_corpse_hits": _int_or(raw.get("projectile_find_hit_corpse_count"), -1),
            "caller_counts": caller_counts,
        }
    return None


def _port_paths_for_native_functions(function_names: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for name in function_names:
        for path in NATIVE_FUNCTION_TO_PORT_PATHS.get(str(name), ()):
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


def _extract_player_input_keys(raw: dict[str, object], player_index: int = 0) -> dict[str, object]:
    rows = raw.get("input_player_keys")
    if not isinstance(rows, list):
        return {}
    for idx, item in enumerate(rows):
        if not isinstance(item, dict):
            continue
        row_player = _int_or(item.get("player_index"), idx)
        if int(row_player) == int(player_index):
            return item
    return {}


def _input_has_opposite_direction_conflict(player_keys: dict[str, object]) -> bool:
    left = player_keys.get("turn_left_pressed")
    right = player_keys.get("turn_right_pressed")
    forward = player_keys.get("move_forward_pressed")
    backward = player_keys.get("move_backward_pressed")
    horizontal_conflict = isinstance(left, bool) and isinstance(right, bool) and left and right
    vertical_conflict = isinstance(forward, bool) and isinstance(backward, bool) and forward and backward
    return bool(horizontal_conflict or vertical_conflict)


def _find_input_conflict_ticks(
    *,
    raw_debug_by_tick: dict[int, dict[str, object]],
    start_tick: int,
    end_tick: int,
    player_index: int = 0,
) -> list[int]:
    ticks: list[int] = []
    for tick in range(max(0, int(start_tick)), int(end_tick) + 1):
        raw = raw_debug_by_tick.get(int(tick), {})
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
    raw_debug_by_tick: dict[int, dict[str, object]],
    native_ranges: tuple[NativeFunctionRange, ...],
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
    focus_raw = raw_debug_by_tick.get(int(focus_tick), {})
    sample_counts = focus_raw.get("sample_counts") if isinstance(focus_raw.get("sample_counts"), dict) else {}
    sample_counts_int = [
        _int_or(sample_counts.get(key), -1)
        for key in ("creatures", "projectiles", "secondary_projectiles", "bonuses")
    ]
    samples_missing = bool(not sample_counts or all(int(value) < 0 for value in sample_counts_int))
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
                        "use the latest v2 capture script defaults (full-detail per tick) so "
                        "`samples.secondary_projectiles` and `samples.creatures` are present at divergence ticks"
                    ),
                ),
                native_functions=(),
                code_paths=(
                    "scripts/frida/gameplay_diff_capture_v2.js",
                    "docs/frida/gameplay-diff-capture-v2.md",
                ),
            )
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
        expected_rand_calls = _int_or(rng_head_shortfall.get("expected_rand_calls"), -1)
        seq_first = _int_or(rng_head_shortfall.get("seq_first"), -1)
        seq_last = _int_or(rng_head_shortfall.get("seq_last"), -1)
        seed_epoch_enter = _int_or(rng_head_shortfall.get("seed_epoch_enter"), -1)
        seed_epoch_last = _int_or(rng_head_shortfall.get("seed_epoch_last"), -1)
        caller_counts = (
            rng_head_shortfall.get("caller_counts") if isinstance(rng_head_shortfall.get("caller_counts"), list) else []
        )
        top_native = _top_native_functions_from_callers(
            caller_counts=caller_counts,
            native_ranges=native_ranges,
            limit=5,
        )
        native_names = tuple(name for name, _calls in top_native)
        native_text = ", ".join(f"{name} x{calls}" for name, calls in top_native)
        top_callers = ", ".join(f"{addr} x{calls}" for addr, calls in caller_counts[:6])

        evidence = [
            (
                f"first pre-focus tick with native RNG-head shortfall: tick={int(shortfall_tick)} "
                f"(expected_head_len={int(expected_head_len)}, actual_rand_calls={int(actual_rand_calls)}, "
                f"missing={int(missing_draws)})"
            ),
            (
                "this means rewrite consumed fewer draws than native before the focus mismatch, "
                "so later gameplay RNG decisions can diverge even if sampled state still matches"
            ),
        ]
        if expected_rand_calls >= 0 and expected_head_len >= 0:
            evidence.append(
                f"capture rand_calls at that tick: {int(expected_rand_calls)} (head_len={int(expected_head_len)})"
            )
        if seq_first >= 0 or seq_last >= 0:
            evidence.append(
                f"capture RNG sequence range at shortfall tick: seq_first={int(seq_first)} seq_last={int(seq_last)}"
            )
        if seed_epoch_enter >= 0 or seed_epoch_last >= 0:
            evidence.append(
                f"capture RNG seed epoch at shortfall tick: enter={int(seed_epoch_enter)} leave={int(seed_epoch_last)}"
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
        leads.append(
            InvestigationLead(
                title="Pre-focus RNG-head shortfall indicates missing RNG-consuming branch",
                evidence=tuple(evidence),
                native_functions=tuple(effective_native),
                code_paths=_merge_paths(
                    _port_paths_for_native_functions(effective_native),
                    (
                        "src/crimson/projectiles.py",
                        "src/crimson/sim/presentation_step.py",
                        "src/crimson/effects.py",
                    ),
                ),
            )
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
        actual_hits = _int_or(projectile_hit_shortfall.get("actual_hits"), -1)
        missing_hits = _int_or(projectile_hit_shortfall.get("missing_hits"), -1)
        corpse_hits = _int_or(projectile_hit_shortfall.get("capture_corpse_hits"), -1)
        caller_counts_raw = (
            projectile_hit_shortfall.get("caller_counts")
            if isinstance(projectile_hit_shortfall.get("caller_counts"), list)
            else []
        )
        caller_counts: list[tuple[str, int]] = []
        for item in caller_counts_raw:
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
        top_native = _top_native_functions_from_callers(
            caller_counts=caller_counts,
            native_ranges=native_ranges,
            limit=5,
        )
        native_names = tuple(name for name, _calls in top_native)
        native_text = ", ".join(f"{name} x{calls}" for name, calls in top_native)

        evidence = [
            (
                f"first tick where native projectile hit resolves exceed rewrite hits: tick={int(shortfall_tick)} "
                f"(capture_hits={int(capture_hits)}, actual_hits={int(actual_hits)}, missing={int(missing_hits)})"
            ),
            (
                "this points to a missing rewrite hit-resolution path (often corpse hits that consume RNG/presentation "
                "without creating extra creature_damage events)"
            ),
        ]
        if corpse_hits >= 0:
            evidence.append(f"capture projectile hit resolves marked as corpse hits at that tick: {int(corpse_hits)}")
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
                        "src/crimson/projectiles.py",
                        "src/crimson/sim/world_state.py",
                        "scripts/frida/gameplay_diff_capture_v2.js",
                    ),
                ),
            )
        )

    if focus_exp is not None and focus_act is not None:
        expected_rand_calls = _int_or(
            focus_raw.get("rng_rand_calls"),
            _int_or(focus_exp.rng_marks.get("rand_calls"), -1),
        )
        actual_rand_calls = _actual_rand_calls_for_checkpoint(focus_act)
        if expected_rand_calls >= 0 and actual_rand_calls is not None:
            rand_delta = int(actual_rand_calls) - int(expected_rand_calls)
            if abs(int(rand_delta)) >= 8:
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
                if top_stages:
                    evidence.append(
                        "rewrite stage-local rand call totals: "
                        + ", ".join(f"{name}={calls}" for name, calls in top_stages[:6])
                    )
                capture_deaths = _int_or(focus_raw.get("spawn_death_count"), -1)
                if int(capture_deaths) == 0 and len(focus_act.deaths) > 0:
                    evidence.append(
                        "capture has 0 creature_death events at focus tick while rewrite produced "
                        f"{len(focus_act.deaths)} death ledger entries"
                    )
                capture_damage = _int_or(focus_raw.get("creature_damage_count"), -1)
                if int(capture_damage) == 0 and len(focus_act.deaths) > 0:
                    evidence.append(
                        "capture has 0 creature_apply_damage events at focus tick while rewrite resolved a kill branch"
                    )

                focus_callers = focus_raw.get("rng_callers")
                if isinstance(focus_callers, list) and focus_callers:
                    top = sorted(
                        [
                            (str(item.get("caller_static")), _int_or(item.get("calls"), 1))
                            for item in focus_callers
                            if isinstance(item, dict) and item.get("caller_static") is not None
                        ],
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )[:6]
                    top_text = ", ".join(f"{addr} x{calls}" for addr, calls in top)
                    if top_text:
                        evidence.append(f"native rng_callers at focus tick: {top_text}")

                stage_paths: list[str] = []
                seen_paths: set[str] = set()
                for stage_name, _calls in top_stages:
                    for path in RNG_STAGE_TO_PORT_PATHS.get(str(stage_name), ()):
                        if path in seen_paths:
                            continue
                        seen_paths.add(path)
                        stage_paths.append(path)
                if not stage_paths:
                    stage_paths = list(
                        _port_paths_for_native_functions(
                            ("projectile_update", "creature_apply_damage", "creature_update_all")
                        )
                    )

                leads.append(
                    InvestigationLead(
                        title="Focus tick has a rewrite-only RNG burst",
                        evidence=tuple(evidence),
                        native_functions=("projectile_update", "creature_apply_damage", "creature_update_all"),
                        code_paths=tuple(stage_paths),
                    )
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
        zero_rand_damage_ticks = [
            int(tick)
            for tick in rng_zero_ticks
            if _int_or(raw_debug_by_tick.get(int(tick), {}).get("creature_damage_count"), 0) > 0
        ]
        if zero_rand_damage_ticks:
            damage_sample = ", ".join(str(tick) for tick in zero_rand_damage_ticks[:8])
            evidence.append(
                "native creature_apply_damage hooks are present on zero-rand ticks: "
                + damage_sample
                + (" ..." if len(zero_rand_damage_ticks) > 8 else "")
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
            )
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
                f"(delta={xp_onset.delta!r}), suggesting movement/targeting drift is upstream"
            )
        leads.append(
            InvestigationLead(
                title="Upstream movement drift before gameplay outcome mismatch",
                evidence=tuple(evidence),
                native_functions=("creature_update_all",),
                code_paths=_port_paths_for_native_functions(("creature_update_all",)),
            )
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
            )
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
        focus_raw = raw_debug_by_tick.get(int(xp_onset.tick), {})
        focus_damage_count = _int_or(focus_raw.get("creature_damage_count"), 0)
        if focus_damage_count > 0:
            evidence.append(f"native creature_apply_damage count at XP-onset tick: {focus_damage_count}")
            damage_head = focus_raw.get("creature_damage_head")
            if isinstance(damage_head, list) and damage_head:
                preview = []
                for item in damage_head[:4]:
                    if not isinstance(item, dict):
                        continue
                    preview.append(
                        "idx="
                        + str(_int_or(item.get("creature_index"), -1))
                        + "/type="
                        + str(_int_or(item.get("damage_type"), -1))
                        + "/k="
                        + str(1 if bool(item.get("killed")) else 0)
                    )
                if preview:
                    evidence.append("native creature_apply_damage head: " + ", ".join(preview))
        else:
            evidence.append("native creature_apply_damage count at XP-onset tick: 0")
        focus_callers = focus_raw.get("rng_callers")
        if isinstance(focus_callers, list) and focus_callers:
            top = sorted(
                [
                    (str(item.get("caller_static")), _int_or(item.get("calls"), 1))
                    for item in focus_callers
                    if isinstance(item, dict) and item.get("caller_static") is not None
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
            )
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
            )
        )

    return leads


def _build_window_rows(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, dict[str, object]],
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
        raw = raw_debug_by_tick.get(int(tick), {})
        exp_player = exp.players[0] if exp.players else None
        act_player = act.players[0] if act.players else None
        before = _int_or(act.rng_marks.get("before_world_step"))
        after = _primary_rng_after(act)
        expected_rand_calls = _int_or(raw.get("rng_rand_calls"), _int_or(exp.rng_marks.get("rand_calls")))
        actual_rand_calls = _actual_rand_calls_for_checkpoint(act)
        rand_calls_delta: int | None = None
        if expected_rand_calls >= 0 and actual_rand_calls is not None:
            rand_calls_delta = int(actual_rand_calls) - int(expected_rand_calls)

        rows.append(
            {
                "tick": int(tick),
                "expected_weapon": _int_or(getattr(exp_player, "weapon_id", -1)),
                "actual_weapon": _int_or(getattr(act_player, "weapon_id", -1)),
                "expected_ammo": _float_or(getattr(exp_player, "ammo", 0.0)),
                "actual_ammo": _float_or(getattr(act_player, "ammo", 0.0)),
                "expected_xp": _int_or(getattr(exp_player, "experience", -1)),
                "actual_xp": _int_or(getattr(act_player, "experience", -1)),
                "expected_score": int(exp.score_xp),
                "actual_score": int(act.score_xp),
                "expected_creatures": int(exp.creature_count),
                "actual_creatures": int(act.creature_count),
                "expected_rand_calls": int(expected_rand_calls),
                "actual_rand_calls": actual_rand_calls,
                "rand_calls_delta": rand_calls_delta,
                "capture_rng_seq_first": _int_or(raw.get("rng_seq_first"), -1),
                "capture_rng_seq_last": _int_or(raw.get("rng_seq_last"), -1),
                "capture_rng_seed_epoch_enter": _int_or(raw.get("rng_seed_epoch_enter"), -1),
                "capture_rng_seed_epoch_last": _int_or(raw.get("rng_seed_epoch_last"), -1),
                "capture_rng_outside_before_calls": _int_or(raw.get("rng_outside_before_calls"), -1),
                "capture_rng_mirror_mismatch_total": _int_or(raw.get("rng_mirror_mismatch_total"), -1),
                "actual_ps_draws": _int_or(act.rng_marks.get("ps_draws_total")),
                "actual_rng_changed": bool(before >= 0 and after >= 0 and before != after),
                "expected_pickups": int(exp.events.pickup_count),
                "actual_pickups": int(act.events.pickup_count),
                "expected_sfx": int(exp.events.sfx_count),
                "actual_sfx": int(act.events.sfx_count),
                "capture_bonus_spawn_events": _int_or(raw.get("spawn_bonus_count")),
                "capture_death_events": _int_or(raw.get("spawn_death_count")),
                "capture_projectile_find_hits": _int_or(raw.get("projectile_find_hit_count"), -1),
                "actual_deaths": int(len(act.deaths)),
                "actual_hits": int(act.events.hit_count),
            }
        )
    return rows


def _print_window(rows: list[dict[str, object]]) -> None:
    print()
    print(
        "tick  w(e/a)   ammo(e/a)  xp(e/a)   score(e/a)  creatures(e/a)"
        "  rand_calls(e/a/d)  ps_draws(a)  rng_changed(a)  bonus_spawn(e)  deaths(e/a)  p_hits(e/a)  pickups(e/a)  sfx(e/a)"
    )
    for row in rows:
        expected_rand_calls = _int_or(row.get("expected_rand_calls"), -1)
        expected_rand_text = _fmt_opt_int(expected_rand_calls if expected_rand_calls >= 0 else None, width=6)
        actual_rand_text = _fmt_opt_int(row.get("actual_rand_calls"), width=6)
        rand_delta_text = _fmt_opt_int(row.get("rand_calls_delta"), width=6)
        print(
            f"{int(row['tick']):4d}  "
            f"{int(row['expected_weapon']):2d}/{int(row['actual_weapon']):2d}    "
            f"{float(row['expected_ammo']):6.2f}/{float(row['actual_ammo']):6.2f}  "
            f"{int(row['expected_xp']):5d}/{int(row['actual_xp']):5d}  "
            f"{int(row['expected_score']):6d}/{int(row['actual_score']):6d}  "
            f"{int(row['expected_creatures']):4d}/{int(row['actual_creatures']):4d}    "
            f"{expected_rand_text}/{actual_rand_text}/{rand_delta_text}     "
            f"{int(row['actual_ps_draws']):6d}        "
            f"{'Y' if bool(row['actual_rng_changed']) else 'N':>1}           "
            f"{int(row['capture_bonus_spawn_events']):4d}       "
            f"{int(row['capture_death_events']):3d}/{int(row['actual_deaths']):3d}      "
            f"{int(row['capture_projectile_find_hits']):3d}/{int(row['actual_hits']):3d}      "
            f"{int(row['expected_pickups']):3d}/{int(row['actual_pickups']):3d}      "
            f"{int(row['expected_sfx']):3d}/{int(row['actual_sfx']):3d}"
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report the next original-capture divergence with context window + RNG diagnostics.",
    )
    parser.add_argument(
        "capture",
        type=Path,
        help="original capture sidecar (.json/.json.gz) or raw gameplay trace (.jsonl/.jsonl.gz)",
    )
    parser.add_argument("--window", type=int, default=20, help="ticks before/after focus tick to display")
    parser.add_argument("--max-ticks", type=int, default=None, help="optional replay tick cap")
    parser.add_argument("--seed", type=int, default=None, help="optional fixed replay seed override")
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
    parser.add_argument("--json-out", type=Path, default=None, help="optional machine-readable report output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    capture_path = Path(args.capture)

    capture = load_original_capture_sidecar(capture_path)
    expected, actual, run_result = _run_actual_checkpoints(
        capture,
        max_ticks=args.max_ticks,
        seed=args.seed,
        inter_tick_rand_draws=args.inter_tick_rand_draws,
    )
    capture_sample_creature_counts = _load_capture_sample_creature_counts(capture_path)
    divergence = _find_first_divergence(
        expected,
        actual,
        float_abs_tol=float(args.float_abs_tol),
        max_field_diffs=max(1, int(args.max_field_diffs)),
        capture_sample_creature_counts=capture_sample_creature_counts,
    )

    print(f"capture={capture_path}")
    print(
        f"ticks(expected/actual)={len(expected)}/{len(actual)}"
        f" sample_rate={int(capture.sample_rate)} run_ticks={int(run_result.ticks)}"
        f" run_score_xp={int(run_result.score_xp)} run_kills={int(run_result.creature_kill_count)}"
    )

    replay = convert_original_capture_to_replay(capture, seed=args.seed)
    print(
        f"mode={int(replay.header.game_mode_id)} tick_rate={int(replay.header.tick_rate)}"
        f" player_count={int(replay.header.player_count)} seed={int(replay.header.seed)}"
    )
    print(
        "status="
        f"(quest_unlock_index={int(replay.header.status.quest_unlock_index)}, "
        f"quest_unlock_index_full={int(replay.header.status.quest_unlock_index_full)}, "
        f"weapon_usage_counts_len={len(replay.header.status.weapon_usage_counts)})"
    )

    run_summary_events: list[RunSummaryEvent] = []
    run_summary_short_events: list[RunSummaryEvent] = []
    if bool(args.run_summary) or bool(args.run_summary_short):
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
    raw_debug_by_tick = _load_raw_tick_debug(capture_path, window_ticks | lead_ticks | {focus_tick})
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
    )
    _print_investigation_leads(leads)

    focus_raw = raw_debug_by_tick.get(focus_tick, {})
    focus_actual_ckpt = actual_by_tick.get(int(focus_tick))
    if focus_raw or focus_actual_ckpt is not None:
        print()
        print("focus_capture_debug:")
    if focus_raw:
        print(
            "  "
            f"spawn_bonus_events={_int_or(focus_raw.get('spawn_bonus_count'))} "
            f"spawn_death_events={_int_or(focus_raw.get('spawn_death_count'))} "
            f"creature_damage_events={_int_or(focus_raw.get('creature_damage_count'))} "
            f"rand_calls={_int_or(focus_raw.get('rng_rand_calls'))} "
            f"rand_last={focus_raw.get('rng_rand_last')!r}"
        )
        rng_seq_first = _int_or(focus_raw.get("rng_seq_first"), -1)
        rng_seq_last = _int_or(focus_raw.get("rng_seq_last"), -1)
        rng_seed_epoch_enter = _int_or(focus_raw.get("rng_seed_epoch_enter"), -1)
        rng_seed_epoch_last = _int_or(focus_raw.get("rng_seed_epoch_last"), -1)
        rng_outside_before_calls = _int_or(focus_raw.get("rng_outside_before_calls"), -1)
        rng_mirror_mismatch_total = _int_or(focus_raw.get("rng_mirror_mismatch_total"), -1)
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
                f"capture_rng_mirror_mismatch_total={int(rng_mirror_mismatch_total)}"
            )
        callers = focus_raw.get("rng_callers")
        if isinstance(callers, list) and callers:
            print(f"  capture_rand_callers_top={callers[:6]!r}")
        top_bonus = focus_raw.get("spawn_top_bonus_callers")
        if isinstance(top_bonus, list) and top_bonus:
            print(f"  capture_bonus_spawn_callers_top={top_bonus[:6]!r}")
        top_damage = focus_raw.get("spawn_top_creature_damage_callers")
        if isinstance(top_damage, list) and top_damage:
            print(f"  capture_creature_damage_callers_top={top_damage[:6]!r}")
        damage_head = focus_raw.get("creature_damage_head")
        if isinstance(damage_head, list) and damage_head:
            print(f"  capture_creature_damage_head={damage_head[:6]!r}")
        projectile_find_hit_count = _int_or(focus_raw.get("projectile_find_hit_count"), -1)
        if projectile_find_hit_count >= 0:
            print(
                "  "
                f"capture_projectile_find_hit_count={int(projectile_find_hit_count)} "
                f"capture_projectile_find_hit_corpse_count={_int_or(focus_raw.get('projectile_find_hit_corpse_count'), -1)}"
            )
        top_projectile_hits = focus_raw.get("spawn_top_projectile_find_hit_callers")
        if isinstance(top_projectile_hits, list) and top_projectile_hits:
            print(f"  capture_projectile_find_hit_callers_top={top_projectile_hits[:6]!r}")
        projectile_find_hit_head = focus_raw.get("projectile_find_hit_head")
        if isinstance(projectile_find_hit_head, list) and projectile_find_hit_head:
            print(f"  capture_projectile_find_hit_head={projectile_find_hit_head[:6]!r}")
        secondary_spawn_count = _int_or(focus_raw.get("secondary_projectile_spawn_count"), 0)
        if secondary_spawn_count > 0:
            print(f"  capture_secondary_projectile_spawn_count={secondary_spawn_count}")
        secondary_spawn_head = focus_raw.get("secondary_projectile_spawn_head")
        if isinstance(secondary_spawn_head, list) and secondary_spawn_head:
            print(f"  capture_secondary_projectile_spawn_head={secondary_spawn_head[:6]!r}")
        before_player = focus_raw.get("before_player0")
        if isinstance(before_player, dict):
            print(f"  before_player0={before_player!r}")
        player_keys = _extract_player_input_keys(focus_raw, player_index=0)
        if player_keys:
            print(f"  input_player_keys[0]={player_keys!r}")
        sample_counts = focus_raw.get("sample_counts")
        if isinstance(sample_counts, dict) and sample_counts:
            print(f"  sample_counts={sample_counts!r}")
        sample_secondary_head = focus_raw.get("sample_secondary_head")
        if isinstance(sample_secondary_head, list) and sample_secondary_head:
            print(f"  sample_secondary_head={sample_secondary_head[:6]!r}")
        sample_creatures_head = focus_raw.get("sample_creatures_head")
        if isinstance(sample_creatures_head, list) and sample_creatures_head:
            print(f"  sample_creatures_head={sample_creatures_head[:6]!r}")
    if focus_actual_ckpt is not None:
        actual_rand_calls = _actual_rand_calls_for_checkpoint(focus_actual_ckpt)
        stage_calls = _actual_rand_stage_calls(focus_actual_ckpt)
        print(
            "  "
            f"rewrite_rand_calls={actual_rand_calls!r} "
            f"rewrite_rand_stage_calls={stage_calls!r}"
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
        if int(row["expected_rand_calls"]) == 0 and bool(row["actual_rng_changed"])
    ]
    if zero_rand_consumed:
        print()
        print(
            "hint: expected rand_calls=0 but actual RNG state changed on ticks: "
            + ", ".join(str(int(row["tick"])) for row in zero_rand_consumed[:12])
        )

    if args.json_out is not None:
        payload = {
            "capture": str(capture_path),
            "summary": {
                "expected_count": len(expected),
                "actual_count": len(actual),
                "sample_rate": int(capture.sample_rate),
                "run_ticks": int(run_result.ticks),
                "run_score_xp": int(run_result.score_xp),
                "run_kills": int(run_result.creature_kill_count),
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
            "window_rows": rows,
            "investigation_leads": [asdict(lead) for lead in leads],
            "focus_capture_debug": focus_raw,
            "focus_rewrite_debug": (
                {
                    "rand_calls": _actual_rand_calls_for_checkpoint(focus_actual_ckpt),
                    "rand_stage_calls": _actual_rand_stage_calls(focus_actual_ckpt),
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
        if bool(args.run_summary) or bool(args.run_summary_short):
            payload["run_summary_events"] = [asdict(event) for event in run_summary_events]
            payload["run_summary_short_events"] = [asdict(event) for event in run_summary_short_events]
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print()
        print(f"json_report={args.json_out}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
