from __future__ import annotations

import argparse
import bisect
import functools
import gzip
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
import re

from crimson.game_modes import GameMode
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


NATIVE_FUNCTION_TO_PORT_PATHS: dict[str, tuple[str, ...]] = {
    "creature_update_all": (
        "src/crimson/creatures/runtime.py",
        "src/crimson/creatures/ai.py",
    ),
    "creature_apply_damage": (
        "src/crimson/creatures/damage.py",
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
}


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
        creature_damage_head = event_heads_obj.get("creature_damage")
        creature_damage_head_obj = creature_damage_head if isinstance(creature_damage_head, list) else []
        projectile_spawn_head = event_heads_obj.get("projectile_spawn")
        projectile_spawn_head_obj = projectile_spawn_head if isinstance(projectile_spawn_head, list) else []
        creature_death_head = event_heads_obj.get("creature_death")
        creature_death_head_obj = creature_death_head if isinstance(creature_death_head, list) else []
        bonus_spawn_head = event_heads_obj.get("bonus_spawn")
        bonus_spawn_head_obj = bonus_spawn_head if isinstance(bonus_spawn_head, list) else []
        rng_callers_top = rng_top_obj.get("callers")
        rng_callers_top_obj = rng_callers_top if isinstance(rng_callers_top, list) else []
        rng_rand_calls = _int_or(rng_obj.get("rand_calls"))
        if rng_rand_calls < 0:
            rng_rand_calls = _int_or(rng_top_obj.get("calls"))
        rng_rand_last = rng_obj.get("rand_last")
        if rng_rand_last is None:
            rng_rand_last = rng_top_obj.get("last_value")
        rng_callers = rng_obj.get("rand_callers") if isinstance(rng_obj.get("rand_callers"), list) else []
        if not rng_callers:
            rng_callers = rng_callers_top_obj

        out[int(tick)] = {
            "rng_rand_calls": rng_rand_calls,
            "rng_rand_last": rng_rand_last,
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
            "creature_death_head": creature_death_head_obj,
            "bonus_spawn_head": bonus_spawn_head_obj,
            "spawn_top_creature_damage_callers": (
                spawn_obj.get("top_creature_damage_callers")
                if isinstance(spawn_obj.get("top_creature_damage_callers"), list)
                else []
            ),
            "lifecycle_before_hash": lifecycle_obj.get("before_hash"),
            "lifecycle_after_hash": lifecycle_obj.get("after_hash"),
            "lifecycle_before_count": _int_or(lifecycle_obj.get("before_count")),
            "lifecycle_after_count": _int_or(lifecycle_obj.get("after_count")),
            "before_player0": before_players_obj[0] if before_players_obj else None,
            "input_player_keys": obj.get("input_player_keys") if isinstance(obj.get("input_player_keys"), list) else [],
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
    actual: list[ReplayCheckpoint] = []

    mode = int(replay.header.game_mode_id)
    if mode == int(GameMode.SURVIVAL):
        run_result = run_survival_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=False,
            trace_rng=True,
            checkpoint_use_world_step_creature_count=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
        )
    elif mode == int(GameMode.RUSH):
        run_result = run_rush_replay(
            replay,
            max_ticks=max_ticks,
            trace_rng=True,
            checkpoint_use_world_step_creature_count=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
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
) -> Divergence | None:
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}

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
    before = _int_or(ckpt.rng_marks.get("before_world_step"))
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
                "expected_rand_calls": _int_or(raw.get("rng_rand_calls"), _int_or(exp.rng_marks.get("rand_calls"))),
                "actual_ps_draws": _int_or(act.rng_marks.get("ps_draws_total")),
                "actual_rng_changed": bool(before >= 0 and after >= 0 and before != after),
                "expected_pickups": int(exp.events.pickup_count),
                "actual_pickups": int(act.events.pickup_count),
                "expected_sfx": int(exp.events.sfx_count),
                "actual_sfx": int(act.events.sfx_count),
                "capture_bonus_spawn_events": _int_or(raw.get("spawn_bonus_count")),
                "capture_death_events": _int_or(raw.get("spawn_death_count")),
            }
        )
    return rows


def _print_window(rows: list[dict[str, object]]) -> None:
    print()
    print(
        "tick  w(e/a)   ammo(e/a)  xp(e/a)   score(e/a)  creatures(e/a)"
        "  rand_calls(e)  ps_draws(a)  rng_changed(a)  bonus_spawn(e)  pickups(e/a)  sfx(e/a)"
    )
    for row in rows:
        print(
            f"{int(row['tick']):4d}  "
            f"{int(row['expected_weapon']):2d}/{int(row['actual_weapon']):2d}    "
            f"{float(row['expected_ammo']):6.2f}/{float(row['actual_ammo']):6.2f}  "
            f"{int(row['expected_xp']):5d}/{int(row['actual_xp']):5d}  "
            f"{int(row['expected_score']):6d}/{int(row['actual_score']):6d}  "
            f"{int(row['expected_creatures']):4d}/{int(row['actual_creatures']):4d}    "
            f"{int(row['expected_rand_calls']):6d}      "
            f"{int(row['actual_ps_draws']):6d}        "
            f"{'Y' if bool(row['actual_rng_changed']) else 'N':>1}           "
            f"{int(row['capture_bonus_spawn_events']):4d}       "
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
    divergence = _find_first_divergence(
        expected,
        actual,
        float_abs_tol=float(args.float_abs_tol),
        max_field_diffs=max(1, int(args.max_field_diffs)),
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
    if focus_raw:
        print()
        print("focus_capture_debug:")
        print(
            "  "
            f"spawn_bonus_events={_int_or(focus_raw.get('spawn_bonus_count'))} "
            f"spawn_death_events={_int_or(focus_raw.get('spawn_death_count'))} "
            f"creature_damage_events={_int_or(focus_raw.get('creature_damage_count'))} "
            f"rand_calls={_int_or(focus_raw.get('rng_rand_calls'))} "
            f"rand_last={focus_raw.get('rng_rand_last')!r}"
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
        before_player = focus_raw.get("before_player0")
        if isinstance(before_player, dict):
            print(f"  before_player0={before_player!r}")
        player_keys = _extract_player_input_keys(focus_raw, player_index=0)
        if player_keys:
            print(f"  input_player_keys[0]={player_keys!r}")

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
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print()
        print(f"json_report={args.json_out}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
