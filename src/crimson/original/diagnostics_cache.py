from __future__ import annotations

import argparse
import copy
from collections import Counter, OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
from typing import Any, TypeVar, cast

import msgspec
from platformdirs import PlatformDirs

import crimson.projectiles.runtime.collision as projectiles_mod
import crimson.projectiles.runtime.projectile_pool as projectile_pool_mod
import crimson.projectiles.runtime.secondary_pool as secondary_pool_mod
import crimson.sim.presentation_step as presentation_step_mod
from crimson.bonuses import bonus_label
from crimson.game_modes import GameMode
from crimson.paths import APP_NAME
from crimson.perks import perk_label
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.sim.runners.common import (
    build_damage_scale_by_type,
    build_empty_fx_queues,
    reset_players,
    status_from_snapshot,
)
from crimson.sim.runners.survival import (
    _apply_tick_events,
    _partition_tick_events,
    _resolve_dt_frame,
    _should_apply_world_dt_steps_for_replay,
)
from crimson.sim.sessions import SurvivalDeterministicSession
from crimson.sim.world_state import WorldState
from crimson.weapons import WEAPON_BY_ID

from .capture import (
    build_capture_dt_frame_overrides,
    build_capture_dt_frame_ms_i32_overrides,
    convert_capture_to_replay,
    load_capture,
)
from .focus_trace import (
    CollisionRow,
    DecalHookRow,
    FocusTraceReport,
    _build_fire_bullets_loop_parity,
    _build_native_caller_gaps,
    _collect_creature_presence_diffs,
    _collect_projectile_presence_diffs,
    _decode_inputs_for_tick,
    _load_capture_events,
    _projectile_snapshot,
    _summarize_creature_diffs,
    _summarize_projectile_diffs,
    _summarize_rng_alignment,
)
from .schema import (
    CaptureEventHeadBonusApply,
    CaptureEventHeadBonusSpawn,
    CaptureEventHeadCreatureDamage,
    CaptureEventHeadCreatureDeath,
    CaptureEventHeadProjectileFindHit,
    CaptureEventHeadProjectileFindQuery,
    CaptureEventHeadProjectileSpawn,
    CaptureEventHeadSecondaryProjectileSpawn,
    CaptureEventHeadStateTransition,
    CaptureEventHeadWeaponAssign,
    CaptureFile,
    CaptureTick,
)

_CACHE_SCHEMA_VERSION = 1
_CAPTURE_BLOB_NAME = "capture.msgpack.gz"
_TICK_LITE_BLOB_NAME = "tick_index.msgpack.gz"
_META_NAME = "meta.json"
_DEFAULT_IDLE_TIMEOUT_SECONDS = 15 * 60
_FOCUS_NEAR_TICK_WINDOW = 256
_FOCUS_ANCHOR_INTERVAL = 64
_FOCUS_ANCHOR_LIMIT = 32
_DecodedT = TypeVar("_DecodedT")


class CaptureFingerprint(msgspec.Struct, forbid_unknown_fields=True):
    resolved_path: str
    size: int
    mtime_ns: int
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ReplayKey:
    max_ticks: int | None
    seed: int | None
    inter_tick_rand_draws: int
    aim_scheme_overrides: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class FocusKey:
    inter_tick_rand_draws: int
    aim_scheme_overrides: tuple[tuple[int, int], ...]


class DaemonRequest(msgspec.Struct, forbid_unknown_fields=True):
    tool: str
    args: list[str] = msgspec.field(default_factory=list)
    cwd: str | None = None


class DaemonResponse(msgspec.Struct, forbid_unknown_fields=True):
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class TickLite(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    row: dict[str, object] = msgspec.field(default_factory=dict)


class RunSummaryEventLite(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    kind: str
    detail: str


class _CaptureMeta(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    fingerprint: CaptureFingerprint


class _TickLiteBlob(msgspec.Struct, forbid_unknown_fields=True):
    rows: list[TickLite] = msgspec.field(default_factory=list)


class _RunSummaryBlob(msgspec.Struct, forbid_unknown_fields=True):
    rows: list[RunSummaryEventLite] = msgspec.field(default_factory=list)


@dataclass(slots=True)
class _FocusStepTraceContext:
    tick: int
    near_miss_threshold: float
    rng_callsites: Counter[str]
    rng_head: list[str]
    rng_values: list[int]
    rng_values_callsites: list[str]
    collision_hits: list[CollisionRow]
    near_misses: list[CollisionRow]
    decal_hook_rows: list[DecalHookRow]
    pre_projectiles: list[dict[str, Any]]
    post_projectiles: list[dict[str, Any]]
    focus_hits: int
    focus_deaths: int
    focus_sfx: int


class _FocusRuntime:
    """Reusable survival runtime for nearby focus-tick probes."""

    def __init__(
        self,
        *,
        capture: CaptureFile,
        replay: Any,
        inter_tick_rand_draws: int,
    ) -> None:
        self.capture = capture
        self.replay = replay
        self.inter_tick_rand_draws = max(0, int(inter_tick_rand_draws))
        self.root = Path.cwd().resolve()

        self.events_by_tick, self.original_capture_replay = _load_capture_events(replay)
        self.dt_frame_overrides = build_capture_dt_frame_overrides(capture, tick_rate=int(replay.header.tick_rate))
        self.dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(capture)
        self.apply_world_dt_steps = _should_apply_world_dt_steps_for_replay(
            original_capture_replay=bool(self.original_capture_replay),
            dt_frame_overrides=self.dt_frame_overrides,
            dt_frame_ms_i32_overrides=self.dt_frame_ms_i32_overrides,
        )
        self.default_dt_frame = 1.0 / float(int(replay.header.tick_rate))
        self.outside_draws_by_tick = {
            int(item.tick_index): int(item.rng.outside_before_calls)
            for item in capture.ticks
            if int(item.rng.outside_before_calls) >= 0
        }
        if self.outside_draws_by_tick:
            first_tick_index = min(self.outside_draws_by_tick)
            self.outside_draws_by_tick[int(first_tick_index)] = 0
        self.use_outside_draws = bool(self.outside_draws_by_tick)

        self.capture_ticks_by_index: dict[int, CaptureTick] = {
            int(item.tick_index): item for item in capture.ticks
        }

        self._initial_state = self._build_initial_state()
        self.world, self.session = copy.deepcopy(self._initial_state)
        self.current_tick = -1
        self.anchors: OrderedDict[int, tuple[WorldState, SurvivalDeterministicSession]] = OrderedDict()

    def _build_initial_state(self) -> tuple[WorldState, SurvivalDeterministicSession]:
        world_size = float(self.replay.header.world_size)
        world = WorldState.build(
            world_size=world_size,
            demo_mode_active=False,
            hardcore=bool(self.replay.header.hardcore),
            difficulty_level=int(self.replay.header.difficulty_level),
            preserve_bugs=bool(self.replay.header.preserve_bugs),
        )
        reset_players(world.players, world_size=world_size, player_count=int(self.replay.header.player_count))
        world.state.status = status_from_snapshot(
            quest_unlock_index=int(self.replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(self.replay.header.status.quest_unlock_index_full),
            weapon_usage_counts=self.replay.header.status.weapon_usage_counts,
        )
        world.state.rng.srand(int(self.replay.header.seed))
        fx_queue, fx_queue_rotated = build_empty_fx_queues()
        session = SurvivalDeterministicSession(
            world=world,
            world_size=world_size,
            damage_scale_by_type=build_damage_scale_by_type(),
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            detail_preset=5,
            fx_toggle=0,
            game_tune_started=False,
            apply_world_dt_steps=bool(self.apply_world_dt_steps),
            clear_fx_queues_each_tick=True,
        )
        return world, session

    def _reset(self) -> None:
        self.world, self.session = copy.deepcopy(self._initial_state)
        self.current_tick = -1

    def _store_anchor(self, tick_index: int) -> None:
        if tick_index < 0:
            return
        if (tick_index % _FOCUS_ANCHOR_INTERVAL) != 0:
            return
        self.anchors[int(tick_index)] = copy.deepcopy((self.world, self.session))
        self.anchors.move_to_end(int(tick_index), last=True)
        while len(self.anchors) > _FOCUS_ANCHOR_LIMIT:
            self.anchors.popitem(last=False)

    def _restore_nearby_anchor(self, target_tick: int) -> bool:
        if not self.anchors:
            return False
        cap = int(target_tick) - 1
        candidates = [tick for tick in self.anchors if tick <= cap]
        if not candidates:
            return False
        best = max(candidates)
        if int(target_tick) - int(best) > _FOCUS_NEAR_TICK_WINDOW:
            return False
        anchor_state = self.anchors.get(int(best))
        if anchor_state is None:
            return False
        self.world, self.session = copy.deepcopy(anchor_state)
        self.current_tick = int(best)
        return True

    def _build_capture_tick_payload(
        self,
        tick: CaptureTick,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
        capture_creatures: list[dict[str, Any]] = []
        capture_projectiles: list[dict[str, Any]] = []
        if tick.samples is not None:
            for item in tick.samples.creatures:
                capture_creatures.append(
                    {
                        "index": int(item.index),
                        "active": int(item.active),
                        "type_id": int(item.type_id),
                        "hp": float(item.hp),
                        "hitbox_size": float(item.hitbox_size),
                        "pos": {"x": float(item.pos.x), "y": float(item.pos.y)},
                    }
                )
            for item in tick.samples.projectiles:
                capture_projectiles.append(
                    {
                        "index": int(item.index),
                        "active": int(item.active),
                        "type_id": int(item.type_id),
                        "life_timer": float(item.life_timer),
                        "damage_pool": float(item.damage_pool),
                        "pos": {"x": float(item.pos.x), "y": float(item.pos.y)},
                    }
                )

        capture_rng_head = [_rng_head_entry_to_row(entry) for entry in tick.rng.head]
        capture_rng_calls = int(tick.rng.calls)
        if capture_rng_calls < len(capture_rng_head):
            capture_rng_calls = len(capture_rng_head)
        return capture_creatures, capture_projectiles, capture_rng_head, capture_rng_calls

    def _step_tick(
        self,
        tick_index: int,
        trace: _FocusStepTraceContext | None,
    ) -> None:
        self.world.state.game_mode = int(GameMode.SURVIVAL)
        self.world.state.demo_mode_active = False

        if self.use_outside_draws:
            draws = self.outside_draws_by_tick.get(int(tick_index), self.inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                self.world.state.rng.rand()

        dt_tick = _resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(self.default_dt_frame),
            dt_frame_overrides=self.dt_frame_overrides,
        )
        dt_tick_ms_i32 = self.dt_frame_ms_i32_overrides.get(int(tick_index))

        tick_events = self.events_by_tick.get(int(tick_index), [])
        pre_step_events, post_step_events = _partition_tick_events(
            tick_events,
            defer_menu_open=bool(self.original_capture_replay),
        )

        _apply_tick_events(
            pre_step_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=self.world,
            strict_events=False,
        )
        player_inputs = _decode_inputs_for_tick(self.replay, int(tick_index))

        orig_rand = self.world.state.rng.rand
        orig_particles_rand = self.world.state.particles._rand
        orig_sprite_effects_rand = self.world.state.sprite_effects._rand
        orig_within = projectiles_mod._within_native_find_radius
        orig_within_projectile_pool = projectile_pool_mod._within_native_find_radius
        orig_within_secondary_pool = secondary_pool_mod._within_native_find_radius
        orig_run_projectile_decal_hooks = presentation_step_mod.run_projectile_decal_hooks

        try:
            if trace is not None:
                trace.pre_projectiles[:] = _projectile_snapshot(self.world)

                def traced_rand() -> int:
                    value = int(orig_rand())
                    frame = None
                    try:
                        import inspect

                        frame = inspect.currentframe()
                    except Exception:
                        frame = None
                    caller = frame.f_back if frame is not None else None
                    key = "<unknown>"
                    while caller is not None:
                        filename = Path(caller.f_code.co_filename).resolve()
                        try:
                            rel = filename.relative_to(self.root)
                        except ValueError:
                            rel = filename
                        rel_s = str(rel)
                        if "src/crimson/" in rel_s:
                            key = f"{rel_s}:{caller.f_code.co_name}:{caller.f_lineno}"
                            break
                        caller = caller.f_back
                    trace.rng_callsites[key] += 1
                    if len(trace.rng_head) < 256:
                        trace.rng_head.append(key)
                    trace.rng_values.append(int(value))
                    trace.rng_values_callsites.append(str(key))
                    return value

                def traced_within_native_find_radius(
                    *,
                    origin: Any,
                    target: Any,
                    radius: float,
                    target_size: float,
                ) -> bool:
                    dx = float(target.x) - float(origin.x)
                    dy = float(target.y) - float(origin.y)
                    dist = (dx * dx + dy * dy) ** 0.5
                    threshold = float(target_size) * 0.14285715 + 3.0
                    margin = dist - float(radius) - float(threshold)
                    hit = bool(margin < 0.0)

                    step: int | None = None
                    creature_idx: int | None = None
                    proj_index: int | None = None
                    proj_type: int | None = None
                    proj_life: float | None = None
                    try:
                        import inspect

                        frame = inspect.currentframe().f_back  # ty:ignore[possibly-missing-attribute]
                    except Exception:
                        frame = None
                    if frame is not None:
                        step = _optional_int(frame.f_locals.get("step") if "step" in frame.f_locals else None)
                        creature_idx = _optional_int(frame.f_locals.get("idx") if "idx" in frame.f_locals else None)
                        proj_index = _optional_int(
                            frame.f_locals.get("proj_index") if "proj_index" in frame.f_locals else None
                        )
                        proj = frame.f_locals.get("proj")
                        if proj is not None:
                            try:
                                proj_type = int(getattr(proj, "type_id"))
                                proj_life = float(getattr(proj, "life_timer"))
                            except Exception:
                                proj_type = None
                                proj_life = None

                    row = CollisionRow(
                        proj_index=proj_index,
                        proj_type=proj_type,
                        proj_life=proj_life,
                        step=step,
                        creature_idx=creature_idx,
                        margin=float(margin),
                        dist=float(dist),
                        radius=float(radius),
                        threshold=float(threshold),
                        hit=bool(hit),
                    )
                    if bool(hit):
                        trace.collision_hits.append(row)
                    elif 0.0 <= float(margin) <= float(trace.near_miss_threshold):
                        trace.near_misses.append(row)
                    return bool(hit)

                hook_index = 0

                def traced_run_projectile_decal_hooks(ctx: Any) -> bool:
                    nonlocal hook_index
                    before = len(trace.rng_values)
                    handled = bool(orig_run_projectile_decal_hooks(ctx))
                    after = len(trace.rng_values)
                    hit = ctx.hit
                    trace.decal_hook_rows.append(
                        DecalHookRow(
                            hook_index=int(hook_index),
                            type_id=int(hit.type_id),
                            handled=bool(handled),
                            rng_draws=max(0, int(after - before)),
                            target_x=float(hit.target.x),
                            target_y=float(hit.target.y),
                        )
                    )
                    hook_index += 1
                    return bool(handled)

                self.world.state.rng.rand = traced_rand
                self.world.state.particles._rand = traced_rand
                self.world.state.sprite_effects._rand = traced_rand
                projectiles_mod._within_native_find_radius = traced_within_native_find_radius  # type: ignore[assignment]
                projectile_pool_mod._within_native_find_radius = traced_within_native_find_radius  # type: ignore[assignment]
                secondary_pool_mod._within_native_find_radius = traced_within_native_find_radius  # type: ignore[assignment]
                presentation_step_mod.run_projectile_decal_hooks = traced_run_projectile_decal_hooks  # type: ignore[assignment]

            tick_result = self.session.step_tick(
                dt_frame=float(dt_tick),
                dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
                inputs=player_inputs,
                trace_rng=False,
            )

            if trace is not None:
                trace.post_projectiles[:] = _projectile_snapshot(self.world)
                trace.focus_hits = int(len(tick_result.step.events.hits))
                trace.focus_deaths = int(len(tick_result.step.events.deaths))
                trace.focus_sfx = int(len(tick_result.step.events.sfx))

            if post_step_events:
                _apply_tick_events(
                    post_step_events,
                    tick_index=int(tick_index),
                    dt_frame=float(dt_tick),
                    world=self.world,
                    strict_events=False,
                )
        finally:
            self.world.state.rng.rand = orig_rand
            self.world.state.particles._rand = orig_particles_rand
            self.world.state.sprite_effects._rand = orig_sprite_effects_rand
            projectiles_mod._within_native_find_radius = orig_within
            projectile_pool_mod._within_native_find_radius = orig_within_projectile_pool
            secondary_pool_mod._within_native_find_radius = orig_within_secondary_pool
            presentation_step_mod.run_projectile_decal_hooks = orig_run_projectile_decal_hooks

        if not self.use_outside_draws:
            for _ in range(max(0, int(self.inter_tick_rand_draws))):
                self.world.state.rng.rand()

    def trace_tick(self, *, tick: int, near_miss_threshold: float) -> FocusTraceReport:
        target_tick = int(tick)
        if target_tick < 0:
            raise ValueError(f"tick must be non-negative (got {target_tick})")

        capture_tick = self.capture_ticks_by_index.get(int(target_tick))
        if capture_tick is None:
            raise ValueError(f"capture tick {target_tick} not found")

        if self.current_tick >= target_tick:
            if not self._restore_nearby_anchor(target_tick):
                self._reset()

        if self.current_tick >= 0 and (target_tick - self.current_tick) > _FOCUS_NEAR_TICK_WINDOW:
            self._reset()

        trace_ctx = _FocusStepTraceContext(
            tick=int(target_tick),
            near_miss_threshold=max(0.0, float(near_miss_threshold)),
            rng_callsites=Counter(),
            rng_head=[],
            rng_values=[],
            rng_values_callsites=[],
            collision_hits=[],
            near_misses=[],
            decal_hook_rows=[],
            pre_projectiles=[],
            post_projectiles=[],
            focus_hits=0,
            focus_deaths=0,
            focus_sfx=0,
        )

        for tick_index in range(int(self.current_tick) + 1, int(target_tick) + 1):
            is_focus_tick = int(tick_index) == int(target_tick)
            self._step_tick(int(tick_index), trace_ctx if is_focus_tick else None)
            self.current_tick = int(tick_index)
            self._store_anchor(int(tick_index))

        trace_ctx.near_misses.sort(key=lambda row: float(row.margin))
        trace_ctx.collision_hits.sort(
            key=lambda row: (int(row.proj_index or -1), int(row.step or -1), int(row.creature_idx or -1))
        )

        capture_creatures, capture_projectiles, capture_rng_head, capture_rng_calls = self._build_capture_tick_payload(capture_tick)
        creature_diffs_top = _summarize_creature_diffs(capture_creatures, self.world)
        projectile_diffs_top = _summarize_projectile_diffs(capture_projectiles, self.world)
        creature_capture_only, creature_rewrite_only = _collect_creature_presence_diffs(capture_creatures, self.world)
        projectile_capture_only, projectile_rewrite_only = _collect_projectile_presence_diffs(capture_projectiles, self.world)
        rng_alignment = _summarize_rng_alignment(
            capture_rng_head=capture_rng_head,
            capture_rng_calls=int(capture_rng_calls),
            rewrite_rng_values=trace_ctx.rng_values,
            rewrite_rng_callsites=trace_ctx.rng_values_callsites,
        )
        native_caller_gaps_top = _build_native_caller_gaps(rng_alignment)
        fire_bullets_loop_parity = _build_fire_bullets_loop_parity(rng_alignment)

        return FocusTraceReport(
            tick=int(target_tick),
            hits=int(trace_ctx.focus_hits),
            deaths=int(trace_ctx.focus_deaths),
            sfx=int(trace_ctx.focus_sfx),
            rand_calls_total=int(sum(trace_ctx.rng_callsites.values())),
            rng_callsites_top=list(trace_ctx.rng_callsites.most_common(64)),
            rng_callsites_head=list(trace_ctx.rng_head),
            collision_hits=trace_ctx.collision_hits,
            collision_near_misses=trace_ctx.near_misses,
            pre_projectiles=trace_ctx.pre_projectiles,
            post_projectiles=trace_ctx.post_projectiles,
            capture_projectiles=list(capture_projectiles),
            capture_creatures=list(capture_creatures),
            creature_diffs_top=creature_diffs_top,
            creature_capture_only=creature_capture_only,
            creature_rewrite_only=creature_rewrite_only,
            projectile_diffs_top=projectile_diffs_top,
            projectile_capture_only=projectile_capture_only,
            projectile_rewrite_only=projectile_rewrite_only,
            decal_hook_rows=trace_ctx.decal_hook_rows,
            rng_alignment=rng_alignment,
            native_caller_gaps_top=native_caller_gaps_top,
            fire_bullets_loop_parity=fire_bullets_loop_parity,
        )


def cache_enabled() -> bool:
    raw = str(os.environ.get("CRIMSON_ORIGINAL_CACHE", "1")).strip().lower()
    return raw not in {"0", "false", "off", "no"}


def _cache_dirs() -> PlatformDirs:
    return PlatformDirs(appname=APP_NAME, appauthor=False)


def default_cache_root() -> Path:
    return Path(_cache_dirs().user_cache_path) / "original-diagnostics"


def cache_root() -> Path:
    override = os.environ.get("CRIMSON_ORIGINAL_CACHE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return default_cache_root().resolve()


def socket_path() -> Path:
    override = os.environ.get("CRIMSON_ORIGINAL_CACHE_SOCKET")
    if override:
        return Path(override).expanduser().resolve()
    return cache_root() / "daemon.sock"


def idle_timeout_seconds() -> int:
    raw = os.environ.get("CRIMSON_ORIGINAL_CACHE_IDLE_TIMEOUT_SECONDS")
    if raw is None:
        return int(_DEFAULT_IDLE_TIMEOUT_SECONDS)
    try:
        parsed = int(raw)
    except ValueError:
        return int(_DEFAULT_IDLE_TIMEOUT_SECONDS)
    return max(60, int(parsed))


def normalize_override_pairs(mapping: Mapping[int, int] | None) -> tuple[tuple[int, int], ...]:
    if not mapping:
        return tuple()
    return tuple(sorted((int(player), int(scheme)) for player, scheme in mapping.items()))


def build_replay_key(
    *,
    max_ticks: int | None,
    seed: int | None,
    inter_tick_rand_draws: int,
    aim_scheme_overrides_by_player: Mapping[int, int] | None,
) -> ReplayKey:
    return ReplayKey(
        max_ticks=(None if max_ticks is None else int(max_ticks)),
        seed=(None if seed is None else int(seed)),
        inter_tick_rand_draws=max(0, int(inter_tick_rand_draws)),
        aim_scheme_overrides=normalize_override_pairs(aim_scheme_overrides_by_player),
    )


def build_focus_key(
    *,
    inter_tick_rand_draws: int,
    aim_scheme_overrides_by_player: Mapping[int, int] | None,
) -> FocusKey:
    return FocusKey(
        inter_tick_rand_draws=max(0, int(inter_tick_rand_draws)),
        aim_scheme_overrides=normalize_override_pairs(aim_scheme_overrides_by_player),
    )


def _int_or(value: object, default: int = -1) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)  # ty:ignore[invalid-argument-type]
    except Exception:
        return int(default)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(cast(Any, value))
    except Exception:
        return None


def _float_or(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)  # ty:ignore[invalid-argument-type]
    except Exception:
        return float(default)


def _cache_id_for_fingerprint(fingerprint: CaptureFingerprint) -> str:
    key = "\n".join(
        (
            str(fingerprint.resolved_path),
            str(int(fingerprint.size)),
            str(int(fingerprint.mtime_ns)),
        )
    ).encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:24]


def _meta_matches(path: Path, fingerprint: CaptureFingerprint) -> bool:
    if not path.exists():
        return False
    try:
        meta_obj = json.loads(path.read_text(encoding="utf-8"))
        meta = msgspec.convert(meta_obj, type=_CaptureMeta, strict=False)
    except Exception:
        return False
    if int(meta.schema_version) != int(_CACHE_SCHEMA_VERSION):
        return False
    cached = meta.fingerprint
    return (
        str(cached.resolved_path) == str(fingerprint.resolved_path)
        and int(cached.size) == int(fingerprint.size)
        and int(cached.mtime_ns) == int(fingerprint.mtime_ns)
    )


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp_path.write_bytes(data)
    tmp_path.replace(path)


def _atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def _write_msgpack_gz(path: Path, value: object) -> None:
    payload = msgspec.msgpack.encode(value)
    _atomic_write_bytes(path, gzip.compress(payload))


def _read_msgpack_gz(path: Path, *, type: type[_DecodedT]) -> _DecodedT:
    raw = gzip.decompress(path.read_bytes())
    return msgspec.msgpack.decode(raw, type=type)


def _read_capture(path: Path) -> CaptureFile:
    return load_capture(path)


def capture_fingerprint(path: Path, *, include_sha256: bool = False) -> CaptureFingerprint:
    resolved = Path(path).expanduser().resolve()
    stat = resolved.stat()
    sha256_hex: str | None = None
    if include_sha256:
        sha = hashlib.sha256()
        with resolved.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                sha.update(chunk)
        sha256_hex = sha.hexdigest()
    return CaptureFingerprint(
        resolved_path=str(resolved),
        size=int(stat.st_size),
        mtime_ns=int(stat.st_mtime_ns),
        sha256=sha256_hex,
    )


def _rng_head_entry_to_row(entry: Any) -> dict[str, object]:
    out: dict[str, object] = {}
    value_15 = _int_or(getattr(entry, "value_15", None), -1)
    if 0 <= value_15 <= 0x7FFF:
        out["value_15"] = int(value_15)
        out["value"] = int(value_15)
    state_before_u32 = _int_or(getattr(entry, "state_before_u32", None), -1)
    if state_before_u32 >= 0:
        out["state_before_u32"] = int(state_before_u32) & 0xFFFFFFFF
    state_after_u32 = _int_or(getattr(entry, "state_after_u32", None), -1)
    if state_after_u32 >= 0:
        out["state_after_u32"] = int(state_after_u32) & 0xFFFFFFFF
    seq = _int_or(getattr(entry, "seq", None), -1)
    if seq >= 0:
        out["seq"] = int(seq)
    tick_call_index = _int_or(getattr(entry, "tick_call_index", None), -1)
    if tick_call_index >= 0:
        out["tick_call_index"] = int(tick_call_index)
    caller_static = str(getattr(entry, "caller_static", "") or "")
    branch_id = str(getattr(entry, "branch_id", "") or "")
    caller = str(getattr(entry, "caller", "") or "")
    if caller_static:
        out["caller_static"] = caller_static
    if branch_id:
        out["branch_id"] = branch_id
    elif caller_static:
        out["branch_id"] = caller_static
    if caller:
        out["caller"] = caller
    return out


def _event_head_payload(head: Any) -> dict[str, object]:
    data = getattr(head, "data", None)
    if isinstance(data, dict):
        return {str(key): value for key, value in data.items()}
    return {}


def _build_event_heads_by_kind(tick: CaptureTick) -> dict[str, list[dict[str, object]]]:
    out: dict[str, list[dict[str, object]]] = {}
    for head in tick.event_heads:
        kind = ""
        if isinstance(head, CaptureEventHeadBonusApply):
            kind = "bonus_apply"
        elif isinstance(head, CaptureEventHeadWeaponAssign):
            kind = "weapon_assign"
        elif isinstance(head, CaptureEventHeadStateTransition):
            kind = "state_transition"
        elif isinstance(head, CaptureEventHeadCreatureDamage):
            kind = "creature_damage"
        elif isinstance(head, CaptureEventHeadProjectileSpawn):
            kind = "projectile_spawn"
        elif isinstance(head, CaptureEventHeadSecondaryProjectileSpawn):
            kind = "secondary_projectile_spawn"
        elif isinstance(head, CaptureEventHeadCreatureDeath):
            kind = "creature_death"
        elif isinstance(head, CaptureEventHeadBonusSpawn):
            kind = "bonus_spawn"
        elif isinstance(head, CaptureEventHeadProjectileFindQuery):
            kind = "projectile_find_query"
        elif isinstance(head, CaptureEventHeadProjectileFindHit):
            kind = "projectile_find_hit"
        if not kind:
            continue
        out.setdefault(kind, []).append(_event_head_payload(head))
    return out


def _build_sample_creatures_head(tick: CaptureTick) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    if tick.samples is None:
        return out
    for item in tick.samples.creatures[:6]:
        row: dict[str, object] = {
            "index": int(item.index),
            "type_id": int(item.type_id),
            "hp": float(item.hp),
            "hitbox_size": float(item.hitbox_size),
            "pos": {"x": float(item.pos.x), "y": float(item.pos.y)},
        }
        if item.ai_mode is not None:
            row["ai_mode"] = int(item.ai_mode)
        if item.link_index is not None:
            row["link_index"] = int(item.link_index)
        if item.ai7_timer_ms is not None:
            row["ai7_timer_ms"] = int(item.ai7_timer_ms)
        if item.orbit_angle is not None:
            row["orbit_angle"] = float(item.orbit_angle)
        if item.orbit_radius is not None:
            row["orbit_radius"] = float(item.orbit_radius)
        out.append(row)
    return out


def _build_sample_secondary_head(tick: CaptureTick) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    if tick.samples is None:
        return out
    for item in tick.samples.secondary_projectiles[:6]:
        out.append(
            {
                "index": int(item.index),
                "type_id": int(item.type_id),
                "target_id": int(item.target_id),
                "life_timer": float(item.life_timer),
                "pos": {"x": float(item.pos.x), "y": float(item.pos.y)},
            }
        )
    return out


def _build_tick_lite_row(tick: CaptureTick) -> dict[str, object]:
    checkpoint = tick.checkpoint
    debug = checkpoint.debug
    spawn_obj = debug.spawn if isinstance(debug.spawn, dict) else {}
    lifecycle_obj = debug.creature_lifecycle if isinstance(debug.creature_lifecycle, dict) else {}
    event_heads_obj = _build_event_heads_by_kind(tick)

    rng_marks = checkpoint.rng_marks
    rng_top = tick.rng
    rng_rand_calls = int(rng_marks.rand_calls)
    if rng_rand_calls < 0:
        rng_rand_calls = int(rng_top.calls)
    rng_rand_last = rng_marks.rand_last if rng_marks.rand_last is not None else rng_top.last_value
    rng_seq_first = int(rng_marks.rand_seq_first) if rng_marks.rand_seq_first is not None else -1
    if rng_seq_first < 0 and rng_top.seq_first is not None:
        rng_seq_first = int(rng_top.seq_first)
    rng_seq_last = int(rng_marks.rand_seq_last) if rng_marks.rand_seq_last is not None else -1
    if rng_seq_last < 0 and rng_top.seq_last is not None:
        rng_seq_last = int(rng_top.seq_last)
    rng_seed_epoch_enter = int(rng_marks.rand_seed_epoch_enter) if rng_marks.rand_seed_epoch_enter is not None else -1
    if rng_seed_epoch_enter < 0 and rng_top.seed_epoch_enter is not None:
        rng_seed_epoch_enter = int(rng_top.seed_epoch_enter)
    rng_seed_epoch_last = int(rng_marks.rand_seed_epoch_last) if rng_marks.rand_seed_epoch_last is not None else -1
    if rng_seed_epoch_last < 0 and rng_top.seed_epoch_last is not None:
        rng_seed_epoch_last = int(rng_top.seed_epoch_last)
    rng_outside_before_calls = int(rng_marks.rand_outside_before_calls)
    if rng_outside_before_calls < 0:
        rng_outside_before_calls = int(rng_top.outside_before_calls)
    rng_mirror_mismatch_total = int(rng_marks.rand_mirror_mismatch_total)
    if rng_mirror_mismatch_total < 0:
        rng_mirror_mismatch_total = int(rng_top.mirror_mismatch_total)

    rng_callers = [
        {"caller_static": str(item.caller_static), "calls": int(item.calls)} for item in rng_marks.rand_callers
    ]
    if not rng_callers:
        rng_callers = [
            {"caller_static": str(item.caller_static), "calls": int(item.calls)} for item in rng_top.callers
        ]

    rng_head_rows = [_rng_head_entry_to_row(item) for item in rng_marks.rand_head]
    if not rng_head_rows:
        rng_head_rows = [_rng_head_entry_to_row(item) for item in rng_top.head]
    rng_head_values = [_int_or(item.get("value_15"), -1) for item in rng_head_rows if _int_or(item.get("value_15"), -1) >= 0]

    creature_damage_head_obj = list(event_heads_obj.get("creature_damage", []))
    projectile_spawn_head_obj = list(event_heads_obj.get("projectile_spawn", []))
    secondary_projectile_spawn_head_obj = list(event_heads_obj.get("secondary_projectile_spawn", []))
    creature_death_head_obj = list(event_heads_obj.get("creature_death", []))
    bonus_spawn_head_obj = list(event_heads_obj.get("bonus_spawn", []))
    projectile_find_query_head_obj = list(event_heads_obj.get("projectile_find_query", []))
    projectile_find_hit_head_obj = list(event_heads_obj.get("projectile_find_hit", []))

    projectile_find_query_miss_count = _int_or(
        spawn_obj.get("event_count_projectile_find_query_miss"),
        sum(
            1
            for item in projectile_find_query_head_obj
            if isinstance(item, dict)
            and (
                str(item.get("result_kind")) == "miss"
                or _int_or(item.get("result_creature_index"), -1) < 0
            )
        ),
    )
    projectile_find_query_owner_collision_count = _int_or(
        spawn_obj.get("event_count_projectile_find_query_owner_collision"),
        sum(
            1
            for item in projectile_find_query_head_obj
            if isinstance(item, dict)
            and (
                bool(item.get("owner_collision"))
                or str(item.get("result_kind")) == "owner_collision"
            )
        ),
    )

    sample_counts = {
        "creatures": (len(tick.samples.creatures) if tick.samples is not None else -1),
        "projectiles": (len(tick.samples.projectiles) if tick.samples is not None else -1),
        "secondary_projectiles": (len(tick.samples.secondary_projectiles) if tick.samples is not None else -1),
        "bonuses": (len(tick.samples.bonuses) if tick.samples is not None else -1),
    }

    before_player0: dict[str, object] | None = None
    before_players = debug.before_players
    if before_players:
        player = before_players[0]
        before_player0 = {
            "pos": {"x": float(player.pos.x), "y": float(player.pos.y)},
            "health": float(player.health),
            "weapon_id": int(player.weapon_id),
            "ammo": float(player.ammo),
            "experience": int(player.experience),
            "level": int(player.level),
            "bonus_timers": {str(key): int(value) for key, value in player.bonus_timers.items()},
        }
    elif tick.before is not None and tick.before.players:
        top_player = tick.before.players[0]
        if isinstance(top_player, dict):
            before_player0 = {str(key): value for key, value in top_player.items()}

    input_player_keys = [
        {
            "player_index": int(row.player_index),
            "move_forward_pressed": row.move_forward_pressed,
            "move_backward_pressed": row.move_backward_pressed,
            "turn_left_pressed": row.turn_left_pressed,
            "turn_right_pressed": row.turn_right_pressed,
            "fire_down": row.fire_down,
            "fire_pressed": row.fire_pressed,
            "reload_pressed": row.reload_pressed,
        }
        for row in tick.input_player_keys
    ]

    top_bonus_spawn_callers_obj = spawn_obj.get("top_bonus_spawn_callers")
    top_bonus_spawn_callers = list(top_bonus_spawn_callers_obj) if isinstance(top_bonus_spawn_callers_obj, list) else []
    top_creature_damage_callers_obj = spawn_obj.get("top_creature_damage_callers")
    top_creature_damage_callers = (
        list(top_creature_damage_callers_obj) if isinstance(top_creature_damage_callers_obj, list) else []
    )
    top_projectile_find_hit_callers_obj = spawn_obj.get("top_projectile_find_hit_callers")
    top_projectile_find_hit_callers = (
        list(top_projectile_find_hit_callers_obj) if isinstance(top_projectile_find_hit_callers_obj, list) else []
    )
    top_projectile_find_query_callers_obj = spawn_obj.get("top_projectile_find_query_callers")
    top_projectile_find_query_callers = (
        list(top_projectile_find_query_callers_obj) if isinstance(top_projectile_find_query_callers_obj, list) else []
    )

    row: dict[str, object] = {
        "rng_rand_calls": int(rng_rand_calls),
        "rng_head_len": len(rng_head_rows),
        "rng_stream_rows": rng_head_rows,
        "rng_head_values": rng_head_values,
        "rng_rand_last": rng_rand_last,
        "rng_seq_first": int(rng_seq_first),
        "rng_seq_last": int(rng_seq_last),
        "rng_seed_epoch_enter": int(rng_seed_epoch_enter),
        "rng_seed_epoch_last": int(rng_seed_epoch_last),
        "rng_outside_before_calls": int(rng_outside_before_calls),
        "rng_mirror_mismatch_total": int(rng_mirror_mismatch_total),
        "rng_callers": rng_callers,
        "spawn_bonus_count": _int_or(spawn_obj.get("event_count_bonus_spawn")),
        "spawn_death_count": _int_or(spawn_obj.get("event_count_death")),
        "spawn_top_bonus_callers": top_bonus_spawn_callers,
        "creature_damage_count": _int_or(
            int(tick.event_counts.creature_damage),
            _int_or(spawn_obj.get("event_count_creature_damage"), 0),
        ),
        "creature_damage_head": creature_damage_head_obj,
        "projectile_spawn_head": projectile_spawn_head_obj,
        "secondary_projectile_spawn_count": int(tick.event_counts.secondary_projectile_spawn),
        "secondary_projectile_spawn_head": secondary_projectile_spawn_head_obj,
        "creature_death_head": creature_death_head_obj,
        "bonus_spawn_head": bonus_spawn_head_obj,
        "projectile_find_hit_count": _int_or(int(tick.event_counts.projectile_find_hit), len(projectile_find_hit_head_obj)),
        "projectile_find_query_count": _int_or(
            int(tick.event_counts.projectile_find_query),
            _int_or(spawn_obj.get("event_count_projectile_find_query"), len(projectile_find_query_head_obj)),
        ),
        "projectile_find_query_head": projectile_find_query_head_obj,
        "projectile_find_query_miss_count": int(projectile_find_query_miss_count),
        "projectile_find_query_owner_collision_count": int(projectile_find_query_owner_collision_count),
        "projectile_find_hit_head": projectile_find_hit_head_obj,
        "projectile_find_hit_corpse_count": sum(
            1
            for item in projectile_find_hit_head_obj
            if isinstance(item, dict) and bool(item.get("corpse_hit"))
        ),
        "spawn_top_creature_damage_callers": top_creature_damage_callers,
        "spawn_top_projectile_find_hit_callers": top_projectile_find_hit_callers,
        "spawn_top_projectile_find_query_callers": top_projectile_find_query_callers,
        "lifecycle_before_hash": lifecycle_obj.get("before_hash"),
        "lifecycle_after_hash": lifecycle_obj.get("after_hash"),
        "lifecycle_before_count": _int_or(lifecycle_obj.get("before_count")),
        "lifecycle_after_count": _int_or(lifecycle_obj.get("after_count")),
        "before_player0": before_player0,
        "input_player_keys": input_player_keys,
        "sample_streams_present": bool(tick.samples is not None),
        "sample_counts": sample_counts,
        "sample_creatures_head": _build_sample_creatures_head(tick),
        "sample_secondary_head": _build_sample_secondary_head(tick),
    }
    return row


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
    out: list[RunSummaryEventLite],
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
        RunSummaryEventLite(
            tick_index=int(tick),
            kind=str(kind),
            detail=str(detail),
        )
    )


def _parse_player_perk_counts(tick: CaptureTick) -> dict[int, Counter[int]]:
    out: dict[int, Counter[int]] = {}
    for player_idx, player_counts in enumerate(tick.checkpoint.perk.player_nonzero_counts):
        counts = Counter()
        for pair in player_counts:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            perk_id = _int_or(pair[0], -1)
            perk_count = _int_or(pair[1], 0)
            if perk_id < 0 or perk_count <= 0:
                continue
            counts[int(perk_id)] = int(perk_count)
        if counts:
            out[int(player_idx)] = counts
    return out


def _build_run_summary_events_from_capture(capture: CaptureFile) -> list[RunSummaryEventLite]:
    events: list[RunSummaryEventLite] = []
    seen: set[tuple[int, str, str]] = set()
    prev_levels: dict[int, int] = {}
    prev_perk_counts: dict[int, Counter[int]] = {}

    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        event_heads = _build_event_heads_by_kind(tick)

        bonus_apply = event_heads.get("bonus_apply", [])
        for item in bonus_apply:
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
                tick=int(tick_index),
                kind="bonus_pickup",
                detail=detail,
            )

        weapon_assign = event_heads.get("weapon_assign", [])
        for item in weapon_assign:
            player_index = _int_or(item.get("player_index"), 0)
            weapon_before = _int_or(item.get("weapon_before"), -1)
            weapon_after = _int_or(item.get("weapon_after"), _int_or(item.get("weapon_id"), -1))
            _append_run_summary_event(
                events,
                seen=seen,
                tick=int(tick_index),
                kind="weapon_assign",
                detail=(
                    f"p{player_index} weapon "
                    f"{_weapon_name(int(weapon_before))} -> {_weapon_name(int(weapon_after))}"
                ),
            )

        state_transition = event_heads.get("state_transition", [])
        for item in state_transition:
            before_obj = item.get("before")
            before = cast(dict[str, object], before_obj) if isinstance(before_obj, dict) else None
            after_obj = item.get("after")
            after = cast(dict[str, object], after_obj) if isinstance(after_obj, dict) else None
            before_state = _int_or(
                before.get("id") if before is not None else None,
                -1,
            )
            after_state = _int_or(
                after.get("id") if after is not None else item.get("target_state"),
                _int_or(item.get("target_state"), -1),
            )
            _append_run_summary_event(
                events,
                seen=seen,
                tick=int(tick_index),
                kind="state_transition",
                detail=f"state {before_state} -> {after_state}",
            )

        for player_index, player in enumerate(tick.checkpoint.players):
            level = int(player.level)
            prev_level = prev_levels.get(int(player_index))
            if prev_level is not None and int(level) > int(prev_level):
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick_index),
                    kind="level_up",
                    detail=f"p{int(player_index)} level {int(prev_level)} -> {int(level)} (xp={int(player.experience)})",
                )
            prev_levels[int(player_index)] = int(level)

        perk_counts = _parse_player_perk_counts(tick)
        for player_index, player_counts in perk_counts.items():
            previous = prev_perk_counts.get(int(player_index), Counter())
            for perk_id, perk_count in sorted(player_counts.items()):
                previous_count = int(previous.get(int(perk_id), 0))
                if int(perk_count) <= int(previous_count):
                    continue
                _append_run_summary_event(
                    events,
                    seen=seen,
                    tick=int(tick_index),
                    kind="perk_pick",
                    detail=(
                        f"p{int(player_index)} perk {perk_label(int(perk_id))} ({int(perk_id)}) "
                        f"x{int(perk_count)}"
                    ),
                )
            prev_perk_counts[int(player_index)] = Counter(player_counts)

    events.sort(key=lambda item: (int(item.tick_index), str(item.kind), str(item.detail)))
    return events


def _capture_sample_rate(capture: CaptureFile) -> int:
    ticks = sorted(int(tick.tick_index) for tick in capture.ticks)
    if len(ticks) < 2:
        return 1
    deltas = [next_tick - tick for tick, next_tick in zip(ticks, ticks[1:]) if int(next_tick) > int(tick)]
    if not deltas:
        return 1
    deltas.sort()
    return max(1, int(deltas[len(deltas) // 2]))


class CaptureSession:
    def __init__(self, capture_path: Path) -> None:
        resolved = Path(capture_path).expanduser().resolve()
        self.capture_path = resolved
        self.fingerprint = capture_fingerprint(resolved)
        self.cache_dir = cache_root() / _cache_id_for_fingerprint(self.fingerprint)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.capture = self._load_or_build_capture()
        self.sample_rate = _capture_sample_rate(self.capture)

        self.tick_lite_by_tick = self._load_or_build_tick_lite()
        sample_creature_counts: dict[int, int] = {}
        for tick, row in self.tick_lite_by_tick.items():
            sample_counts_obj = row.get("sample_counts")
            if not isinstance(sample_counts_obj, dict):
                continue
            sample_counts = cast(dict[str, object], sample_counts_obj)
            creature_count = _int_or(sample_counts.get("creatures"), -1)
            if int(creature_count) < 0:
                continue
            sample_creature_counts[int(tick)] = int(creature_count)
        self.sample_creature_counts = sample_creature_counts
        self.run_summary_events = _build_run_summary_events_from_capture(self.capture)

        self._replay_cache: OrderedDict[ReplayKey, tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], object, object]] = (
            OrderedDict()
        )
        self._divergence_cache: OrderedDict[tuple[ReplayKey, float, int], object] = OrderedDict()
        self._focus_runtime_by_key: dict[FocusKey, _FocusRuntime] = {}
        self._focus_report_cache: OrderedDict[tuple[FocusKey, int, float], FocusTraceReport] = OrderedDict()

    def matches_current_file(self) -> bool:
        try:
            current = capture_fingerprint(self.capture_path)
        except OSError:
            return False
        return (
            str(current.resolved_path) == str(self.fingerprint.resolved_path)
            and int(current.size) == int(self.fingerprint.size)
            and int(current.mtime_ns) == int(self.fingerprint.mtime_ns)
        )

    def _load_or_build_capture(self) -> CaptureFile:
        capture_blob_path = self.cache_dir / _CAPTURE_BLOB_NAME
        meta_path = self.cache_dir / _META_NAME
        if _meta_matches(meta_path, self.fingerprint) and capture_blob_path.exists():
            try:
                return _read_msgpack_gz(capture_blob_path, type=CaptureFile)
            except Exception:
                pass

        capture = _read_capture(self.capture_path)
        _write_msgpack_gz(capture_blob_path, capture)
        meta = _CaptureMeta(schema_version=int(_CACHE_SCHEMA_VERSION), fingerprint=self.fingerprint)
        _atomic_write_text(meta_path, json.dumps(msgspec.to_builtins(meta), indent=2, sort_keys=True))
        return capture

    def _load_or_build_tick_lite(self) -> dict[int, dict[str, object]]:
        tick_blob_path = self.cache_dir / _TICK_LITE_BLOB_NAME
        meta_path = self.cache_dir / _META_NAME
        if _meta_matches(meta_path, self.fingerprint) and tick_blob_path.exists():
            try:
                blob = _read_msgpack_gz(tick_blob_path, type=_TickLiteBlob)
                return {int(row.tick_index): dict(row.row) for row in blob.rows}
            except Exception:
                pass

        rows: list[TickLite] = []
        for tick in self.capture.ticks:
            rows.append(TickLite(tick_index=int(tick.tick_index), row=_build_tick_lite_row(tick)))
        blob = _TickLiteBlob(rows=rows)
        _write_msgpack_gz(tick_blob_path, blob)
        return {int(row.tick_index): dict(row.row) for row in rows}

    def get_capture(self) -> CaptureFile:
        return self.capture

    def get_sample_rate(self) -> int:
        return int(self.sample_rate)

    def get_sample_creature_counts(self) -> dict[int, int]:
        return dict(self.sample_creature_counts)

    def get_raw_debug_by_tick(self, tick_indices: set[int] | None = None) -> dict[int, dict[str, object]]:
        if tick_indices is None:
            return {int(tick): dict(row) for tick, row in self.tick_lite_by_tick.items()}
        return {
            int(tick): dict(row)
            for tick, row in self.tick_lite_by_tick.items()
            if int(tick) in tick_indices
        }

    def get_run_summary_events(self) -> list[RunSummaryEventLite]:
        return list(self.run_summary_events)

    def get_replay_outcome(
        self,
        key: ReplayKey,
    ) -> tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], object, object]:
        cached = self._replay_cache.get(key)
        if cached is not None:
            self._replay_cache.move_to_end(key, last=True)
            return cached

        from . import divergence_report as divergence_report_mod

        aim_overrides = {int(player): int(scheme) for player, scheme in key.aim_scheme_overrides}
        expected, actual, run_result = divergence_report_mod._run_actual_checkpoints(
            self.capture,
            max_ticks=key.max_ticks,
            seed=key.seed,
            inter_tick_rand_draws=int(key.inter_tick_rand_draws),
            aim_scheme_overrides_by_player=aim_overrides,
        )
        replay = convert_capture_to_replay(
            self.capture,
            seed=key.seed,
            aim_scheme_overrides_by_player=aim_overrides,
        )
        result = (expected, actual, run_result, replay)
        self._replay_cache[key] = result
        self._replay_cache.move_to_end(key, last=True)
        while len(self._replay_cache) > 8:
            self._replay_cache.popitem(last=False)
        return result

    def get_divergence(
        self,
        *,
        replay_key: ReplayKey,
        expected: list[ReplayCheckpoint],
        actual: list[ReplayCheckpoint],
        float_abs_tol: float,
        max_field_diffs: int,
    ) -> object:
        cache_key = (replay_key, float(float_abs_tol), int(max_field_diffs))
        cached = self._divergence_cache.get(cache_key)
        if cached is not None:
            self._divergence_cache.move_to_end(cache_key, last=True)
            return cached

        from . import divergence_report as divergence_report_mod

        divergence = divergence_report_mod._find_first_divergence(
            expected,
            actual,
            float_abs_tol=float(float_abs_tol),
            max_field_diffs=max(1, int(max_field_diffs)),
            capture_sample_creature_counts=self.sample_creature_counts,
            raw_debug_by_tick=self.get_raw_debug_by_tick(),
        )

        self._divergence_cache[cache_key] = divergence
        self._divergence_cache.move_to_end(cache_key, last=True)
        while len(self._divergence_cache) > 16:
            self._divergence_cache.popitem(last=False)
        return divergence

    def get_focus_report(
        self,
        *,
        key: FocusKey,
        tick: int,
        near_miss_threshold: float,
    ) -> FocusTraceReport:
        report_key = (key, int(tick), round(float(near_miss_threshold), 6))
        cached = self._focus_report_cache.get(report_key)
        if cached is not None:
            self._focus_report_cache.move_to_end(report_key, last=True)
            return cached

        runtime = self._focus_runtime_by_key.get(key)
        if runtime is None:
            replay = convert_capture_to_replay(
                self.capture,
                aim_scheme_overrides_by_player={int(player): int(scheme) for player, scheme in key.aim_scheme_overrides},
            )
            runtime = _FocusRuntime(
                capture=self.capture,
                replay=replay,
                inter_tick_rand_draws=int(key.inter_tick_rand_draws),
            )
            self._focus_runtime_by_key[key] = runtime

        report = runtime.trace_tick(
            tick=int(tick),
            near_miss_threshold=float(near_miss_threshold),
        )
        self._focus_report_cache[report_key] = report
        self._focus_report_cache.move_to_end(report_key, last=True)
        while len(self._focus_report_cache) > 128:
            self._focus_report_cache.popitem(last=False)
        return report


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: OrderedDict[str, CaptureSession] = OrderedDict()

    def get_session(self, capture_path: Path) -> CaptureSession:
        resolved = Path(capture_path).expanduser().resolve()
        key = str(resolved)
        existing = self._sessions.get(key)
        if existing is not None and existing.matches_current_file():
            self._sessions.move_to_end(key, last=True)
            return existing

        session = CaptureSession(resolved)
        self._sessions[key] = session
        self._sessions.move_to_end(key, last=True)
        while len(self._sessions) > 4:
            self._sessions.popitem(last=False)
        return session


def replay_key_from_args(args: argparse.Namespace, *, aim_scheme_overrides: Mapping[int, int]) -> ReplayKey:
    return build_replay_key(
        max_ticks=args.max_ticks,
        seed=args.seed,
        inter_tick_rand_draws=args.inter_tick_rand_draws,
        aim_scheme_overrides_by_player=aim_scheme_overrides,
    )


def focus_key_from_args(args: argparse.Namespace, *, aim_scheme_overrides: Mapping[int, int]) -> FocusKey:
    return build_focus_key(
        inter_tick_rand_draws=args.inter_tick_rand_draws,
        aim_scheme_overrides_by_player=aim_scheme_overrides,
    )
