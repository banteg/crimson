from __future__ import annotations

import time
from collections.abc import Callable

import msgspec

from grim.rand import CallerStatic

from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..math_parity import f32
from ..perks.availability import perks_rebuild_available
from ..weapon_runtime import weapon_refresh_available
from .input import PlayerInput
from .input_frame import normalize_input_frame
from .presentation_step import PresentationStepCommands, plan_world_presentation_step
from .timing import FrameTiming
from .world_state import WorldEvents, WorldState


class PresentationRngTrace(msgspec.Struct):
    draws_total: int = 0
    draws_by_consumer: dict[str, int] = msgspec.field(default_factory=dict)


class DeterministicStepResult(msgspec.Struct):
    dt_sim: float
    timing: FrameTiming
    events: WorldEvents
    presentation: PresentationStepCommands
    presentation_plan_ms: float
    presentation_rng_trace: PresentationRngTrace
    post_apply_sfx_keys: tuple[str, ...] = ()


class StepPipelineOptions(msgspec.Struct, frozen=True):
    world_size: float
    damage_scale_by_type: dict[int, float]
    detail_preset: int
    gore_disabled: int
    auto_pick_perks: bool
    game_mode: GameMode
    demo_mode_active: bool
    perk_progression_enabled: bool
    game_tune_started: bool


def time_scale_reflex_boost_bonus(
    *,
    reflex_boost_timer: float,
    time_scale_active: bool,
    dt: float,
) -> float:
    """Apply Reflex Boost time scaling, matching the classic frame loop latch semantics."""

    # Native stores frame delta time in float32 (`frame_dt`). Many downstream systems
    # multiply `frame_dt` before rounding back to float32, so the *input* precision
    # matters even when Reflex Boost is inactive.
    dt_f32 = f32(float(dt))
    if not (float(dt_f32) > 0.0):
        return float(dt_f32)
    if not time_scale_active:
        return float(dt_f32)

    time_scale_factor = time_scale_reflex_boost_factor(
        reflex_boost_timer=float(reflex_boost_timer),
        time_scale_active=bool(time_scale_active),
    )
    return float(f32(float(dt_f32) * float(time_scale_factor)))


def time_scale_reflex_boost_factor(
    *,
    reflex_boost_timer: float,
    time_scale_active: bool,
) -> float:
    if not bool(time_scale_active):
        return 1.0
    reflex_f32 = f32(float(reflex_boost_timer))
    time_scale_factor = f32(0.3)
    if float(reflex_f32) < 1.0:
        time_scale_factor = f32((1.0 - float(reflex_f32)) * 0.7 + 0.3)
    return float(time_scale_factor)


def run_deterministic_step(
    *,
    world: WorldState,
    timing: FrameTiming,
    options: StepPipelineOptions,
    apply_world_dt_steps: bool = True,
    inputs: list[PlayerInput] | None,
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    defer_camera_shake_update: bool = False,
    defer_freeze_corpse_fx: bool = False,
    mid_step_hook: Callable[[], None] | None = None,
    rng_marks_out: dict[str, int] | None = None,
    trace_presentation_rng: bool = False,
) -> DeterministicStepResult:
    state = world.state
    rand = state.rng.rand

    def _mark(name: str) -> None:
        if rng_marks_out is None:
            return
        rng_marks_out[str(name)] = int(state.rng.state)

    inputs = normalize_input_frame(inputs, player_count=len(world.players)).as_list()

    _mark("gw_begin")
    state.game_mode = options.game_mode
    state.demo_mode_active = bool(options.demo_mode_active)

    weapon_refresh_available(state)
    _mark("gw_after_weapon_refresh")
    perks_rebuild_available(state)
    _mark("gw_after_perks_rebuild")
    _mark("gw_after_time_scale")

    prev_audio = [(player.shot_seq, player.weapon.reload_active, player.weapon.reload_timer) for player in world.players]
    prev_perk_pending = int(state.perk_selection.pending_count)

    events = world.step(
        float(timing.dt_sim),
        apply_world_dt_steps=apply_world_dt_steps,
        dt_player_local=float(timing.dt_player_local),
        defer_camera_shake_update=defer_camera_shake_update,
        defer_freeze_corpse_fx=defer_freeze_corpse_fx,
        mid_step_hook=mid_step_hook,
        inputs=inputs,
        world_size=float(options.world_size),
        damage_scale_by_type=options.damage_scale_by_type,
        detail_preset=int(options.detail_preset),
        gore_disabled=int(options.gore_disabled),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        auto_pick_perks=bool(options.auto_pick_perks),
        game_mode=options.game_mode,
        perk_progression_enabled=bool(options.perk_progression_enabled),
        game_tune_started=bool(options.game_tune_started),
        rng_marks=rng_marks_out,
    )

    trace = PresentationRngTrace()

    def _rand_for(label: str):
        if not trace_presentation_rng:
            return rand

        def _draw(*, caller_static_u32: CallerStatic = None) -> int:
            _ = caller_static_u32
            value = int(rand())
            trace.draws_total += 1
            trace.draws_by_consumer[str(label)] = int(trace.draws_by_consumer.get(str(label), 0)) + 1
            return value

        return _draw

    plan_ns_start = time.perf_counter_ns()
    presentation = plan_world_presentation_step(
        state=state,
        players=world.players,
        fx_queue=fx_queue,
        hits=events.hits,
        deaths=events.deaths,
        pickups=events.pickups,
        event_sfx=events.sfx,
        prev_audio=prev_audio,
        prev_perk_pending=int(prev_perk_pending),
        game_mode=options.game_mode,
        demo_mode_active=bool(options.demo_mode_active),
        perk_progression_enabled=bool(options.perk_progression_enabled),
        rand=rand,
        rand_for=_rand_for if trace_presentation_rng else None,
        detail_preset=int(options.detail_preset),
        gore_disabled=int(options.gore_disabled),
        game_tune_started=bool(options.game_tune_started),
        trigger_game_tune=events.trigger_game_tune,
        hit_sfx=events.hit_sfx,
        death_sfx_preplanned=events.death_sfx_preplanned,
    )
    presentation_plan_ms = (time.perf_counter_ns() - plan_ns_start) / 1_000_000.0

    if rng_marks_out is not None and trace_presentation_rng:
        rng_marks_out["ps_draws_total"] = int(trace.draws_total)
        for key, value in sorted(trace.draws_by_consumer.items()):
            rng_marks_out[f"ps_draws_{key}"] = int(value)

    return DeterministicStepResult(
        dt_sim=float(timing.dt_sim),
        timing=timing,
        events=events,
        presentation=presentation,
        presentation_plan_ms=float(presentation_plan_ms),
        presentation_rng_trace=trace,
    )
