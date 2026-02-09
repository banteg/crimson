from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from ..effects import FxQueue, FxQueueRotated
from ..gameplay import PlayerInput, perks_rebuild_available, weapon_refresh_available
from ..math_parity import f32
from .input_frame import normalize_input_frame
from .presentation_step import PresentationStepCommands, apply_world_presentation_step
from .world_state import WorldEvents, WorldState


@dataclass(slots=True)
class PresentationRngTrace:
    draws_total: int = 0
    draws_by_consumer: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class DeterministicStepResult:
    dt_sim: float
    events: WorldEvents
    presentation: PresentationStepCommands
    command_hash: str
    presentation_rng_trace: PresentationRngTrace


def time_scale_reflex_boost_bonus(
    *,
    reflex_boost_timer: float,
    time_scale_active: bool,
    dt: float,
) -> float:
    """Apply Reflex Boost time scaling, matching the classic frame loop latch semantics."""

    if not (float(dt) > 0.0):
        return float(dt)
    if not bool(time_scale_active):
        return float(dt)

    dt_f32 = f32(float(dt))
    reflex_f32 = f32(float(reflex_boost_timer))
    time_scale_factor = f32(0.3)
    if float(reflex_f32) < 1.0:
        time_scale_factor = f32(f32(f32(1.0) - reflex_f32) * f32(0.7) + f32(0.3))
    return float(f32(float(dt_f32) * float(time_scale_factor)))


def presentation_commands_hash(commands: PresentationStepCommands) -> str:
    payload = {
        "trigger_game_tune": bool(commands.trigger_game_tune),
        "sfx_keys": [str(key) for key in commands.sfx_keys],
    }
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


def run_deterministic_step(
    *,
    world: WorldState,
    dt_frame: float,
    dt_frame_ms_i32: int | None = None,
    inputs: list[PlayerInput] | None,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    detail_preset: int,
    fx_toggle: int,
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    auto_pick_perks: bool,
    game_mode: int,
    demo_mode_active: bool,
    perk_progression_enabled: bool,
    game_tune_started: bool,
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
    state.game_mode = int(game_mode)
    state.demo_mode_active = bool(demo_mode_active)

    weapon_refresh_available(state)
    _mark("gw_after_weapon_refresh")
    perks_rebuild_available(state)
    _mark("gw_after_perks_rebuild")

    dt_sim = time_scale_reflex_boost_bonus(
        reflex_boost_timer=float(state.bonuses.reflex_boost),
        time_scale_active=bool(state.time_scale_active),
        dt=float(dt_frame),
    )
    _mark("gw_after_time_scale")

    prev_audio = [(player.shot_seq, player.reload_active, player.reload_timer) for player in world.players]
    prev_perk_pending = int(state.perk_selection.pending_count)

    dt_sim_ms_i32: int | None = None
    if dt_frame_ms_i32 is not None and int(dt_frame_ms_i32) > 0:
        if float(dt_frame) > 0.0:
            scale = float(dt_sim) / float(dt_frame)
            dt_sim_ms_i32 = max(0, int(float(int(dt_frame_ms_i32)) * float(scale)))
        else:
            dt_sim_ms_i32 = int(dt_frame_ms_i32)

    events = world.step(
        float(dt_sim),
        dt_ms_i32=(int(dt_sim_ms_i32) if dt_sim_ms_i32 is not None else None),
        inputs=inputs,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        detail_preset=int(detail_preset),
        fx_toggle=int(fx_toggle),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        auto_pick_perks=bool(auto_pick_perks),
        game_mode=int(game_mode),
        perk_progression_enabled=bool(perk_progression_enabled),
        game_tune_started=bool(game_tune_started),
        rng_marks=rng_marks_out,
    )

    trace = PresentationRngTrace()

    def _rand_for(label: str):
        if not trace_presentation_rng:
            return rand

        def _draw() -> int:
            value = int(rand())
            trace.draws_total += 1
            trace.draws_by_consumer[str(label)] = int(trace.draws_by_consumer.get(str(label), 0)) + 1
            return value

        return _draw

    presentation = apply_world_presentation_step(
        state=state,
        players=world.players,
        fx_queue=fx_queue,
        hits=events.hits,
        deaths=events.deaths,
        pickups=events.pickups,
        event_sfx=events.sfx,
        prev_audio=prev_audio,
        prev_perk_pending=int(prev_perk_pending),
        game_mode=int(game_mode),
        demo_mode_active=bool(demo_mode_active),
        perk_progression_enabled=bool(perk_progression_enabled),
        rand=rand,
        rand_for=_rand_for if trace_presentation_rng else None,
        detail_preset=int(detail_preset),
        fx_toggle=int(fx_toggle),
        game_tune_started=bool(game_tune_started),
        trigger_game_tune=bool(events.trigger_game_tune),
        hit_sfx=events.hit_sfx,
        death_sfx_preplanned=bool(events.death_sfx_preplanned),
    )

    command_hash = presentation_commands_hash(presentation)

    if rng_marks_out is not None and trace_presentation_rng:
        rng_marks_out["ps_draws_total"] = int(trace.draws_total)
        for key, value in sorted(trace.draws_by_consumer.items()):
            rng_marks_out[f"ps_draws_{key}"] = int(value)

    return DeterministicStepResult(
        dt_sim=float(dt_sim),
        events=events,
        presentation=presentation,
        command_hash=str(command_hash),
        presentation_rng_trace=trace,
    )
