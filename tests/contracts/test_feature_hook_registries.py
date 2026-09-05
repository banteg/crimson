from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.pickup_fx import emit_bonus_pickup_effects
from crimson.effects import FxQueue, FxQueueRotated
from crimson.effects_atlas import EffectId
from crimson.game_modes import GameMode
from crimson.perks.impl.final_revenge import apply_final_revenge_on_player_death
from crimson.perks.impl.reflex_boosted import apply_reflex_boosted_dt
from crimson.perks.runtime.manifest import (
    PERK_APPLY_HANDLERS,
    PERK_HOOKS_IN_ORDER,
    PERKS_UPDATE_EFFECT_STEPS,
    PLAYER_DEATH_HOOKS,
    PLAYER_PERK_TICK_STEPS,
    WORLD_DT_STEPS,
)
from crimson.perks.runtime.player_bonus_timers import update_player_bonus_timers
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.presentation_step import plan_world_presentation_step, queue_projectile_decals
from crimson.sim.state_types import BonusPickupEvent
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_rng_progression


def test_perk_hook_registries_are_explicit_and_ordered() -> None:
    assert WORLD_DT_STEPS == (apply_reflex_boosted_dt,)
    assert PLAYER_DEATH_HOOKS == (apply_final_revenge_on_player_death,)


def test_perk_manifest_has_single_runtime_owner_per_perk() -> None:
    perk_ids = [hooks.perk_id for hooks in PERK_HOOKS_IN_ORDER]
    assert len(perk_ids) == len(set(perk_ids))

    expected_apply_ids = {hooks.perk_id for hooks in PERK_HOOKS_IN_ORDER if hooks.apply_handler is not None}
    assert set(PERK_APPLY_HANDLERS) == expected_apply_ids

    expected_player_tick_steps = tuple(step for hooks in PERK_HOOKS_IN_ORDER for step in hooks.player_tick_steps)
    assert PLAYER_PERK_TICK_STEPS == expected_player_tick_steps

    expected_effect_steps = (update_player_bonus_timers,) + tuple(
        step for hooks in PERK_HOOKS_IN_ORDER for step in hooks.effects_steps
    )
    assert PERKS_UPDATE_EFFECT_STEPS == expected_effect_steps


def test_bonus_pickup_feature_hooks_emit_expected_fx() -> None:
    state = GameplayState()
    pickups = [
        BonusPickupEvent(
            player_index=0,
            bonus_id=BonusId.REFLEX_BOOST,
            amount=3,
            pos=Vec2(100.0, 100.0),
        ),
        BonusPickupEvent(
            player_index=0,
            bonus_id=BonusId.FREEZE,
            amount=5,
            pos=Vec2(200.0, 200.0),
        ),
        BonusPickupEvent(
            player_index=0,
            bonus_id=BonusId.NUKE,
            amount=0,
            pos=Vec2(300.0, 300.0),
        ),
    ]

    emit_bonus_pickup_effects(
        state=state,
        pickups=pickups,
        detail_preset=5,
    )

    active = state.effects.iter_active()
    burst_count = sum(1 for effect in active if int(effect.effect_id) == int(EffectId.BURST))
    ring_count = sum(1 for effect in active if int(effect.effect_id) == int(EffectId.RING))
    assert burst_count == 24  # reflex + freeze each emit 12 burst particles; nuke skips burst
    assert ring_count == 2


def test_fire_bullets_projectile_decals_flow_through_feature_hooks() -> None:
    state = GameplayState()
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[],
        fx_queue=fx_queue,
        hits=[
            ProjectileHit(
                type_id=ProjectileTemplateId.FIRE_BULLETS,
                origin=Vec2(0.0, 0.0),
                hit=Vec2(1.0, 1.0),
                target=Vec2(1.0, 1.0),
            ),
        ],
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=59,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 59
    assert fx_queue.count > 0


def test_step_dispatch_functions_execute_as_behavioral_smoke() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
        preserve_bugs=False,
    )
    fx_queue = FxQueue()
    fx_queue_rotated = FxQueueRotated()
    events = world.step(
        1.0 / 60.0,
        inputs=[],
        world_size=1024.0,
        damage_scale_by_type={},
        detail_preset=5,
        violence_disabled=0,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
    )

    plan = plan_world_presentation_step(
        state=world.state,
        players=world.players,
        fx_queue=fx_queue,
        hits=list(events.hits),
        pickups=list(events.pickups),
        event_sfx=list(events.sfx),
        prev_audio=[],
        prev_perk_pending=0,
        game_mode=GameMode.SURVIVAL,
        demo_mode_active=False,
        perk_progression_enabled=True,
        rng=world.state.rng,
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=False,
        trigger_game_tune=False,
        hit_sfx=[],
    )

    assert isinstance(events.hits, list)
    assert isinstance(events.pickups, list)
    assert isinstance(plan.sfx, tuple)
    assert plan.trigger_game_tune is False
