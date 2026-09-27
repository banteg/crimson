from __future__ import annotations

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.presentation_step import plan_world_presentation_step, queue_projectile_decals
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.helpers import ScriptedCrand, assert_rng_progression


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
    world = make_world()
    fx_queue = FxQueue()
    fx_queue_rotated = FxQueueRotated()
    events = world.step(
        1.0 / 60.0,
        mid_step_runtime=None,
        inputs=[],
        detail_preset=5,
        violence_disabled=0,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
        game_tune_started=False,
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
