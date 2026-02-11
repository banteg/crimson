from __future__ import annotations

import inspect

from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.bonuses.pickup_fx import emit_bonus_pickup_effects
from crimson.effects import FxQueue
from crimson.effects_atlas import EffectId
from crimson.features.perks import PLAYER_DEATH_HOOKS, WORLD_DT_STEPS
from crimson.features.perks.final_revenge import apply_final_revenge_on_player_death
from crimson.features.perks.reflex_boosted import apply_reflex_boosted_dt
from crimson.gameplay import GameplayState
from crimson.projectiles import ProjectileHit, ProjectileTypeId
from crimson.sim.presentation_step import apply_world_presentation_step, queue_projectile_decals
from crimson.sim.state_types import BonusPickupEvent
from crimson.sim.world_state import WorldState


def test_perk_hook_registries_are_explicit_and_ordered() -> None:
    assert WORLD_DT_STEPS == (apply_reflex_boosted_dt,)
    assert PLAYER_DEATH_HOOKS == (apply_final_revenge_on_player_death,)


def test_bonus_pickup_feature_hooks_emit_expected_fx() -> None:
    state = GameplayState()
    pickups = [
        BonusPickupEvent(
            player_index=0,
            bonus_id=int(BonusId.REFLEX_BOOST),
            amount=3,
            pos=Vec2(100.0, 100.0),
        ),
        BonusPickupEvent(
            player_index=0,
            bonus_id=int(BonusId.FREEZE),
            amount=5,
            pos=Vec2(200.0, 200.0),
        ),
        BonusPickupEvent(
            player_index=0,
            bonus_id=int(BonusId.NUKE),
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
    draws = {"count": 0}

    def rand() -> int:
        draws["count"] += 1
        return 0

    queue_projectile_decals(
        state=state,
        players=[],
        fx_queue=fx_queue,
        hits=[
            ProjectileHit(
                type_id=int(ProjectileTypeId.FIRE_BULLETS),
                origin=Vec2(0.0, 0.0),
                hit=Vec2(1.0, 1.0),
                target=Vec2(1.0, 1.0),
            )
        ],
        rand=rand,
        detail_preset=5,
        fx_toggle=0,
    )

    assert draws["count"] > 0
    assert fx_queue.count > 0


def test_step_dispatch_functions_are_size_bounded() -> None:
    assert len(inspect.getsource(WorldState.step).splitlines()) <= 320
    assert len(inspect.getsource(apply_world_presentation_step).splitlines()) <= 80
