from __future__ import annotations

from crimson.effects import FxQueue
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from tests.support.decals import queue_projectile_decals
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
