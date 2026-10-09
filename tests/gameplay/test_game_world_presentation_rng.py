from __future__ import annotations

from crimson.effects import FxQueue
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand


def test_projectile_decals_skip_splatter_rands_when_violence_disabled() -> None:
    from crimson.sim.presentation_step import queue_projectile_decals_pre_hit
    from crimson.sim.state_types import PlayerState

    state = GameplayState()
    state.rng = RecordingCrand(Crand(0x1234))
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    hit = ProjectileHit(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(90.0, 90.0),
        hit=Vec2(100.0, 100.0),
        target=Vec2(100.0, 100.0),
    )

    queue_projectile_decals_pre_hit(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hit=hit,
        rng=state.rng,
        detail_preset=5,
        violence_disabled=1,
    )

    # Native wraps the whole splatter block (including its rand draws) in
    # `if (config_violence_disabled == '\0')`.
    assert state.rng.calls == 0


def test_projectile_decals_bloody_mess_keeps_decal_loop_when_violence_disabled() -> None:
    from crimson.perks import PerkId
    from crimson.rng_caller_static import RngCallerStatic
    from crimson.sim.presentation_step import queue_projectile_decals_pre_hit
    from crimson.sim.state_types import PlayerState

    state = GameplayState()
    state.rng = RecordingCrand(Crand(0x1234))
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    state.perks[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1
    hit = ProjectileHit(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(90.0, 90.0),
        hit=Vec2(100.0, 100.0),
        target=Vec2(100.0, 100.0),
    )

    queue_projectile_decals_pre_hit(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hit=hit,
        rng=state.rng,
        detail_preset=5,
        violence_disabled=1,
    )

    callers = {record.caller for record in state.rng.records_since()}
    # The splatter spread draws are violence-gated; the bloody-mess terrain
    # decal loop is not.
    assert RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_SPREAD not in callers
    assert RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_1 in callers
