from __future__ import annotations

from pathlib import Path

from crimson.effects import FxQueue
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.presentation_step import queue_projectile_decals
from grim.geom import Vec2
from tests.support.world_runtime import WorldRuntimeHost


def test_projectile_decals_consume_authoritative_rng() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    world.sim_world.state.rng.srand(0x1234)
    sim_before = int(world.sim_world.state.rng.state)

    player = world.sim_world.players[0]
    fx_queue = FxQueue()
    hit = ProjectileHit(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(float(player.pos.x - 10.0), float(player.pos.y - 10.0)),
        hit=player.pos,
        target=player.pos,
    )
    queue_projectile_decals(
        state=world.sim_world.state,
        players=world.sim_world.players,
        fx_queue=fx_queue,
        hits=[hit],
        rng=world.sim_world.state.rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert int(world.sim_world.state.rng.state) != sim_before
    assert fx_queue.count > 0


def test_projectile_decals_skip_splatter_rands_when_violence_disabled() -> None:
    from crimson.gameplay import GameplayState
    from crimson.sim.presentation_step import queue_projectile_decals_pre_hit
    from crimson.sim.state_types import PlayerState
    from tests.support.helpers import ScriptedCrand

    state = GameplayState()
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
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
    from crimson.gameplay import GameplayState
    from crimson.perks import PerkId
    from crimson.rng_caller_static import RngCallerStatic
    from crimson.sim.presentation_step import queue_projectile_decals_pre_hit
    from crimson.sim.state_types import PlayerState
    from tests.support.helpers import ScriptedCrand

    state = GameplayState()
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1
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
