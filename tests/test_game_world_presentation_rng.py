from __future__ import annotations

from pathlib import Path

from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.presentation_step import queue_projectile_decals
from grim.geom import Vec2
from tests.world_runtime import WorldRuntimeHost


def test_projectile_decals_consume_authoritative_rng() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    world.sim_world.state.rng.srand(0x1234)
    sim_before = int(world.sim_world.state.rng.state)

    player = world.sim_world.players[0]
    hit = ProjectileHit(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(float(player.pos.x - 10.0), float(player.pos.y - 10.0)),
        hit=player.pos,
        target=player.pos,
    )
    queue_projectile_decals(
        state=world.sim_world.state,
        players=world.sim_world.players,
        fx_queue=world.render_resources.fx_queue,
        hits=[hit],
        rand=world.sim_world.state.rng.rand,
        detail_preset=5,
        gore_disabled=0,
    )

    assert int(world.sim_world.state.rng.state) != sim_before
    assert world.render_resources.fx_queue.count > 0
