from __future__ import annotations

from pathlib import Path

from crimson.game_world import GameWorld
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from grim.geom import Vec2


def test_projectile_decals_consume_authoritative_rng() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    world.sim_world.state.rng.srand(0x1234)
    sim_before = int(world.sim_world.state.rng.state)

    player = world.sim_world.players[0]
    hit = ProjectileHit(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(float(player.pos.x - 10.0), float(player.pos.y - 10.0)),
        hit=player.pos,
        target=player.pos,
    )
    world._queue_projectile_decals([hit], rand=world.sim_world.state.rng.rand)

    assert int(world.sim_world.state.rng.state) != sim_before
    assert world.render_resources.fx_queue.count > 0
