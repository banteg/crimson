from __future__ import annotations

from pathlib import Path

from crimson.game_world import GameWorld
from crimson.projectiles import ProjectileTypeId


def test_projectile_decals_do_not_consume_sim_rng() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    world.state.rng.srand(0x1234)
    world.presentation_rng.srand(0xBEEF)
    sim_before = int(world.state.rng.state)
    present_before = int(world.presentation_rng.state)

    player = world.players[0]
    hit = (
        int(ProjectileTypeId.PISTOL),
        float(player.pos_x - 10.0),
        float(player.pos_y - 10.0),
        float(player.pos_x),
        float(player.pos_y),
        float(player.pos_x),
        float(player.pos_y),
    )
    world._queue_projectile_decals([hit])

    assert int(world.state.rng.state) == sim_before
    assert int(world.presentation_rng.state) != present_before
    assert world.fx_queue.count > 0

