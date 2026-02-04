from __future__ import annotations

from pathlib import Path

from crimson.bonuses import BonusId
from crimson.game_world import GameWorld


def test_bonus_pickup_spawns_burst_effect() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(player.pos_x, player.pos_y, int(BonusId.POINTS), state=world.state)
    assert entry is not None

    assert not world.state.effects.iter_active()
    world.update(0.016, perk_progression_enabled=False)

    assert entry.picked
    active = world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}
