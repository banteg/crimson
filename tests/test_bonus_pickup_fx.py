from __future__ import annotations

from pathlib import Path

from crimson.bonuses import BonusId
from crimson.game_world import GameWorld
from grim.geom import Vec2


def test_bonus_pickup_spawns_burst_effect() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(pos=Vec2(player.pos.x, player.pos.y), bonus_id=int(BonusId.POINTS), state=world.state)
    assert entry is not None

    assert not world.state.effects.iter_active()
    world.update(0.016, perk_progression_enabled=False)

    assert entry.picked
    active = world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}


def test_expired_bonus_can_still_pickup_as_unused_in_same_tick() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(pos=Vec2(player.pos.x, player.pos.y), bonus_id=int(BonusId.FREEZE), state=world.state)
    assert entry is not None
    entry.time_left = 0.01
    world.state.bonuses.freeze = 0.0

    world.update(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert int(entry.bonus_id) == int(BonusId.UNUSED)
    assert world.state.bonuses.freeze == 0.0
    active = world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}
