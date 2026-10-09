from __future__ import annotations

from crimson.creatures.runtime import PHANTOM_CREATURE_INDEX, CreaturePool
from crimson.gameplay import _player_apply_move_with_spawn_avoidance
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2


def test_phantom_spawn_slot_owner_still_blocks_the_player() -> None:
    pool = CreaturePool()
    pool.phantom.pos = Vec2(140.0, 100.0)
    pool.phantom.size = 60.0
    pool.spawn_slots[0].owner_creature = PHANTOM_CREATURE_INDEX
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), size=48.0)

    _player_apply_move_with_spawn_avoidance(player, perks=PerkCounts(), delta=Vec2(5.0, 0.0), creatures=pool)

    assert player.pos == Vec2(100.0, 100.0)
