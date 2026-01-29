from __future__ import annotations

import math

from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import GameplayState, PlayerState


def test_ranged_creature_spawns_player_targeting_projectile() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=64.0, pos_y=64.0)

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.x = 32.0
    creature.y = 64.0
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ranged_projectile_type = 9
    creature.contact_damage = 0.0

    pool.update(0.001, state=state, players=[player])

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    assert spawned[0].hits_players is True
    assert int(spawned[0].type_id) == 9


def test_ranged_projectile_can_damage_player() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=4.0, pos_y=0.0)

    state.projectiles.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=9,
        owner_id=0,
        base_damage=45.0,
        hits_players=True,
    )

    def _apply_player_damage(player_index: int, damage: float) -> None:
        assert player_index == 0
        player.health -= float(damage)

    state.projectiles.update(
        0.001,
        [],
        world_size=1024.0,
        rng=state.rng.rand,
        runtime_state=state,
        players=[player],
        apply_player_damage=_apply_player_damage,
    )

    assert player.health < 100.0
