from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId


def test_mr_melee_hits_attacking_creature_on_contact_damage_tick() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.MR_MELEE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.pos.x = 100.0
    creature.pos.y = 100.0
    creature.hp = 100.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, state=state, players=[player])

    assert creature.hp == pytest.approx(75.0)


def test_mr_melee_does_not_prevent_player_damage_when_killing_attacker() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=100.0)
    player.perk_counts[int(PerkId.MR_MELEE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.pos.x = 100.0
    creature.pos.y = 100.0
    creature.hp = 10.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, state=state, players=[player])

    assert player.health == pytest.approx(90.0)


def test_mr_melee_is_inert_when_not_active() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.pos.x = 100.0
    creature.pos.y = 100.0
    creature.hp = 100.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, state=state, players=[player])

    assert creature.hp == pytest.approx(100.0)
