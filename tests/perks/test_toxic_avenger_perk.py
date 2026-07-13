from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import make_creature_update_options


def test_toxic_avenger_sets_strong_self_damage_flags_on_contact_hit() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.TOXIC_AVENGER)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK
    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK_STRONG


def test_toxic_avenger_strong_tick_overrides_weak_tick() -> None:
    dt = 0.1
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SELF_DAMAGE_TICK | CreatureFlags.SELF_DAMAGE_TICK_STRONG | CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    pool.update(dt, options=make_creature_update_options(state=state, players=[player]))

    assert creature.hp == f32(100.0 - float(f32(float(dt))) * 180.0)


def test_toxic_avenger_skips_when_player_shielded() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), shield_timer=1.0)
    player.perk_counts[int(PerkId.TOXIC_AVENGER)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK_STRONG)
