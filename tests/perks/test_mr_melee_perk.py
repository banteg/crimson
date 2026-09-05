from __future__ import annotations

import pytest

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import make_creature_update_options
from tests.support.helpers import assert_float_close


def test_mr_melee_hits_attacking_creature_on_contact_damage_tick() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.MR_MELEE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert_float_close(creature.hp, 75.0)


def test_mr_melee_does_not_prevent_player_damage_when_killing_attacker() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=100.0, plaguebearer_active=True)
    player.perk_counts[int(PerkId.MR_MELEE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert_float_close(player.health, 90.0)
    assert creature.plague_infected
    # The live interaction tail finishes without an in-frame dt * 28 corpse step.
    assert creature.lifecycle_stage > CREATURE_LIFECYCLE_ALIVE - 1.0


def test_mr_melee_is_inert_when_not_active() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert_float_close(creature.hp, 100.0)


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_hp", "expected_strong_poison"),
    [
        (True, 75.0, False),
        (False, 100.0, True),
    ],
)
def test_contact_perks_select_native_player_zero_or_corrected_target(
    preserve_bugs: bool,
    expected_hp: float,
    expected_strong_poison: bool,
) -> None:
    state = GameplayState(preserve_bugs=preserve_bugs)
    player0 = PlayerState(index=0, pos=Vec2(900.0, 900.0), health=100.0)
    player0.perk_counts[int(PerkId.MR_MELEE)] = 1
    player0.perk_counts[int(PerkId.VEINS_OF_POISON)] = 1
    player1 = PlayerState(index=1, pos=Vec2(100.0, 100.0), health=100.0)
    player1.perk_counts[int(PerkId.TOXIC_AVENGER)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.target_player = 1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player0, player1]))

    assert_float_close(creature.hp, expected_hp)
    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK
    assert bool(creature.flags & CreatureFlags.SELF_DAMAGE_TICK_STRONG) is expected_strong_poison
    assert_float_close(player1.health, 90.0)
