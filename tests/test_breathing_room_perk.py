from __future__ import annotations

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreatureState
from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_perk_apply_breathing_room_reduces_health_and_starts_creature_death_staging() -> None:
    dt = 0.25

    state = GameplayState()
    state.bonus_spawn_guard = True

    player = PlayerState(index=0, pos=Vec2(), health=90.0)

    creatures: list[CreatureState] = [CreatureState() for _ in range(3)]
    creatures[0].active = True
    creatures[0].hitbox_size = CREATURE_HITBOX_ALIVE
    creatures[1].active = False
    creatures[1].hitbox_size = 123.0
    creatures[2].active = True
    creatures[2].hitbox_size = -5.0

    perk_apply(state, [player], PerkId.BREATHING_ROOM, dt=dt, creatures=creatures)

    assert_float_close(player.health, 30.0, abs_tol=1e-9)
    assert_float_close(creatures[0].hitbox_size, CREATURE_HITBOX_ALIVE - dt, abs_tol=1e-9)
    assert_float_close(creatures[1].hitbox_size, 123.0, abs_tol=1e-9)
    assert_float_close(creatures[2].hitbox_size, -5.0 - dt, abs_tol=1e-9)
    assert state.bonus_spawn_guard is False
    assert player.perk_counts[int(PerkId.BREATHING_ROOM)] == 1
