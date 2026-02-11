from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects


class _ScriptedRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values]
        self._index = 0

    def rand(self) -> int:
        if not self._values:
            return 0
        if self._index >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._index])
        self._index += 1
        return value


def test_perks_update_effects_jinxed_kills_creature_and_awards_base_reward() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x17F)]
    creatures[2].active = True
    creatures[2].hp = 100.0
    creatures[2].hitbox_size = 16.0
    creatures[2].reward_value = 12.7

    state = GameplayState()
    state.rng = _ScriptedRng(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            2,  # creature index: rand%0x17f
        ]
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=100, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert math.isclose(state.jinxed_timer, 1.8, abs_tol=1e-9)
    assert creatures[2].hp == -1.0
    assert math.isclose(creatures[2].hitbox_size, 16.0 - dt * 20.0, abs_tol=1e-9)
    assert player.experience == 112
    assert state.sfx_queue == ["sfx_trooper_inpain_01"]


def test_perks_update_effects_jinxed_accident_damages_player_and_spawns_fx() -> None:
    dt = 0.2

    state = GameplayState()
    state.rng = _ScriptedRng(
        [
            3,  # accident roll
            0,  # timer roll
        ]
    )
    state.bonuses.freeze = 1.0

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player], dt, creatures=[], fx_queue=fx_queue)

    assert math.isclose(state.jinxed_timer, 1.8, abs_tol=1e-9)
    assert math.isclose(player.health, 45.0, abs_tol=1e-9)
    assert fx_queue.count == 2
    assert state.sfx_queue == []
