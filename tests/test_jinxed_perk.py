from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects


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

    assert math.isclose(state.jinxed_timer, 1.8, abs_tol=1e-8)
    assert creatures[2].hp == -1.0
    assert math.isclose(creatures[2].hitbox_size, 16.0 - dt * 20.0, abs_tol=1e-9)
    assert player.experience == 112
    assert state.sfx_queue == ["sfx_trooper_inpain_01"]


def test_perks_update_effects_jinxed_award_uses_float32_sum_before_truncation() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x17F)]
    creatures[2].active = True
    creatures[2].hp = 100.0
    creatures[2].hitbox_size = 16.0
    creatures[2].reward_value = 97.99636190476191

    state = GameplayState()
    state.rng = _ScriptedRng(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            2,  # creature index: rand%0x17f
        ]
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=139_451, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert player.experience == 139_549


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

    assert math.isclose(state.jinxed_timer, 1.8, abs_tol=1e-8)
    assert math.isclose(player.health, 45.0, abs_tol=1e-9)
    assert fx_queue.count == 2
    assert state.sfx_queue == []
def test_perks_update_effects_jinxed_timer_uses_f32_underflow_threshold() -> None:
    # Capture boundary from gameplay_diff_capture tick 5163:
    # native decrements to a tiny positive value and does not proc Jinxed this tick.
    dt = 0.03400000184774399

    state = GameplayState()
    state.jinxed_timer = 0.034000836312770844
    state.rng = _ScriptedRng([3, 0, 7, 9])

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=[])

    assert math.isclose(state.jinxed_timer, 8.344650268554688e-07, abs_tol=1e-15)
    assert math.isclose(player.health, 50.0, abs_tol=1e-9)
    assert state.rng._index == 0  # ty: ignore[attr-defined]
