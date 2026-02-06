from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import BonusPool, GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.weapons import WeaponId


class _SequenceRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values]
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return 0
        value = self._values[self._idx]
        self._idx += 1
        return int(value)


def test_bonus_magnet_allows_bonus_spawn_on_secondary_roll() -> None:
    base_state = GameplayState()
    base_state.rng = _SequenceRng([0])
    base_state.bonus_pool = BonusPool()
    base_player = PlayerState(index=0, pos=Vec2(), weapon_id=int(WeaponId.ASSAULT_RIFLE))

    assert (
        base_state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=base_state, players=[base_player])
        is None
    )

    perk_state = GameplayState()
    perk_state.rng = _SequenceRng([0, 2, 0, 0])
    perk_state.bonus_pool = BonusPool()
    perk_player = PlayerState(index=0, pos=Vec2(), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    perk_player.perk_counts[int(PerkId.BONUS_MAGNET)] = 1

    assert (
        perk_state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=perk_state, players=[perk_player])
        is not None
    )
