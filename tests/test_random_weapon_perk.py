from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_random_weapon_assigns_a_non_pistol_weapon() -> None:
    state = GameplayState(rng=_FixedRng(1))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    player.weapon_id = 1  # pistol

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == 2
