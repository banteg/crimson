from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)

class _SequenceRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(value) for value in values]
        self._index = 0

    def rand(self) -> int:
        if self._index < len(self._values):
            value = self._values[self._index]
            self._index += 1
            return int(value)
        return int(self._values[-1]) if self._values else 0


def test_random_weapon_assigns_a_non_pistol_weapon() -> None:
    state = GameplayState(rng=_FixedRng(1))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.weapon_id = 1  # pistol

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == 2


def test_random_weapon_skips_pistol_when_current_is_not_pistol() -> None:
    # First roll is pistol (0 % 33 + 1 = 1), second roll is Assault Rifle (1 % 33 + 1 = 2).
    state = GameplayState(rng=_SequenceRng([0, 1]))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.weapon_id = 3  # shotgun

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == 2
