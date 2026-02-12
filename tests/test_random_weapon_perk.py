from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply


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


class _CountingFixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)
        self.calls = 0

    def rand(self) -> int:
        self.calls += 1
        return int(self._value)


def test_random_weapon_assigns_a_non_pistol_weapon() -> None:
    state = GameplayState(rng=_FixedRng(1))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2())
    player.weapon_id = 1  # pistol

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == 2


def test_random_weapon_skips_pistol_when_current_is_not_pistol() -> None:
    # First roll is pistol (0 % 33 + 1 = 1), second roll is Assault Rifle (1 % 33 + 1 = 2).
    state = GameplayState(rng=_SequenceRng([0, 1]))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2())
    player.weapon_id = 3  # shotgun

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == 2


def test_random_weapon_uses_last_roll_after_100_retries() -> None:
    rng = _CountingFixedRng(0)  # 0 % 33 + 1 = pistol every time
    state = GameplayState(rng=rng)  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2())
    player.weapon_id = 1

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    # Native behavior: capped retries still apply the last candidate.
    assert rng.calls == 100
    assert player.weapon_id == 1
