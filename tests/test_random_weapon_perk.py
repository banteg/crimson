from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.state_types import PlayerState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.helpers import MockCrand


def test_random_weapon_assigns_a_non_pistol_weapon() -> None:
    state = GameplayState(rng=MockCrand(1))
    player = PlayerState(index=0, pos=Vec2())
    player.weapon_id = int(WeaponId.PISTOL)

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == int(WeaponId.ASSAULT_RIFLE)


def test_random_weapon_skips_pistol_when_current_is_not_pistol() -> None:
    # First roll is pistol (0 % 33 + 1 = 1), second roll is Assault Rifle (1 % 33 + 1 = 2).
    state = GameplayState(rng=MockCrand([0, 1], fallback="repeat_last"))
    player = PlayerState(index=0, pos=Vec2())
    player.weapon_id = int(WeaponId.SHOTGUN)

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon_id == int(WeaponId.ASSAULT_RIFLE)


def test_random_weapon_uses_last_roll_after_100_retries() -> None:
    rng = MockCrand(0)  # 0 % 33 + 1 = pistol every time
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2())
    player.weapon_id = int(WeaponId.PISTOL)

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    # Native behavior: capped retries still apply the last candidate.
    assert rng.calls == 100
    assert player.weapon_id == int(WeaponId.PISTOL)
