from __future__ import annotations

from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime.availability import prepare_weapon_availability
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_rng_progression


def test_random_weapon_assigns_a_non_pistol_weapon() -> None:
    state = GameplayState(rng=ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    prepare_weapon_availability(state)
    player = PlayerState(index=0, pos=Vec2())
    player.weapon.weapon_id = WeaponId.PISTOL

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon.weapon_id == WeaponId.ASSAULT_RIFLE


def test_random_weapon_skips_pistol_when_current_is_not_pistol() -> None:
    # First roll is pistol (0 % 33 + 1 = 1), second roll is Assault Rifle (1 % 33 + 1 = 2).
    state = GameplayState(rng=ScriptedCrand([0, 1], fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    prepare_weapon_availability(state)
    player = PlayerState(index=0, pos=Vec2())
    player.weapon.weapon_id = WeaponId.SHOTGUN

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    assert player.weapon.weapon_id == WeaponId.ASSAULT_RIFLE


def test_random_weapon_uses_last_roll_after_100_retries() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # 0 % 33 + 1 = pistol every time
    state = GameplayState(rng=rng)
    prepare_weapon_availability(state)
    player = PlayerState(index=0, pos=Vec2())
    player.weapon.weapon_id = WeaponId.PISTOL
    before_calls = rng.calls
    before_state = rng.state

    perk_apply(state, [player], PerkId.RANDOM_WEAPON)

    # Native behavior: capped retries still apply the last candidate.
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=100,
        expected_after_state=0,
    )
    assert player.weapon.weapon_id == WeaponId.PISTOL
