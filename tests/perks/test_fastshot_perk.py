from __future__ import annotations

from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import WeaponFireCtx, fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def _fire_once(state: GameplayState, player: PlayerState, *, players: list[PlayerState] | None = None) -> float:
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True),
            dt=0.1,
            state=state,
            players=players,
        ),
    )
    return float(player.weapon.shot_cooldown)


def test_fastshot_scales_shot_cooldown() -> None:
    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, ammo=2))
    base_cd = _fire_once(base_state, base_player)

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, ammo=2))
    perk_player.perk_counts[int(PerkId.FASTSHOT)] = 1
    perk_cd = _fire_once(perk_state, perk_player)

    assert_float_close(perk_cd, float(f32(float(base_cd) * 0.88)))


def test_preserve_mode_uses_player_zero_fastshot_for_player_one() -> None:
    base_player = PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, ammo=2))
    base_cd = _fire_once(GameplayState(), base_player)

    state = GameplayState(preserve_bugs=True)
    player0 = PlayerState(index=0, pos=Vec2())
    player0.perk_counts[int(PerkId.FASTSHOT)] = 1
    player1 = PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, ammo=2))

    player1_cd = _fire_once(state, player1, players=[player0, player1])

    assert_float_close(player1_cd, float(f32(float(base_cd) * 0.88)))
