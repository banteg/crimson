from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import player_update
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, player_input, step_player
from tests.support.helpers import assert_float_close


def _pick_up_weapon(world: WorldState, player: PlayerState, weapon_id: WeaponId) -> None:
    bonus_apply(
        world.state,
        player,
        BonusId.WEAPON,
        step_runtime=make_step_runtime(world),
        amount=int(weapon_id),
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
    )


@pytest.mark.parametrize("regression,ammunition,expected_xp,expected_health", [
    (True, False, 760, 100.0),
    (False, True, 1000, 99.0),
    (True, True, 760, 100.0),
])
def test_alternate_weapon_swap_preserves_perk_firing_and_charges_incoming_weapon(
    regression: bool, ammunition: bool, expected_xp: int, expected_health: float,
) -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    weapon_assign_player(player, WeaponId.PLASMA_MINIGUN, state=state)
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    state.perks[int(PerkId.REGRESSION_BULLETS)] = int(regression)
    state.perks[int(PerkId.AMMUNITION_WITHIN)] = int(ammunition)
    player.experience = 1000
    player.weapon.shot_cooldown = 0.0
    player.weapon.reload_timer = 1.0
    player.weapon.reload_timer_max = 1.0
    player.weapon.reload_active = True
    player.alt_weapon = WeaponSlot(
        weapon_id=WeaponId.PISTOL, clip_size=12, ammo=12.0,
        reload_timer=0.0, reload_timer_max=1.2, shot_cooldown=0.0,
    )

    step_player(world, player, player_input(reload_pressed=True, fire_down=True, aim=Vec2(700.0, 512.0)), 0.01)

    # Native captures both ready flags before swapping, then charges the new
    # weapon despite its zero reload timer and the swap's added cooldown.
    assert player.weapon.weapon_id == WeaponId.PISTOL
    assert_float_close(player.weapon.ammo, 11.0)
    assert state.survival_reward_fire_seen
    assert player.experience == expected_xp
    assert_float_close(player.health, expected_health)


def test_alternate_weapon_multiplayer_hold_not_cleared_by_other_player() -> None:
    world = make_world(player_count=2)
    state = world.state
    players = world.players
    player0, player1 = players
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1

    for player in players:
        _pick_up_weapon(world, player, WeaponId.ASSAULT_RIFLE)
    player_update(
        player0,
        player_input(reload_pressed=True, reload_down=True),
        0.05,
        step_runtime=make_step_runtime(world, dt=0.05),
        reload_key_down_any=True,
    )
    assert player0.weapon.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    player_update(
        player1,
        player_input(reload_pressed=False),
        0.05,
        step_runtime=make_step_runtime(world, dt=0.05),
        reload_key_down_any=True,
    )
    assert state.player_alt_weapon_swap_cooldown_ms > 0

    player_update(
        player0,
        player_input(reload_pressed=False, reload_down=True),
        0.05,
        step_runtime=make_step_runtime(world, dt=0.05),
        reload_key_down_any=True,
    )
    assert player0.weapon.weapon_id == 1
