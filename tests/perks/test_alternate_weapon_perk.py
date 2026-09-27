from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import player_update
from crimson.math_parity import f32, x87_pc24_mul
from crimson.movement_controls import MovementControlType
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_reset import reset_world_players
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, step_player
from tests.support.helpers import assert_float_close


def _alt(player: PlayerState) -> WeaponSlot:
    assert player.alt_weapon is not None
    return player.alt_weapon


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

    step_player(world, player, PlayerInput(reload_pressed=True, fire_down=True, aim=Vec2(700.0, 512.0)), 0.01)

    # Native captures both ready flags before swapping, then charges the new
    # weapon despite its zero reload timer and the swap's added cooldown.
    assert player.weapon.weapon_id == WeaponId.PISTOL
    assert player.shot_seq == 1
    assert_float_close(player.weapon.ammo, 11.0)
    assert state.survival_reward_fire_seen
    assert player.experience == expected_xp
    assert_float_close(player.health, expected_health)


def test_alternate_weapon_slows_movement() -> None:
    move_heading = Vec2(1.0, 0.0).to_heading()
    base_world = make_world()
    perk_world = make_world()
    perk_world.state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    base = base_world.players[0]
    perk = perk_world.players[0]
    for player in (base, perk):
        player.pos = Vec2()
        player.move_speed = 2.0
        player.heading = move_heading

    step_player(base_world, base, PlayerInput(move=Vec2(1.0, 0.0)), 1.0)
    step_player(perk_world, perk, PlayerInput(move=Vec2(1.0, 0.0)), 1.0)

    # player_apply_move_with_spawn_avoidance scales the delta by 0.8f at PC24.
    assert base.pos.x == pytest.approx(100.0, abs=1e-4)
    assert perk.pos.x == x87_pc24_mul(base.pos.x, f32(0.8))


def test_alternate_weapon_starts_with_preloaded_pistol_alt_slot() -> None:
    state = GameplayState()
    players: list[PlayerState] = []
    reset_world_players(players, state=state, player_count=1)
    player = players[0]
    alt = _alt(player)

    assert player.weapon.weapon_id == 1
    assert alt.weapon_id == 1
    assert alt.clip_size == 12
    assert_float_close(alt.ammo, 12.0)
    assert alt.reload_active is False
    assert_float_close(alt.reload_timer_max, 1.2)


def test_alternate_weapon_first_weapon_pickup_keeps_preloaded_pistol_slot() -> None:
    world = make_world()
    player = world.players[0]
    world.state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1

    _pick_up_weapon(world, player, WeaponId.ASSAULT_RIFLE)
    alt = _alt(player)

    assert player.weapon.weapon_id == 2
    assert alt.weapon_id == 1
    assert alt.clip_size == 12
    assert_float_close(alt.ammo, 12.0)


def test_alternate_weapon_reload_pressed_swaps_and_adds_cooldown() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    _pick_up_weapon(world, player, WeaponId.ASSAULT_RIFLE)
    alt = _alt(player)

    assert player.weapon.weapon_id == 2
    assert alt.weapon_id == 1

    player.weapon.shot_cooldown = 0.0
    state.sfx_queue.clear()
    step_player(world, player, PlayerInput(reload_pressed=True), 0.1)
    alt = _alt(player)

    assert player.weapon.weapon_id == 1
    assert alt.weapon_id == 2
    assert player.weapon.shot_cooldown == f32(0.1)


def test_alternate_weapon_reload_pressed_still_swaps_in_point_click_mode() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    _pick_up_weapon(world, player, WeaponId.ASSAULT_RIFLE)

    player.weapon.shot_cooldown = 0.0
    state.sfx_queue.clear()
    step_player(world, player, PlayerInput(reload_pressed=True, move_mode=MovementControlType.MOUSE_POINT_CLICK), 0.1)
    alt = _alt(player)

    assert player.weapon.weapon_id == 1
    assert alt.weapon_id == 2
    assert player.weapon.shot_cooldown == f32(0.1)


def test_alternate_weapon_swap_preserves_same_tick_fire_gate() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    _pick_up_weapon(world, player, WeaponId.PLASMA_MINIGUN)
    alt = _alt(player)

    assert player.weapon.weapon_id == 11
    assert alt.weapon_id == 1
    starting_alt_ammo = float(alt.ammo)

    player.weapon.shot_cooldown = 0.05
    step_player(world, player, PlayerInput(aim=Vec2(700.0, 512.0), reload_pressed=True, fire_down=True), 0.06)

    assert player.weapon.weapon_id == 1
    assert player.weapon.ammo < starting_alt_ammo


def test_alternate_weapon_swap_allows_same_tick_fire_with_swapped_reload_timer() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    weapon_assign_player(player, WeaponId.SPLITTER_GUN, state=state)
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    player.weapon.ammo = 2.0
    player.weapon.reload_timer = 0.0
    player.weapon.reload_active = False
    player.alt_weapon = WeaponSlot(
        weapon_id=WeaponId.PLASMA_MINIGUN,
        clip_size=30,
        ammo=0.0,
        reload_active=True,
        reload_timer=0.85,
        reload_timer_max=1.3,
        shot_cooldown=0.0,
    )

    player.weapon.shot_cooldown = 0.05
    step_player(world, player, PlayerInput(aim=Vec2(700.0, 512.0), reload_pressed=True, fire_down=True), 0.06)

    assert player.weapon.weapon_id == 11
    assert player.weapon.reload_timer > 0.0
    assert_float_close(player.weapon.reload_timer, player.weapon.reload_timer_max)
    assert player.weapon.ammo < 0.0
    assert player.shot_seq >= 1


def test_alternate_weapon_swap_held_reload_uses_native_cooldown_gate() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    _pick_up_weapon(world, player, WeaponId.ASSAULT_RIFLE)

    assert player.weapon.weapon_id == 2
    step_player(world, player, PlayerInput(reload_pressed=True), 0.05)
    assert player.weapon.weapon_id == 1
    assert player.weapon.shot_cooldown == f32(0.1)
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    for _ in range(3):
        step_player(world, player, PlayerInput(reload_pressed=True), 0.05)
        assert player.weapon.weapon_id == 1

    step_player(world, player, PlayerInput(reload_pressed=True), 0.05)
    assert player.weapon.weapon_id == 2
    assert state.player_alt_weapon_swap_cooldown_ms == 200


def test_alternate_weapon_swap_release_resets_cooldown_gate() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    state.perks[int(PerkId.ALTERNATE_WEAPON)] = 1
    _pick_up_weapon(world, player, WeaponId.ASSAULT_RIFLE)

    step_player(world, player, PlayerInput(reload_pressed=True), 0.05)
    assert player.weapon.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    step_player(world, player, PlayerInput(reload_pressed=False), 0.05)
    assert state.player_alt_weapon_swap_cooldown_ms == 0

    step_player(world, player, PlayerInput(reload_pressed=True), 0.05)
    assert player.weapon.weapon_id == 2


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
        PlayerInput(reload_pressed=True, reload_down=True),
        0.05,
        step_runtime=make_step_runtime(world, dt=0.05),
        reload_active_any=True,
    )
    assert player0.weapon.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    player_update(
        player1,
        PlayerInput(reload_pressed=False),
        0.05,
        step_runtime=make_step_runtime(world, dt=0.05),
        reload_active_any=True,
    )
    assert state.player_alt_weapon_swap_cooldown_ms > 0

    player_update(
        player0,
        PlayerInput(reload_pressed=False, reload_down=True),
        0.05,
        step_runtime=make_step_runtime(world, dt=0.05),
        reload_active_any=True,
    )
    assert player0.weapon.weapon_id == 1
