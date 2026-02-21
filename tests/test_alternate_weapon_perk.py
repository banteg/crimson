from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import weapon_assign_player
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_alternate_weapon_slows_movement() -> None:
    state = GameplayState()
    move_heading = Vec2(1.0, 0.0).to_heading()
    base = PlayerState(index=0, pos=Vec2(), move_speed=2.0, heading=move_heading)
    perk = PlayerState(index=0, pos=Vec2(), move_speed=2.0, heading=move_heading)
    perk.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    player_update(base, PlayerInput(move=Vec2(1.0, 0.0)), dt=1.0, state=state)
    player_update(perk, PlayerInput(move=Vec2(1.0, 0.0)), dt=1.0, state=state)

    assert_float_close(base.pos.x, 100.0)
    assert_float_close(perk.pos.x, 80.0)


def test_alternate_weapon_stashes_previous_weapon_on_first_weapon_pickup() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    bonus_apply(state, player, BonusId.WEAPON, amount=2)

    assert player.weapon_id == 2
    assert player.alt_weapon_id == 1
    assert player.alt_clip_size == 10


def test_alternate_weapon_reload_pressed_swaps_and_adds_cooldown() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(state, player, BonusId.WEAPON, amount=2)

    assert player.weapon_id == 2
    assert player.alt_weapon_id == 1

    player.shot_cooldown = 0.0
    state.sfx_queue.clear()
    player_update(player, PlayerInput(reload_pressed=True), dt=0.1, state=state)

    assert player.weapon_id == 1
    assert player.alt_weapon_id == 2
    assert_float_close(player.shot_cooldown, 0.1)


def test_alternate_weapon_reload_pressed_still_swaps_in_move_to_cursor_mode() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(state, player, BonusId.WEAPON, amount=2)

    player.shot_cooldown = 0.0
    state.sfx_queue.clear()
    player_update(
        player,
        PlayerInput(reload_pressed=True, move_to_cursor_pressed=True),
        dt=0.1,
        state=state,
    )

    assert player.weapon_id == 1
    assert player.alt_weapon_id == 2
    assert_float_close(player.shot_cooldown, 0.1)


def test_alternate_weapon_swap_preserves_same_tick_fire_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(state, player, BonusId.WEAPON, amount=11)

    assert player.weapon_id == 11
    assert player.alt_weapon_id == 1
    starting_alt_ammo = float(player.alt_ammo)

    player.shot_cooldown = 0.05
    player_update(
        player,
        PlayerInput(aim=Vec2(700.0, 512.0), reload_pressed=True, fire_down=True),
        dt=0.06,
        state=state,
    )

    assert player.weapon_id == 1
    assert player.ammo < starting_alt_ammo


def test_alternate_weapon_swap_allows_same_tick_fire_with_swapped_reload_timer() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 29)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    player.ammo = 2.0
    player.reload_timer = 0.0
    player.reload_active = False
    player.alt_weapon_id = 11
    player.alt_ammo = 0.0
    player.alt_clip_size = 30
    player.alt_reload_active = True
    player.alt_reload_timer = 0.85
    player.alt_reload_timer_max = 1.3
    player.alt_shot_cooldown = 0.0

    player.shot_cooldown = 0.05
    player_update(
        player,
        PlayerInput(aim=Vec2(700.0, 512.0), reload_pressed=True, fire_down=True),
        dt=0.06,
        state=state,
    )

    assert player.weapon_id == 11
    assert player.reload_timer > 0.0
    assert_float_close(player.reload_timer, player.reload_timer_max)
    assert player.ammo < 0.0
    assert player.shot_seq >= 1


def test_alternate_weapon_swap_held_reload_uses_native_cooldown_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(state, player, BonusId.WEAPON, amount=2)

    assert player.weapon_id == 2
    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    for _ in range(3):
        player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
        assert player.weapon_id == 1

    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon_id == 2
    assert state.player_alt_weapon_swap_cooldown_ms == 200


def test_alternate_weapon_swap_release_resets_cooldown_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(state, player, BonusId.WEAPON, amount=2)

    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    player_update(player, PlayerInput(reload_pressed=False), dt=0.05, state=state)
    assert state.player_alt_weapon_swap_cooldown_ms == 0

    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon_id == 2
