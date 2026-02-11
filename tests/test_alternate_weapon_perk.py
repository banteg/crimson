from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update, weapon_assign_player
from crimson.perks import PerkId


def test_alternate_weapon_slows_movement() -> None:
    state = GameplayState()
    move_heading = Vec2(1.0, 0.0).to_heading()
    base = PlayerState(index=0, pos=Vec2(), move_speed=2.0, heading=move_heading)
    perk = PlayerState(index=0, pos=Vec2(), move_speed=2.0, heading=move_heading)
    perk.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    player_update(base, PlayerInput(move=Vec2(1.0, 0.0)), dt=1.0, state=state)
    player_update(perk, PlayerInput(move=Vec2(1.0, 0.0)), dt=1.0, state=state)

    assert base.pos.x == pytest.approx(100.0)
    assert perk.pos.x == pytest.approx(80.0)


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
    assert player.shot_cooldown == pytest.approx(0.1)


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
    assert player.shot_cooldown == pytest.approx(0.1)
