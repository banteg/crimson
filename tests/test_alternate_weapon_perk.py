from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.gameplay import GameplayState, PlayerInput, PlayerState, bonus_apply, player_update, weapon_assign_player
from crimson.perks import PerkId


def test_alternate_weapon_slows_movement() -> None:
    state = GameplayState()
    base = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    perk = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    perk.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    player_update(base, PlayerInput(move_x=1.0), dt=1.0, state=state)
    player_update(perk, PlayerInput(move_x=1.0), dt=1.0, state=state)

    assert base.pos_x == pytest.approx(50.0)
    assert perk.pos_x == pytest.approx(40.0)


def test_alternate_weapon_stashes_previous_weapon_on_first_weapon_pickup() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    weapon_assign_player(player, 1)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    bonus_apply(state, player, BonusId.WEAPON, amount=2)

    assert player.weapon_id == 2
    assert player.alt_weapon_id == 1
    assert player.alt_clip_size == 12


def test_alternate_weapon_reload_pressed_swaps_and_adds_cooldown() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
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
