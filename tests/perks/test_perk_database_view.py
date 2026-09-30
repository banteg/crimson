from __future__ import annotations

from crimson.perks import PerkId
from crimson.screens.panels.databases import UnlockedPerksDatabaseView


def test_selected_perk_id_uses_the_list_selection(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"violence_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view.list_scroll.selected_index = 2
    assert view._selected_perk_id() == PerkId.LEAN_MEAN_EXP_MACHINE


def test_selected_perk_id_returns_none_for_out_of_range_row(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"violence_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view.list_scroll.selected_index = 9
    assert view._selected_perk_id() is None


def test_hovered_perk_id_uses_hovered_row_index(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"violence_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view.list_scroll.hovered_index = 3
    assert view._hovered_perk_id() == PerkId.PYROKINETIC


def test_hovered_perk_id_returns_none_when_not_hovered(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"violence_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view.list_scroll.hovered_index = -1
    assert view._hovered_perk_id() is None
