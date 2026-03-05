from __future__ import annotations

from typing import cast

import crimson.frontend.panels.databases_perks as perk_db
from crimson.frontend.panels.databases import UnlockedPerksDatabaseView
from crimson.perks import PerkId
from grim.fonts.small import SmallFontData


def test_selected_perk_id_uses_selected_row_index(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"gore_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view._selected_row_index = 2
    assert view._selected_perk_id() == PerkId.LEAN_MEAN_EXP_MACHINE


def test_selected_perk_id_returns_none_for_out_of_range_row(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"gore_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view._selected_row_index = 9
    assert view._selected_perk_id() is None


def test_hovered_perk_id_uses_hovered_row_index(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"gore_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view._hovered_row_index = 3
    assert view._hovered_perk_id() == PerkId.PYROKINETIC


def test_hovered_perk_id_returns_none_when_not_hovered(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"gore_disabled": 0}))
    view._perk_ids = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.PYROKINETIC,
    ]
    view._hovered_row_index = -1
    assert view._hovered_perk_id() is None


def test_wrap_small_text_native_inserts_newline_at_previous_space(mocker) -> None:
    mocker.patch.object(perk_db, "measure_small_text_width", side_effect=lambda _font, text, _scale: float(len(text)))
    fake_font = cast(SmallFontData, object())
    wrapped = UnlockedPerksDatabaseView._wrap_small_text_native(fake_font, "alpha beta", 6.0, scale=1.0)
    assert wrapped == "alpha\nbeta"


def test_prewrapped_perk_desc_uses_cache(mocker, make_game_state) -> None:
    measure_mock = mocker.patch.object(
        perk_db,
        "measure_small_text_width",
        side_effect=lambda _font, text, _scale: float(len(text)),
    )

    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"gore_disabled": 0}))
    fake_font = cast(SmallFontData, object())
    first = view._prewrapped_perk_desc(PerkId.LONG_DISTANCE_RUNNER, fake_font, gore_disabled=0)
    count_after_first = measure_mock.call_count
    cache_key = (int(PerkId.LONG_DISTANCE_RUNNER), 0, 0)
    assert cache_key in view._wrapped_desc_cache
    second = view._prewrapped_perk_desc(PerkId.LONG_DISTANCE_RUNNER, fake_font, gore_disabled=0)

    assert first == second
    assert measure_mock.call_count == count_after_first


def test_perk_prereq_name_uses_first_prereq_entry() -> None:
    assert UnlockedPerksDatabaseView._perk_prereq_name(PerkId.TOXIC_AVENGER) == "Veins of Poison"
    assert UnlockedPerksDatabaseView._perk_prereq_name(PerkId.NINJA) == "Dodger"
    assert UnlockedPerksDatabaseView._perk_prereq_name(PerkId.PERK_MASTER) == "Perk Expert"
    assert UnlockedPerksDatabaseView._perk_prereq_name(PerkId.GREATER_REGENERATION) == "Regeneration"
