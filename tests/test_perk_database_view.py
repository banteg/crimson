from __future__ import annotations

from typing import cast

import crimson.frontend.panels.databases as perk_db
from crimson.frontend.panels.databases import UnlockedPerksDatabaseView
from grim.fonts.small import SmallFontData


def test_selected_perk_id_uses_selected_row_index(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"fx_toggle": 0}))
    view._perk_ids = [1, 2, 4, 6]
    view._selected_row_index = 2
    assert view._selected_perk_id() == 4


def test_selected_perk_id_returns_none_for_out_of_range_row(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"fx_toggle": 0}))
    view._perk_ids = [1, 2, 4, 6]
    view._selected_row_index = 9
    assert view._selected_perk_id() is None


def test_hovered_perk_id_uses_hovered_row_index(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"fx_toggle": 0}))
    view._perk_ids = [1, 2, 4, 6]
    view._hovered_row_index = 3
    assert view._hovered_perk_id() == 6


def test_hovered_perk_id_returns_none_when_not_hovered(make_game_state) -> None:
    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"fx_toggle": 0}))
    view._perk_ids = [1, 2, 4, 6]
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
    mocker.patch.object(
        UnlockedPerksDatabaseView,
        "_perk_desc",
        staticmethod(lambda _perk_id, *, fx_toggle=0, preserve_bugs=False: "alpha beta gamma"),
    )

    view = UnlockedPerksDatabaseView(make_game_state(config_updates={"fx_toggle": 0}))
    fake_font = cast(SmallFontData, object())
    first = view._prewrapped_perk_desc(5, fake_font, fx_toggle=0)
    count_after_first = measure_mock.call_count
    second = view._prewrapped_perk_desc(5, fake_font, fx_toggle=0)

    assert first == second
    assert measure_mock.call_count == count_after_first


def test_perk_prereq_name_uses_first_prereq_entry() -> None:
    assert UnlockedPerksDatabaseView._perk_prereq_name(37) == "Veins of Poison"
    assert UnlockedPerksDatabaseView._perk_prereq_name(40) == "Dodger"
    assert UnlockedPerksDatabaseView._perk_prereq_name(43) == "Perk Expert"
    assert UnlockedPerksDatabaseView._perk_prereq_name(45) == "Regeneration"
