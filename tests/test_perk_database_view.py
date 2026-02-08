from __future__ import annotations

from types import SimpleNamespace

from crimson.frontend.panels.databases import UnlockedPerksDatabaseView


def _dummy_state() -> object:
    return SimpleNamespace(audio=None)


def test_selected_perk_id_uses_selected_row_index() -> None:
    view = UnlockedPerksDatabaseView(_dummy_state())  # type: ignore[arg-type]
    view._perk_ids = [1, 2, 4, 6]
    view._selected_row_index = 2
    assert view._selected_perk_id() == 4


def test_selected_perk_id_returns_none_for_out_of_range_row() -> None:
    view = UnlockedPerksDatabaseView(_dummy_state())  # type: ignore[arg-type]
    view._perk_ids = [1, 2, 4, 6]
    view._selected_row_index = 9
    assert view._selected_perk_id() is None


def test_hovered_perk_id_uses_hovered_row_index() -> None:
    view = UnlockedPerksDatabaseView(_dummy_state())  # type: ignore[arg-type]
    view._perk_ids = [1, 2, 4, 6]
    view._hovered_row_index = 3
    assert view._hovered_perk_id() == 6


def test_hovered_perk_id_returns_none_when_not_hovered() -> None:
    view = UnlockedPerksDatabaseView(_dummy_state())  # type: ignore[arg-type]
    view._perk_ids = [1, 2, 4, 6]
    view._hovered_row_index = -1
    assert view._hovered_perk_id() is None


def test_perk_prereq_name_uses_first_prereq_entry() -> None:
    assert UnlockedPerksDatabaseView._perk_prereq_name(37) == "Veins of Poison"
    assert UnlockedPerksDatabaseView._perk_prereq_name(40) == "Dodger"
    assert UnlockedPerksDatabaseView._perk_prereq_name(43) == "Perk Expert"
    assert UnlockedPerksDatabaseView._perk_prereq_name(45) == "Regeneration"
