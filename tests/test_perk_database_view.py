from __future__ import annotations

from types import SimpleNamespace

import crimson.frontend.panels.databases as perk_db
from crimson.frontend.panels.databases import UnlockedPerksDatabaseView


def _dummy_state() -> object:
    return SimpleNamespace(audio=None, config=SimpleNamespace(data={"fx_toggle": 0}))


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


def test_wrap_small_text_native_inserts_newline_at_previous_space(monkeypatch) -> None:
    monkeypatch.setattr(perk_db, "measure_small_text_width", lambda _font, text, _scale: float(len(text)))
    wrapped = UnlockedPerksDatabaseView._wrap_small_text_native(object(), "alpha beta", 6.0, scale=1.0)  # type: ignore[arg-type]
    assert wrapped == "alpha\nbeta"


def test_prewrapped_perk_desc_uses_cache(monkeypatch) -> None:
    calls = {"count": 0}

    def _fake_measure(_font, text: str, _scale: float) -> float:
        calls["count"] += 1
        return float(len(text))

    monkeypatch.setattr(perk_db, "measure_small_text_width", _fake_measure)
    monkeypatch.setattr(
        UnlockedPerksDatabaseView,
        "_perk_desc",
        staticmethod(lambda _perk_id, *, fx_toggle=0, preserve_bugs=False: "alpha beta gamma"),  # noqa: ARG005
    )

    view = UnlockedPerksDatabaseView(_dummy_state())  # type: ignore[arg-type]
    first = view._prewrapped_perk_desc(5, object(), fx_toggle=0)  # type: ignore[arg-type]
    count_after_first = calls["count"]
    second = view._prewrapped_perk_desc(5, object(), fx_toggle=0)  # type: ignore[arg-type]

    assert first == second
    assert calls["count"] == count_after_first


def test_perk_prereq_name_uses_first_prereq_entry() -> None:
    assert UnlockedPerksDatabaseView._perk_prereq_name(37) == "Veins of Poison"
    assert UnlockedPerksDatabaseView._perk_prereq_name(40) == "Dodger"
    assert UnlockedPerksDatabaseView._perk_prereq_name(43) == "Perk Expert"
    assert UnlockedPerksDatabaseView._perk_prereq_name(45) == "Regeneration"
