from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from crimson.frontend.boot import TEXTURE_LOAD_STAGES, BootView, _is_balloon_easter_egg_day


def test_balloon_easter_egg_day_matches_three_known_dates() -> None:
    assert _is_balloon_easter_egg_day(dt.date(2026, 9, 12)) is True
    assert _is_balloon_easter_egg_day(dt.date(2026, 11, 8)) is True
    assert _is_balloon_easter_egg_day(dt.date(2026, 12, 18)) is True


def test_balloon_easter_egg_day_rejects_other_dates() -> None:
    assert _is_balloon_easter_egg_day(dt.date(2026, 3, 3)) is False
    assert _is_balloon_easter_egg_day(dt.date(2026, 9, 11)) is False


def test_boot_stage_completion_loads_company_logos_before_balloon(monkeypatch) -> None:
    state = SimpleNamespace(audio=None, texture_cache=None)
    view = BootView(state)
    calls: list[str] = []

    monkeypatch.setattr(view, "_load_texture_stage", lambda stage: calls.append(f"stage:{stage}"))
    monkeypatch.setattr(view, "_load_company_logos", lambda: calls.append("company"))
    monkeypatch.setattr(view, "_load_balloon_easter_egg_texture", lambda: calls.append("balloon"))
    monkeypatch.setattr(view, "_prepare_menu_assets", lambda: calls.append("menu"))

    view._texture_stage = len(TEXTURE_LOAD_STAGES) - 1
    view.update(1.0 / 60.0)

    assert calls == [f"stage:{len(TEXTURE_LOAD_STAGES) - 1}", "company", "balloon", "menu"]
