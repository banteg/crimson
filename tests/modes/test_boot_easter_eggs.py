from __future__ import annotations

import datetime as dt

from crimson.screens.boot import TEXTURE_LOAD_STAGES, BootView, _is_balloon_easter_egg_day


def test_balloon_easter_egg_day_matches_three_known_dates() -> None:
    assert _is_balloon_easter_egg_day(dt.date(2026, 9, 12)) is True
    assert _is_balloon_easter_egg_day(dt.date(2026, 11, 8)) is True
    assert _is_balloon_easter_egg_day(dt.date(2026, 12, 18)) is True


def test_balloon_easter_egg_day_rejects_other_dates() -> None:
    assert _is_balloon_easter_egg_day(dt.date(2026, 3, 3)) is False
    assert _is_balloon_easter_egg_day(dt.date(2026, 9, 11)) is False


def test_boot_stage_completion_loads_company_logos_before_balloon(make_game_state, mocker) -> None:
    state = make_game_state()
    view = BootView(state)
    load_texture_stage = mocker.patch.object(view, "_load_texture_stage")
    load_company_logos = mocker.patch.object(view, "_load_company_logos")
    load_balloon = mocker.patch.object(view, "_load_balloon_easter_egg_texture")
    prepare_menu_assets = mocker.patch.object(view, "_prepare_menu_assets")

    call_order = mocker.Mock()
    call_order.attach_mock(load_texture_stage, "load_texture_stage")
    call_order.attach_mock(load_company_logos, "load_company_logos")
    call_order.attach_mock(load_balloon, "load_balloon")
    call_order.attach_mock(prepare_menu_assets, "prepare_menu_assets")

    view._texture_stage = len(TEXTURE_LOAD_STAGES) - 1
    view.update(1.0 / 60.0)

    assert call_order.mock_calls == [
        mocker.call.load_texture_stage(len(TEXTURE_LOAD_STAGES) - 1),
        mocker.call.load_company_logos(),
        mocker.call.load_balloon(),
        mocker.call.prepare_menu_assets(),
    ]
