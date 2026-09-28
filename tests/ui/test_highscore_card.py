from __future__ import annotations

import datetime as dt
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

import pytest

import crimson.ui.highscore_card as card
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.highscore_card import ui_text_input_render
from crimson.weapons import WeaponId
from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.raylib_api import rl

DIVIDER = (149, 175, 198, 178)


class _Resources:
    small_font = SimpleNamespace()

    def texture(self, _texture_id: TextureId) -> rl.Texture:
        texture = rl.Texture()
        texture.width = 256
        texture.height = 256
        return texture


def _record(mode: GameMode) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.set_name("tester")
    record.game_mode_id = mode
    record.score_xp = 1234
    record.survival_elapsed_ms = 65_000
    record.creature_kill_count = 10
    record.shots_fired = 40
    record.shots_hit = 9
    record.most_used_weapon_id = WeaponId.SHOTGUN
    return record


class _Drawn:
    def __init__(self, text: MagicMock, rect: MagicMock) -> None:
        self._text = text
        self._rect = rect

    @property
    def texts(self) -> dict[str, tuple[Vec2, tuple[int, int, int, int]]]:
        return {
            str(call.args[1]): (call.args[2], (call.args[3].r, call.args[3].g, call.args[3].b, call.args[3].a))
            for call in self._text.call_args_list
        }

    @property
    def rects(self) -> list[tuple[float, float, float, float]]:
        return [(c.args[0].x, c.args[0].y, c.args[0].width, c.args[0].height) for c in self._rect.call_args_list]

    def clear(self) -> None:
        self._text.reset_mock()
        self._rect.reset_mock()


@pytest.fixture
def drawn(mocker) -> _Drawn:
    card._hover.weapon = card._hover.time = card._hover.hit_ratio = 0.0
    mocker.patch.object(card, "measure_small_text_width", side_effect=lambda _font, value: float(len(value) * 8))
    mocker.patch.object(card.rl, "draw_texture_pro")
    return _Drawn(mocker.patch.object(card, "draw_small_text"), mocker.patch.object(card.rl, "draw_rectangle_rec"))


def _render(record: HighScoreRecord, state: GameStateId, phase: int, *, mouse=(0.0, 0.0), dt: float = 0.0) -> None:
    ui_text_input_render(
        Vec2(100.0, 200.0), record, 1.0, 3,
        game_state=state, ui_phase=phase, resources=cast("RuntimeResources", _Resources()),
        mouse=rl.Vector2(*mouse), dt=dt,
    )


def test_quest_name_entry_card_matches_native_layout(drawn: _Drawn) -> None:
    _render(_record(GameMode.QUESTS), GameStateId.QUEST_RESULTS, 1)

    assert drawn.texts["Score"][0] == Vec2(116.0, 200.0)
    assert drawn.texts["65.00 secs"][0] == Vec2(96.0, 215.0)
    assert drawn.texts["Rank: 3rd"][0] == Vec2(100.0, 230.0)
    # The vertical divider leaves its color current for the "Experience" label.
    assert drawn.texts["Experience"] == (Vec2(200.0, 200.0), DIVIDER)
    assert drawn.texts["Frags: 10"][0] == Vec2(214.0, 257.0)
    assert drawn.texts["Hit %: 22%"][0] == Vec2(214.0, 271.0)
    assert drawn.rects == [(184.0, 200.0, 1.0, 48.0), (88.0, 252.0, 192.0, 1.0), (88.0, 304.0, 192.0, 1.0)]


@pytest.mark.parametrize(
    ("state", "phase", "row"),
    [
        (GameStateId.GAME_OVER, 0, False),
        (GameStateId.GAME_OVER, 1, True),
        (GameStateId.QUEST_RESULTS, 1, True),
        (GameStateId.QUEST_RESULTS, 2, False),
        (GameStateId.QUEST_FAILED, 0, False),
        (GameStateId.HIGHSCORES, 0, True),
    ],
)
def test_weapon_row_follows_state_and_phase(drawn: _Drawn, state: GameStateId, phase: int, row: bool) -> None:
    _render(_record(GameMode.SURVIVAL), state, phase)

    assert ("Frags: 10" in drawn.texts) is row
    assert ("Rank: 3rd" in drawn.texts) is (state != GameStateId.QUEST_FAILED)


def test_highscore_screen_card_adds_name_date_and_underline(drawn: _Drawn) -> None:
    record = _record(GameMode.SURVIVAL)
    record.ensure_date_fields(dt.date(2026, 1, 31))

    _render(record, GameStateId.HIGHSCORES, 0)

    assert drawn.texts["tester"] == (Vec2(104.0, 200.0), (255, 255, 255, 255))
    assert drawn.texts["Local score"][0] == Vec2(104.0, 214.0)
    assert drawn.texts["31. Jan 2026"][0] == Vec2(208.0, 228.0)
    assert drawn.rects[0] == (104.0, 213.0, 48.0, 1.0)
    assert drawn.texts["Game time"] == (Vec2(218.0, 246.0), DIVIDER)
    assert drawn.texts["1:05"][0] == Vec2(252.0, 265.0)


def test_negative_quest_score_shows_signed_seconds(drawn: _Drawn) -> None:
    record = _record(GameMode.QUESTS)
    record.survival_elapsed_ms = -500

    _render(record, GameStateId.QUEST_RESULTS, 2)

    assert "-0.50 secs" in drawn.texts


def test_hover_tooltips_fade_in_on_result_screens_only(drawn: _Drawn) -> None:
    hit_ratio_area = (230.0, 280.0)
    tooltip = "The % of shot bullets hit the target"
    record = _record(GameMode.SURVIVAL)

    for _ in range(11):
        _render(record, GameStateId.GAME_OVER, 1, mouse=hit_ratio_area, dt=0.05)
    assert card._hover.hit_ratio == 1.0
    assert tooltip in drawn.texts

    drawn.clear()
    _render(record, GameStateId.HIGHSCORES, 0)
    assert card._hover.hit_ratio == 1.0
    assert tooltip not in drawn.texts
