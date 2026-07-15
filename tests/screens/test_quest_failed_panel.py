from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

import crimson.screens.quest_views.quest_failed as quest_failed_module
from crimson.modes.quest_mode import QuestRunOutcome
from crimson.quests.level import QuestLevel
from crimson.screens.quest_views import QUEST_FAILED_PANEL_SLIDE_DURATION_MS, QUEST_FAILED_PANEL_W, QuestFailedView
from crimson.weapons import WeaponId
from grim import music as grim_music
from grim import sfx as grim_sfx
from grim.assets import RuntimeResources
from grim.audio import AudioState
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId


class _PauseBackgroundStub:
    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        _ = float(entity_alpha)


def _dummy_audio_state() -> AudioState:
    return AudioState(
        ready=False,
        music=grim_music.init_music_state(ready=False, enabled=False, volume=1.0),
        sfx=grim_sfx.init_sfx_state(ready=False, enabled=False, volume=1.0),
    )


def _texture_stub() -> rl.Texture:
    return SimpleNamespace(width=1, height=1)  # type: ignore[return-value]


def _resources_stub() -> RuntimeResources:
    tex = _texture_stub()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: tex,
            small_font=SimpleNamespace(cell_size=8, widths=[8] * 256),
        ),
    )


@pytest.fixture
def quest_failed_state(make_game_state, tmp_path):
    state = make_game_state(assets_root=tmp_path, audio=_dummy_audio_state())
    # Avoid ground/menu asset loading in tests.
    state.pause_background = _PauseBackgroundStub()
    state.resources = _resources_stub()
    return state


def _failed_outcome() -> QuestRunOutcome:
    return QuestRunOutcome(
        kind="failed",
        level=QuestLevel(5, 10),
        base_time_ms=7_000,
        player_health=0.0,
        player2_health=None,
        pending_perk_count=0,
        experience=123,
        kill_count=45,
        weapon_id=WeaponId.PISTOL,
        shots_fired=100,
        shots_hit=42,
        most_used_weapon_id=WeaponId.PISTOL,
        highscore_random_tag=0x0AAC0004,
    )


def test_quest_failed_preserves_start_random_tag(quest_failed_state) -> None:
    state = quest_failed_state
    state.quest_outcome = _failed_outcome()

    view = QuestFailedView(state)
    view.open()

    assert view._record is not None
    assert view._record.uni_num == 0x0AAC0004


def test_quest_failed_panel_layout_uses_native_anchor(monkeypatch, quest_failed_state, mocker) -> None:
    view = QuestFailedView(quest_failed_state)

    mocker.patch.object(quest_failed_module.rl, "get_screen_width", side_effect=lambda: 640)
    panel_640 = view._panel_origin()
    assert panel_640.x == -108.0
    assert panel_640.y == 29.0

    mocker.patch.object(quest_failed_module.rl, "get_screen_width", side_effect=lambda: 1024)
    panel_1024 = view._panel_origin()
    assert panel_1024.x == -108.0
    assert panel_1024.y == 119.0


def test_quest_failed_panel_slides_in_from_left(monkeypatch, quest_failed_state, mocker) -> None:
    view = QuestFailedView(quest_failed_state)

    mocker.patch.object(quest_failed_module.rl, "get_screen_width", side_effect=lambda: 640)
    base = view._panel_origin()

    view._intro_ms = 0.0
    assert view._panel_top_left().x == base.x - QUEST_FAILED_PANEL_W

    view._intro_ms = 250.0
    assert view._panel_top_left().x == base.x


def test_quest_failed_retry_message_respects_preserve_bugs(quest_failed_state) -> None:
    state = quest_failed_state
    state.quest_fail_retry_count = 4
    view = QuestFailedView(state)

    state.preserve_bugs = False
    assert view._failure_message() == "Persistence will be rewarded."

    state.preserve_bugs = True
    assert view._failure_message() == "Persistence will be rewared."


def test_quest_failed_enter_retries_current_quest(monkeypatch, quest_failed_state, mocker) -> None:
    state = quest_failed_state
    state.quest_outcome = _failed_outcome()
    state.quest_fail_retry_count = 2

    play_sfx = mocker.Mock()
    mocker.patch.object(quest_failed_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(quest_failed_module, "play_sfx", side_effect=play_sfx)
    mocker.patch.object(quest_failed_module.rl, "is_key_pressed", side_effect=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER))

    view = QuestFailedView(state)
    view.open()
    view.update(0.016)

    assert state.quest_fail_retry_count == 3
    assert state.pending_quest_level == QuestLevel(5, 10)
    assert [call.args[1] for call in play_sfx.call_args_list] == [SfxId.UI_BUTTONCLICK]
    assert view.take_action() is None
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "start_quest"


def test_quest_failed_q_opens_quest_list(monkeypatch, quest_failed_state, mocker) -> None:
    state = quest_failed_state
    state.quest_outcome = _failed_outcome()
    state.quest_fail_retry_count = 4

    play_sfx = mocker.Mock()
    mocker.patch.object(quest_failed_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(quest_failed_module, "play_sfx", side_effect=play_sfx)
    mocker.patch.object(quest_failed_module.rl, "is_key_pressed", side_effect=lambda key: int(key) == int(rl.KeyboardKey.KEY_Q))

    view = QuestFailedView(state)
    view.open()
    view.update(0.016)

    assert state.quest_fail_retry_count == 0
    assert [call.args[1] for call in play_sfx.call_args_list] == [SfxId.UI_BUTTONCLICK]
    assert view.take_action() is None
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "open_quests"


def test_quest_failed_main_menu_waits_for_exit_transition(monkeypatch, quest_failed_state, mocker) -> None:
    state = quest_failed_state
    state.quest_outcome = _failed_outcome()
    state.quest_fail_retry_count = 4

    play_sfx = mocker.Mock()
    mocker.patch.object(quest_failed_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(quest_failed_module, "play_sfx", side_effect=play_sfx)
    mocker.patch.object(quest_failed_module.rl, "is_key_pressed", side_effect=lambda key: int(key) == int(rl.KeyboardKey.KEY_ESCAPE))

    view = QuestFailedView(state)
    view.open()
    view.update(0.016)

    assert state.quest_fail_retry_count == 0
    assert [call.args[1] for call in play_sfx.call_args_list] == [SfxId.UI_BUTTONCLICK]
    assert view.take_action() is None
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "back_to_menu"


def test_quest_failed_score_block_matches_native_fields(monkeypatch, quest_failed_state, mocker) -> None:
    state = quest_failed_state
    state.quest_outcome = _failed_outcome()
    view = QuestFailedView(state)

    view.open()

    drawn_text: list[str] = []
    drawn_lines: list[tuple[int, int, int, int]] = []
    drawn_rects: list[tuple[int, int, int, int]] = []

    def _draw_small_text(_font, text, pos, color):
        drawn_text.append(str(text))

    def _draw_line(x1, y1, x2, y2, color):
        drawn_lines.append((int(x1), int(y1), int(x2), int(y2)))

    def _draw_rect(x, y, w, h, color):
        drawn_rects.append((int(x), int(y), int(w), int(h)))

    mocker.patch.object(quest_failed_module, "draw_small_text", side_effect=_draw_small_text)
    mocker.patch.object(quest_failed_module.rl, "draw_line", side_effect=_draw_line)
    mocker.patch.object(quest_failed_module.rl, "draw_rectangle", side_effect=_draw_rect)
    mocker.patch.object(quest_failed_module.rl, "measure_text", side_effect=lambda text, _size: len(str(text)) * 8)

    view._draw_score_preview(state.resources.small_font, panel_top_left=Vec2(-108.0, 29.0))

    assert "Score" in drawn_text
    assert "Experience" in drawn_text
    assert "Rank: 1" not in drawn_text
    assert not any(text.startswith("Frags:") for text in drawn_text)
    assert not any(text.startswith("Hit %:") for text in drawn_text)
    assert drawn_lines  # vertical separator
    assert any(w == 192 and h == 1 for (_x, _y, w, h) in drawn_rects)  # horizontal separator


def test_quest_failed_draw_fades_pause_background_during_close(quest_failed_state, mocker) -> None:
    state = quest_failed_state
    state.quest_outcome = _failed_outcome()
    pause_background = mocker.Mock()
    state.pause_background = pause_background
    view = QuestFailedView(state)
    mocker.patch.object(quest_failed_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(quest_failed_module, "_draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module, "_draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module, "draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module, "draw_small_text", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module.rl, "draw_texture_pro", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_failed_module, "button_width", side_effect=lambda *_args, **_kwargs: 82.0)
    mocker.patch.object(view, "_draw_score_preview", side_effect=lambda *_args, **_kwargs: None)

    view.open()
    view._closing = True
    view._intro_ms = QUEST_FAILED_PANEL_SLIDE_DURATION_MS * 0.5
    view.draw()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=0.5)
