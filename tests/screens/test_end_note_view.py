from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import crimson.screens.quest_views.end_note as end_note_module
from crimson.screens.panels.base import PANEL_TIMELINE_START_MS
from crimson.screens.quest_views import EndNoteView
from grim.assets import RuntimeResources
from grim.raylib_api import rl
from grim.sfx_map import SfxId


def _texture_stub() -> rl.Texture:
    return cast("rl.Texture", SimpleNamespace(width=1, height=1))


def _font_stub() -> SimpleNamespace:
    return SimpleNamespace(cell_size=8, widths=[8] * 256)


def _resources_stub() -> RuntimeResources:
    tex = _texture_stub()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: tex,
            small_font=_font_stub(),
        ),
    )


def test_end_note_escape_waits_for_close_transition(make_game_state, tmp_path, mocker) -> None:
    state = make_game_state(assets_root=tmp_path, audio=object())
    state.resources = _resources_stub()
    play_sfx = mocker.patch.object(end_note_module, "play_sfx")

    mocker.patch.object(end_note_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(end_note_module, "ensure_menu_ground", return_value=None)
    mocker.patch.object(end_note_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    view = EndNoteView(state)
    view.open()
    view.update(0.1)
    view.update(0.1)
    view.update(0.1)

    mocker.patch.object(end_note_module.rl, "is_key_pressed", side_effect=lambda key: int(key) == int(rl.KeyboardKey.KEY_ESCAPE))
    view.update(0.1)

    assert [call.args[1] for call in play_sfx.call_args_list] == [SfxId.UI_BUTTONCLICK]
    assert view.take_action() is None

    mocker.patch.object(end_note_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    action = None
    for _ in range(30):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "back_to_menu"


def test_end_note_draw_fades_pause_background_during_close(make_game_state, tmp_path, mocker) -> None:
    state = make_game_state(assets_root=tmp_path, audio=None)
    state.resources = _resources_stub()
    pause_background = mocker.Mock()
    state.pause_background = pause_background

    mocker.patch.object(end_note_module, "update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch.object(end_note_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(end_note_module, "_draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(end_note_module, "draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(end_note_module, "draw_small_text", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(end_note_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(end_note_module, "button_width", side_effect=lambda *_args, **_kwargs: 96.0)
    mocker.patch.object(end_note_module, "_draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)

    view = EndNoteView(state)
    view.open()
    view._closing = True
    view._timeline_ms = PANEL_TIMELINE_START_MS // 2
    view.draw()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=0.5)
