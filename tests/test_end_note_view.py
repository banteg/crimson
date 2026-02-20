from __future__ import annotations

import pyray as rl

import crimson.game.quest_views.end_note as end_note_module
from crimson.frontend.panels.base import PANEL_TIMELINE_START_MS
from crimson.game.quest_views import EndNoteView


class _PauseBackgroundStub:
    def __init__(self, sink: list[float]) -> None:
        self._sink = sink

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        self._sink.append(float(entity_alpha))


def test_end_note_escape_waits_for_close_transition(make_game_state, tmp_path, mocker) -> None:
    state = make_game_state(assets_root=tmp_path, audio=object())
    played: list[str] = []

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):
            class _StubAsset:
                texture = None

            return _StubAsset()

    def _play_sfx(_audio, key, *, rng=None, allow_variants=True) -> None:
        played.append(key)

    mocker.patch("crimson.game.quest_views.end_note.update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch("crimson.game.quest_views.end_note._ensure_texture_cache", side_effect=lambda _state: _DummyCache())
    mocker.patch("crimson.game.quest_views.end_note.play_sfx", side_effect=_play_sfx)
    mocker.patch.object(end_note_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    view = EndNoteView(state)
    view.open()
    view.update(0.1)
    view.update(0.1)
    view.update(0.1)

    mocker.patch.object(end_note_module.rl, "is_key_pressed", side_effect=lambda key: int(key) == int(rl.KeyboardKey.KEY_ESCAPE))
    view.update(0.1)

    assert played == ["sfx_ui_buttonclick"]
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
    captured_alpha: list[float] = []
    state.pause_background = _PauseBackgroundStub(captured_alpha)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):
            class _StubAsset:
                texture = None

            return _StubAsset()

    mocker.patch("crimson.game.quest_views.end_note.update_audio", side_effect=lambda _audio, _dt: None)
    mocker.patch("crimson.game.quest_views.end_note._ensure_texture_cache", side_effect=lambda _state: _DummyCache())
    mocker.patch.object(end_note_module.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.game.quest_views.end_note._draw_screen_fade", side_effect=lambda *_args, **_kwargs: None)

    view = EndNoteView(state)
    view.open()
    view._closing = True
    view._timeline_ms = PANEL_TIMELINE_START_MS // 2
    view._panel_tex = None
    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 0.5
