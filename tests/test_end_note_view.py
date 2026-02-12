from __future__ import annotations

from pathlib import Path
import random
import time
from types import SimpleNamespace

import pyray as rl

from crimson.frontend.panels.base import PANEL_TIMELINE_START_MS
from crimson.game.quest_views import EndNoteView
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _make_state(tmp_path: Path, *, audio) -> GameState:  # noqa: ANN001
    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=tmp_path,
        rng=random.Random(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=tmp_path),
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=audio,
        resource_paq=tmp_path / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_end_note_escape_waits_for_close_transition(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path, audio=object())
    played: list[str] = []

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    def _play_sfx(_audio, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.game.quest_views.update_audio", lambda _audio, _dt: None)
    monkeypatch.setattr("crimson.game.quest_views._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr("crimson.game.quest_views.play_sfx", _play_sfx)
    monkeypatch.setattr("crimson.game.quest_views.rl.is_key_pressed", lambda _key: False)

    view = EndNoteView(state)
    view.open()
    view.update(0.1)
    view.update(0.1)
    view.update(0.1)

    monkeypatch.setattr(
        "crimson.game.quest_views.rl.is_key_pressed",
        lambda key: int(key) == int(rl.KeyboardKey.KEY_ESCAPE),
    )
    view.update(0.1)

    assert played == ["sfx_ui_buttonclick"]
    assert view.take_action() is None

    monkeypatch.setattr("crimson.game.quest_views.rl.is_key_pressed", lambda _key: False)
    action = None
    for _ in range(30):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "back_to_menu"


def test_end_note_draw_fades_pause_background_during_close(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path, audio=None)
    captured_alpha: list[float] = []
    state.pause_background = SimpleNamespace(
        draw_pause_background=lambda *, entity_alpha=1.0: captured_alpha.append(float(entity_alpha))
    )

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    monkeypatch.setattr("crimson.game.quest_views.update_audio", lambda _audio, _dt: None)
    monkeypatch.setattr("crimson.game.quest_views._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr("crimson.game.quest_views.rl.clear_background", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.game.quest_views._draw_screen_fade", lambda *_args, **_kwargs: None)

    view = EndNoteView(state)
    view.open()
    view._closing = True
    view._timeline_ms = PANEL_TIMELINE_START_MS // 2
    view._panel_tex = None
    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 0.5
