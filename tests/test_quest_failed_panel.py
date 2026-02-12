from __future__ import annotations

from pathlib import Path
import random
import time
from types import SimpleNamespace

import pyray as rl

from crimson.game import (
    GameState,
    QUEST_FAILED_PANEL_SLIDE_DURATION_MS,
    QUEST_FAILED_PANEL_W,
    QuestFailedView,
)
from crimson.modes.quest_mode import QuestRunOutcome
from crimson.persistence import save_status
from grim.geom import Vec2
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _make_state(tmp_path: Path) -> GameState:
    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
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
        audio=object(),
        resource_paq=tmp_path / "crimson.paq",
        session_start=time.monotonic(),
    )
    # Avoid ground/menu asset loading in tests.
    state.pause_background = SimpleNamespace(draw_pause_background=lambda **_kwargs: None)
    return state


def _failed_outcome() -> QuestRunOutcome:
    return QuestRunOutcome(
        kind="failed",
        level="5.10",
        base_time_ms=7_000,
        player_health=0.0,
        player2_health=None,
        pending_perk_count=0,
        experience=123,
        kill_count=45,
        weapon_id=1,
        shots_fired=100,
        shots_hit=42,
        most_used_weapon_id=1,
    )


def test_quest_failed_panel_layout_uses_native_anchor(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    view = QuestFailedView(state)

    monkeypatch.setattr("crimson.game.rl.get_screen_width", lambda: 640)
    panel_640 = view._panel_origin()
    assert panel_640.x == -108.0
    assert panel_640.y == 29.0

    monkeypatch.setattr("crimson.game.rl.get_screen_width", lambda: 1024)
    panel_1024 = view._panel_origin()
    assert panel_1024.x == -108.0
    assert panel_1024.y == 119.0


def test_quest_failed_panel_slides_in_from_left(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    view = QuestFailedView(state)

    monkeypatch.setattr("crimson.game.rl.get_screen_width", lambda: 640)
    base = view._panel_origin()

    view._intro_ms = 0.0
    assert view._panel_top_left().x == base.x - QUEST_FAILED_PANEL_W

    view._intro_ms = 250.0
    assert view._panel_top_left().x == base.x


def test_quest_failed_retry_message_respects_preserve_bugs(tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.quest_fail_retry_count = 4
    view = QuestFailedView(state)

    state.preserve_bugs = False
    assert view._failure_message() == "Persistence will be rewarded."

    state.preserve_bugs = True
    assert view._failure_message() == "Persistence will be rewared."


def test_quest_failed_enter_retries_current_quest(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.quest_outcome = _failed_outcome()
    state.quest_fail_retry_count = 2

    played: list[str] = []

    def _play_sfx(_audio, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    monkeypatch.setattr("crimson.game.update_audio", lambda _audio, _dt: None)
    monkeypatch.setattr("crimson.game._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr("crimson.game.play_sfx", _play_sfx)
    monkeypatch.setattr("crimson.game.rl.is_key_pressed", lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER))

    view = QuestFailedView(state)
    view.open()
    view.update(0.016)

    assert state.quest_fail_retry_count == 3
    assert state.pending_quest_level == "5.10"
    assert played == ["sfx_ui_buttonclick"]
    assert view.take_action() is None
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "start_quest"


def test_quest_failed_q_opens_quest_list(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.quest_outcome = _failed_outcome()
    state.quest_fail_retry_count = 4

    played: list[str] = []

    def _play_sfx(_audio, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    monkeypatch.setattr("crimson.game.update_audio", lambda _audio, _dt: None)
    monkeypatch.setattr("crimson.game._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr("crimson.game.play_sfx", _play_sfx)
    monkeypatch.setattr("crimson.game.rl.is_key_pressed", lambda key: int(key) == int(rl.KeyboardKey.KEY_Q))

    view = QuestFailedView(state)
    view.open()
    view.update(0.016)

    assert state.quest_fail_retry_count == 0
    assert played == ["sfx_ui_buttonclick"]
    assert view.take_action() is None
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "open_quests"


def test_quest_failed_main_menu_waits_for_exit_transition(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.quest_outcome = _failed_outcome()
    state.quest_fail_retry_count = 4

    played: list[str] = []

    def _play_sfx(_audio, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    monkeypatch.setattr("crimson.game.update_audio", lambda _audio, _dt: None)
    monkeypatch.setattr("crimson.game._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr("crimson.game.play_sfx", _play_sfx)
    monkeypatch.setattr("crimson.game.rl.is_key_pressed", lambda key: int(key) == int(rl.KeyboardKey.KEY_ESCAPE))

    view = QuestFailedView(state)
    view.open()
    view.update(0.016)

    assert state.quest_fail_retry_count == 0
    assert played == ["sfx_ui_buttonclick"]
    assert view.take_action() is None
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == "back_to_menu"


def test_quest_failed_score_block_matches_native_fields(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.quest_outcome = _failed_outcome()
    view = QuestFailedView(state)

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    monkeypatch.setattr("crimson.game._ensure_texture_cache", lambda _state: _DummyCache())
    view.open()

    drawn_text: list[str] = []
    drawn_lines: list[tuple[int, int, int, int]] = []
    drawn_rects: list[tuple[int, int, int, int]] = []

    def _draw_small_text(_font, text, pos, scale, color):  # noqa: ANN001, ARG001
        drawn_text.append(str(text))

    def _draw_line(x1, y1, x2, y2, color):  # noqa: ANN001, ARG001
        drawn_lines.append((int(x1), int(y1), int(x2), int(y2)))

    def _draw_rect(x, y, w, h, color):  # noqa: ANN001, ARG001
        drawn_rects.append((int(x), int(y), int(w), int(h)))

    monkeypatch.setattr("crimson.game.draw_small_text", _draw_small_text)
    monkeypatch.setattr("crimson.game.rl.draw_line", _draw_line)
    monkeypatch.setattr("crimson.game.rl.draw_rectangle", _draw_rect)
    monkeypatch.setattr("crimson.game.rl.measure_text", lambda text, _size: len(str(text)) * 8)

    view._small_font = None
    view._draw_score_preview(None, panel_top_left=Vec2(-108.0, 29.0))  # type: ignore[arg-type]

    assert "Score" in drawn_text
    assert "Experience" in drawn_text
    assert "Rank: 1" not in drawn_text
    assert not any(text.startswith("Frags:") for text in drawn_text)
    assert not any(text.startswith("Hit %:") for text in drawn_text)
    assert drawn_lines  # vertical separator
    assert any(w == 192 and h == 1 for (_x, _y, w, h) in drawn_rects)  # horizontal separator


def test_quest_failed_draw_fades_pause_background_during_close(monkeypatch, tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.quest_outcome = _failed_outcome()
    captured_alpha: list[float] = []
    state.pause_background = SimpleNamespace(
        draw_pause_background=lambda *, entity_alpha=1.0: captured_alpha.append(float(entity_alpha))
    )

    class _DummyCache:
        def get_or_load(self, *_args, **_kwargs):  # noqa: ANN001
            return SimpleNamespace(texture=None)

    view = QuestFailedView(state)
    monkeypatch.setattr("crimson.game._ensure_texture_cache", lambda _state: _DummyCache())
    monkeypatch.setattr("crimson.game.rl.clear_background", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.game.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.game._draw_screen_fade", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.game._draw_menu_cursor", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.game.draw_small_text", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.game.button_draw", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.game.button_width", lambda *_args, **_kwargs: 82.0)
    monkeypatch.setattr(view, "_ensure_small_font", lambda: SimpleNamespace())
    monkeypatch.setattr(view, "_draw_score_preview", lambda *_args, **_kwargs: None)

    view.open()
    view._closing = True
    view._intro_ms = QUEST_FAILED_PANEL_SLIDE_DURATION_MS * 0.5
    view.draw()

    assert captured_alpha
    assert captured_alpha[-1] == 0.5
