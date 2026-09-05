"""Headless evidence for the screen review, pinned to the reviewed source revision.

Run with `PYTHONPATH=. uv run python analysis/reviews/2026-09-05-screen-review/probes.py`.
Assertions describe the reviewed bugs, not the desired future behavior.
Native window/input/drawing and terrain allocation are replaced; the panel,
widget state mutation, action delivery, and navigation code are production code.
"""

from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import crimson.screens.high_scores_view.view as scores_module
import crimson.screens.panels.controls as controls_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState, HighScoresRequest
from crimson.game_modes import GameMode
from crimson.persistence.save_status import ensure_game_status
from crimson.quests.level import QuestLevel
from crimson.screens.high_scores_layout import HS_QUEST_ARROW_X, HS_QUEST_ARROW_Y
from crimson.screens.high_scores_view import HighScoresView
from crimson.screens.panels.controls import ControlsMenuView
from crimson.screens.panels.controls_labels import RebindRowSpec, RebindTarget
from grim.assets import RuntimeResources
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from tests.support.gameplay_screen import GameplayScreenStub


def state_for(path: Path) -> GameState:
    path.mkdir(parents=True)
    texture = rl.Texture()
    texture.width = texture.height = 32
    font = SmallFontData(widths=[8] * 256, texture=texture, cell_size=8)
    resources = cast(RuntimeResources, SimpleNamespace(texture=lambda _: texture, small_font=font))
    return GameState(
        base_dir=path,
        assets_dir=path,
        rng=Crand(0),
        config=ensure_crimson_cfg(path),
        status=ensure_game_status(path),
        console=create_console(path, assets_dir=path),
        demo_enabled=False,
        preserve_bugs=True,
        resources=resources,
        audio=None,
        session_start=0.0,
    )


def controls_capture(state: GameState) -> dict[str, object]:
    observations = {}
    for key in (rl.KeyboardKey.KEY_ESCAPE, rl.KeyboardKey.KEY_ENTER):
        view = ControlsMenuView(state)
        view.open()
        view._timeline_ms = view._timeline_max_ms
        row = RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE)
        view._start_rebind_capture(row=row, player_index=0)
        view._rebind_skip_frames = 0
        with patch.object(rl, "is_key_pressed", side_effect=lambda k, expected=key: k == expected):
            view.update(0.016)
        observations[key.name] = {
            "closing": view._closing,
            "action": view._close_action,
            "capture_still_active": view._rebind_active(),
        }
        assert view._closing and view._close_action == "open_options"
        assert view._rebind_active()
        view.close()
    return observations


def controls_prompt(state: GameState) -> dict[str, object]:
    observations = {}
    for player_index in (0, 1):
        view = ControlsMenuView(state)
        view.open()
        view._timeline_ms = view._timeline_max_ms
        view._config_player = player_index + 1
        view._start_rebind_capture(
            row=RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE),
            player_index=player_index,
        )
        texts = []
        with patch.object(controls_module, "draw_small_text", side_effect=lambda _f, text, *_a, collected=texts: collected.append(text)):
            view._draw_contents()
        observations[str(player_index + 1)] = {
            "prompt_visible": "<press input>" in texts,
            "hint_visible": any("Esc/Right: cancel" in text for text in texts),
        }
        view.close()
    assert observations["1"] == {"prompt_visible": False, "hint_visible": False}
    assert observations["2"] == {"prompt_visible": True, "hint_visible": True}
    return observations


def score_button(view: HighScoresView, label: str) -> None:
    view._timeline_ms = view._timeline_max_ms
    with patch.object(scores_module, "button_update", side_effect=lambda button, **_k: button.label == label):
        view.update(0.016)


def scores_refresh(state: GameState) -> dict[str, object]:
    state.config.gameplay.mode = GameMode.QUESTS
    state.pending_quest_level = QuestLevel(1, 1)
    state.pending_high_scores = HighScoresRequest(GameMode.QUESTS, QuestLevel(1, 1), highlight_rank=4)
    view = HighScoresView(state)
    view.open()
    assert view._request is not None
    # Change a date filter through the actual widget handler.
    resources = state.resources
    assert resources is not None
    state.status.quest_unlock_index = 2
    # Move from the originating quest to its next score table with the real arrow handler.
    with (
        patch.object(rl, "get_mouse_position", return_value=rl.Vector2(HS_QUEST_ARROW_X + 1, HS_QUEST_ARROW_Y + 1)),
        patch.object(rl, "is_mouse_button_pressed", return_value=True),
    ):
        assert view._update_quest_arrows(left_panel_top_left=Vec2(), scale=1.0, resources=resources)
    with patch.object(view, "_update_dropdown", return_value=(False, 1, True)):
        view._update_right_panel_widgets(
            right_top_left=Vec2(),
            scale=1.0,
            resources=resources,
            font=resources.small_font,
        )
    before = {"quest": view._request.quest_level.text, "highlight": view._request.highlight_rank, "dirty": view._dirty}
    score_button(view, "Update scores")
    assert view._request is not None and view._request.quest_level is not None
    after = {"quest": view._request.quest_level.text, "highlight": view._request.highlight_rank, "dirty": view._dirty}
    assert before == {"quest": "1.2", "highlight": 4, "dirty": True}
    assert after == {"quest": "1.1", "highlight": None, "dirty": False}
    with patch.object(type(state.config), "save") as save:
        view._begin_close_transition("back_to_previous")
        assert save.call_count == 0
    view.close()
    return {"before_update": before, "after_update": after, "save_on_back_calls": 0}


def scores_return_context(state: GameState) -> dict[str, object]:
    state.config.gameplay.mode = GameMode.SURVIVAL
    loop = GameLoopView(state)
    gameplay = GameplayScreenStub(game_mode_id=GameMode.SURVIVAL, action="open_high_scores")
    loop._front_active = gameplay
    loop._active = gameplay
    with ExitStack() as stack:
        for name in ("handle_hotkey", "update"):
            stack.enter_context(patch.object(type(state.console), name))
        loop.update(0.016)
        view = loop._front_active
        assert isinstance(view, HighScoresView)
        resources = state.resources
        assert resources is not None
        # No date/player selection, then select Rush through the real mode handler.
        with patch.object(
            view,
            "_update_dropdown",
            side_effect=[
                (False, None, False),
                (False, None, False),
                (False, 1, True),
            ],
        ):
            view._update_right_panel_widgets(
                right_top_left=Vec2(),
                scale=1.0,
                resources=resources,
                font=resources.small_font,
            )
        view._timeline_ms = view._timeline_max_ms
        with patch.object(rl, "is_key_pressed", side_effect=lambda k: k == rl.KeyboardKey.KEY_ESCAPE):
            loop.update(0.016)
        for _ in range(4):
            loop.update(0.1)
        assert loop._front_active is gameplay
        assert state.config.gameplay.mode == GameMode.RUSH
    return {
        "returned_to_original_gameplay": True,
        "originating_mode": gameplay.default_game_mode_id.name,
        "config_mode_after_back": state.config.gameplay.mode.name,
    }


def scores_play_selected(state: GameState) -> dict[str, object]:
    observations = {}
    for mode in (GameMode.SURVIVAL, GameMode.RUSH, GameMode.TYPO, GameMode.QUESTS):
        state.pending_high_scores = HighScoresRequest(mode, QuestLevel(1, 1) if mode == GameMode.QUESTS else None)
        view = HighScoresView(state)
        view.open()
        score_button(view, "Play a game")
        observations[mode.name] = view._close_action
        assert view._close_action == "open_play_game"
        view.close()
    return observations


def main() -> None:
    with TemporaryDirectory(prefix="crimson-screen-review-") as temp, ExitStack() as stack:
        for name, value in {
            "is_key_pressed": False,
            "is_key_down": False,
            "is_mouse_button_pressed": False,
            "is_mouse_button_down": False,
            "get_mouse_position": rl.Vector2(-1000, -1000),
            "get_mouse_wheel_move": 0.0,
        }.items():
            stack.enter_context(patch.object(rl, name, return_value=value))
        for name in ("draw_rectangle", "draw_rectangle_lines_ex", "draw_line", "draw_texture_pro"):
            stack.enter_context(patch.object(rl, name))
        for module in ("crimson.screens.panels.base", "crimson.screens.high_scores_view.view"):
            stack.enter_context(patch(f"{module}.ensure_menu_ground", return_value=None))
        stack.enter_context(patch.object(scores_module, "button_width", return_value=100.0))
        stack.enter_context(patch.object(scores_module, "button_update", return_value=False))
        results = {}
        for probe in (controls_capture, controls_prompt, scores_refresh, scores_return_context, scores_play_selected):
            state = state_for(Path(temp) / probe.__name__)
            results[probe.__name__] = probe(state)
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
