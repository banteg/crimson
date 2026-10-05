from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.screens.actions import Route, StartRun
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.assets import TextureId
from grim.fonts.small import draw_small_text
from grim.geom import Rect, Vec2
from grim.music import play_music
from grim.raylib_api import rl

from ...game.types import GameState
from ...game_modes import GameMode
from ...game_states import GameStateId
from ...ui.animation import ui_transition_alpha
from ...ui.button import UiButtonState, button_draw, button_update
from ...ui.highscore_card import ui_text_input_render
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen
from .shared import (
    QUEST_FAILED_BANNER_H,
    QUEST_FAILED_BANNER_W,
    QUEST_FAILED_BANNER_X_OFFSET,
    QUEST_FAILED_BANNER_Y_OFFSET,
    QUEST_FAILED_BUTTON_STEP_Y,
    QUEST_FAILED_BUTTON_X_OFFSET,
    QUEST_FAILED_BUTTON_Y_OFFSET,
    QUEST_FAILED_MESSAGE_X_OFFSET,
    QUEST_FAILED_MESSAGE_Y_OFFSET,
    QUEST_FAILED_SCORE_X_OFFSET,
    QUEST_FAILED_SCORE_Y_OFFSET,
    _player_name_default,
)

if TYPE_CHECKING:
    from ...modes.quest_mode import QuestRunOutcome
    from ...persistence.highscores import HighScoreRecord


class QuestFailedView(MenuScreen):
    game_state = GameStateId.QUEST_FAILED

    def __init__(self, state: GameState, outcome: QuestRunOutcome) -> None:
        super().__init__(state)
        self._outcome = outcome
        self._record: HighScoreRecord | None = None
        self._dt = 0.0
        self._quest_title: str = ""
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        super().open()
        self._quest_title = ""
        self._record = None
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)
        outcome = self._outcome
        if outcome is not None:
            from ...quests import quest_by_level

            quest = quest_by_level(outcome.level)
            self._quest_title = quest.title if quest is not None else ""

        self._build_score_preview(outcome)

    def close(self) -> None:
        super().close()
        self._record = None
        self._quest_title = ""

    def update(self, dt: float) -> None:
        if self.state.audio is not None and not self.state.ui.closing:
            play_music(self.state.audio.music, "shortie_monk")
        self._dt = min(float(dt), 0.1)
        dt_ms = self._dt * 1000.0
        if not self._advance(dt):
            return

        outcome = self._outcome
        # Port shortcuts: Escape for Main Menu and Q for Play Another. Enter takes the focused button, as native.
        if self.state.focus.escape:
            self._activate_main_menu()
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Q):
            self._activate_play_another()
            return

        panel_top_left = self._panel_rect().top_left
        if outcome is None:
            return

        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        resources = require_runtime_resources(self.state)
        button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET, QUEST_FAILED_BUTTON_Y_OFFSET)

        if button_update(
            resources,
            self._retry_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_retry()
            return
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

        if button_update(
            resources,
            self._quest_list_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_play_another()
            return
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

        if button_update(
            resources,
            self._main_menu_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_main_menu()
            return

    def draw(self) -> None:
        self._assert_open()
        self._draw_background(entity_alpha=self._world_entity_alpha())

        panel = self._panel_rect()
        resources = require_runtime_resources(self.state)
        draw_ui_panel(resources, 35, panel, shadow=self.state.config.display.shadows_enabled)
        panel_top_left = panel.top_left

        reaper_tex = resources.texture(TextureId.UI_TEXT_REAPER)
        src = rl.Rectangle(0.0, 0.0, float(reaper_tex.width), float(reaper_tex.height))
        banner_pos = panel_top_left + Vec2(QUEST_FAILED_BANNER_X_OFFSET, QUEST_FAILED_BANNER_Y_OFFSET)
        dst = rl.Rectangle(
            banner_pos.x,
            banner_pos.y,
            float(QUEST_FAILED_BANNER_W),
            float(QUEST_FAILED_BANNER_H),
        )
        rl.draw_texture_pro(reaper_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        font = resources.small_font
        text_color = rl.Color(235, 235, 235, 255)
        draw_small_text(
            font,
            self._failure_message(),
            panel_top_left + Vec2(QUEST_FAILED_MESSAGE_X_OFFSET, QUEST_FAILED_MESSAGE_Y_OFFSET),
            text_color,
        )
        self._draw_score_preview(panel_top_left=panel_top_left)

        button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET, QUEST_FAILED_BUTTON_Y_OFFSET)

        button_draw(resources, self._retry_button, focus=self.state.focus, pos=button_pos)
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

        button_draw(
            resources,
            self._quest_list_button,
            focus=self.state.focus,
            pos=button_pos,
        )
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

        button_draw(
            resources,
            self._main_menu_button,
            focus=self.state.focus,
            pos=button_pos,
        )

        ui_cursor_render(resources, dt=self.state.frame_dt)


    def _world_entity_alpha(self) -> float:
        # `quest_failed_screen_update`'s buttons set `game_state_pending`; a retry keeps the run lit.
        match self.state.ui.pending:
            case None:
                pending = None
            case StartRun():
                pending = GameStateId.GAMEPLAY
            case Route.QUESTS:
                pending = GameStateId.QUEST_SELECT
            case _:
                pending = GameStateId.MAIN_MENU
        return ui_transition_alpha(self.state.ui.timeline_ms, state=GameStateId.QUEST_FAILED, pending=pending)

    def _panel_rect(self) -> Rect:
        """`quest_failed_screen_update` lays out on `ui_element_slot_35`'s panel."""
        return ui_panel_rect(35, self.state.ui.timeline_ms, canvas.width())

    def _failure_message(self) -> str:
        retry_count = int(self.state.quest_fail_retry_count)
        if retry_count == 1:
            return "You didn't make it, do try again."
        if retry_count == 2:
            return "Third time no good."
        if retry_count == 3:
            return "No luck this time, have another go?"
        if retry_count == 4:
            return "Persistence will be rewared."
        if retry_count == 5:
            return "Try one more time?"
        return "Quest failed, try again."

    def _build_score_preview(self, outcome: QuestRunOutcome | None) -> None:
        self._record = None
        if outcome is None:
            return
        record = outcome.record.copy()
        record.set_name(_player_name_default(self.state.config) or "Player")
        record.run_elapsed_ms = max(1, outcome.base_time_ms)
        self._record = record

    def _activate_retry(self) -> None:
        outcome = self._outcome
        if outcome is None:
            return
        self.state.quest_fail_retry_count = int(self.state.quest_fail_retry_count) + 1
        level = outcome.level
        self.state.config.gameplay.mode = GameMode.QUESTS
        self.state.config.gameplay.quest_level = level
        try:
            self.state.config.save()
        except (OSError, ValueError) as exc:
            self.state.console.log.log(f"quest failed: failed to save quest selection config: {exc}")
        self._begin_close_transition(StartRun(GameMode.QUESTS, level))

    def _activate_play_another(self) -> None:
        self.state.quest_fail_retry_count = 0
        self._begin_close_transition(Route.QUESTS)

    def _activate_main_menu(self) -> None:
        self.state.quest_fail_retry_count = 0
        self._begin_close_transition(Route.MENU)

    def _draw_score_preview(self, *, panel_top_left: Vec2) -> None:
        if self._record is None:
            return
        # Quest-failed cards never show the rank, so any rank works.
        ui_text_input_render(
            panel_top_left + Vec2(QUEST_FAILED_SCORE_X_OFFSET, QUEST_FAILED_SCORE_Y_OFFSET), self._record, 1.0, 0,
            game_state=GameStateId.QUEST_FAILED, ui_phase=0, resources=require_runtime_resources(self.state),
            mouse=canvas.mouse_position(), dt=self._dt,
        )


__all__ = ["QuestFailedView"]
