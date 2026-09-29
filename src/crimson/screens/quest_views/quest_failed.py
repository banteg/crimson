from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.screens.actions import Route, ScreenAction, StartRun
from crimson.screens.chrome import draw_screen_background, ensure_menu_ground
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from grim import canvas
from grim.assets import TextureId
from grim.audio import play_music, play_sfx, update_audio
from grim.fonts.small import draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...game_modes import GameMode
from ...game_states import GameStateId
from ...ui.animation import ui_element_anim, ui_elements_max_timeline, world_fade_alpha
from ...ui.highscore_card import ui_text_input_render
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update
from ..assets import require_runtime_resources
from ..transitions import _draw_screen_fade
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
    QUEST_FAILED_PANEL_GEOM_X0,
    QUEST_FAILED_PANEL_GEOM_Y0,
    QUEST_FAILED_PANEL_H,
    QUEST_FAILED_PANEL_POS_X,
    QUEST_FAILED_PANEL_POS_Y,
    QUEST_FAILED_PANEL_W,
    QUEST_FAILED_SCORE_X_OFFSET,
    QUEST_FAILED_SCORE_Y_OFFSET,
    _player_name_default,
)

if TYPE_CHECKING:
    from ...modes.quest_mode import QuestRunOutcome
    from ...persistence.highscores import HighScoreRecord


class QuestFailedView:
    def __init__(self, state: GameState, outcome: QuestRunOutcome) -> None:
        self.state = state
        self._ground: GroundRenderer | None = None
        self._outcome = outcome
        self._record: HighScoreRecord | None = None
        self._dt = 0.0
        self._quest_title: str = ""
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self.state.ui.enter(ui_elements_max_timeline(GameStateId.QUEST_FAILED))
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
        self._ground = None
        self._record = None
        self._quest_title = ""

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            if not self.state.ui.closing:
                play_music(self.state.audio, "shortie_monk")
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_step = min(float(dt), 0.1)
        self._dt = dt_step
        dt_ms = dt_step * 1000.0
        panel_was_hidden = not self.state.ui.opened
        if not self.state.ui.advance(int(dt_ms)):
            return
        if panel_was_hidden and self.state.ui.opened and self.state.audio is not None:
            # ui_element_update clicks as the panel element becomes enabled.
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)

        outcome = self._outcome
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._activate_main_menu()
            return
        if outcome is not None and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._activate_retry()
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Q):
            self._activate_play_another()
            return

        panel_top_left = self._panel_top_left()
        if outcome is None:
            return

        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        resources = require_runtime_resources(self.state)
        button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET, QUEST_FAILED_BUTTON_Y_OFFSET)

        if button_update(
            resources,
            self._retry_button,
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
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_main_menu()
            return

    def draw(self) -> None:
        draw_screen_background(self.state, self._ground, entity_alpha=self._world_entity_alpha())
        _draw_screen_fade(self.state)

        panel_top_left = self._panel_top_left()
        resources = require_runtime_resources(self.state)
        panel_tex = resources.texture(TextureId.UI_MENU_PANEL)
        panel = rl.Rectangle(
            panel_top_left.x,
            panel_top_left.y,
            float(QUEST_FAILED_PANEL_W),
            float(QUEST_FAILED_PANEL_H),
        )
        shadows_enabled = self.state.config.display.shadows_enabled
        draw_classic_menu_panel(panel_tex, dst=panel, tint=rl.WHITE, shadow=shadows_enabled)

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

        button_draw(resources, self._retry_button, pos=button_pos)
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

        button_draw(
            resources,
            self._quest_list_button,
            pos=button_pos,
        )
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

        button_draw(
            resources,
            self._main_menu_button,
            pos=button_pos,
        )

        ui_cursor_render(resources, dt=self.state.frame_dt)

    def take_action(self) -> ScreenAction | None:
        return self.state.ui.take_action()

    def _panel_origin(self) -> Vec2:
        screen_w = float(canvas.width())
        widescreen_shift_y = menu_widescreen_y_shift(screen_w)
        return Vec2(
            QUEST_FAILED_PANEL_GEOM_X0 + QUEST_FAILED_PANEL_POS_X,
            QUEST_FAILED_PANEL_GEOM_Y0 + QUEST_FAILED_PANEL_POS_Y + widescreen_shift_y,
        )

    def _world_entity_alpha(self) -> float:
        if not self.state.ui.closing:
            return 1.0
        return world_fade_alpha(self.state.ui.timeline_ms)

    def _panel_top_left(self) -> Vec2:
        return self._panel_origin().offset(dx=ui_element_anim(self.state.ui.timeline_ms, index=35, width=QUEST_FAILED_PANEL_W)[1])

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
        record.survival_elapsed_ms = max(1, outcome.base_time_ms)
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
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self._begin_close(StartRun(GameMode.QUESTS, level))

    def _activate_play_another(self) -> None:
        self.state.quest_fail_retry_count = 0
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self._begin_close(Route.QUESTS)

    def _activate_main_menu(self) -> None:
        self.state.quest_fail_retry_count = 0
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self._begin_close(Route.MENU)

    def _begin_close(self, action: ScreenAction) -> None:
        self.state.ui.begin(action)

    def _draw_score_preview(self, *, panel_top_left: Vec2) -> None:
        if self._record is None:
            return
        # Quest-failed cards never show the rank, so any rank works.
        ui_text_input_render(
            panel_top_left + Vec2(QUEST_FAILED_SCORE_X_OFFSET, QUEST_FAILED_SCORE_Y_OFFSET), self._record, 1.0, 0,
            game_state=GameStateId.QUEST_FAILED, ui_phase=0, resources=require_runtime_resources(self.state),
            mouse=canvas.mouse_position(), dt=self._dt,
        )


__all__ = [
    "QUEST_FAILED_PANEL_W",
    "QuestFailedView",
]
