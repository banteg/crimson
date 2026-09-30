from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.screens.actions import Route, StartRun
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.audio import play_sfx
from grim.fonts.small import draw_small_text
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game.types import GameState
from ...game_modes import GameMode
from ...ui.animation import ui_transition_alpha
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.perk_menu import UiButtonState, button_draw, button_update
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen
from .shared import (
    END_NOTE_AFTER_BODY_Y_GAP,
    END_NOTE_BODY_X_OFFSET,
    END_NOTE_BODY_Y_GAP,
    END_NOTE_BUTTON_STEP_Y,
    END_NOTE_BUTTON_X_OFFSET,
    END_NOTE_BUTTON_Y_OFFSET,
    END_NOTE_HEADER_X_OFFSET,
    END_NOTE_HEADER_Y_OFFSET,
    END_NOTE_LINE_STEP_Y,
)


class EndNoteView(MenuScreen):
    """Final quest "Show End Note" flow.

    Classic:
      - quest_results_screen_update uses "Show End Note" instead of "Play Next" for quest 5.10
      - clicking it transitions to state 0x15 (game_update_victory_screen @ 0x00406350)
    """

    game_state = GameStateId.FINAL_QUEST_END_NOTE

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._survival_button = UiButtonState("Survival", force_wide=True)
        self._rush_button = UiButtonState("  Rush  ", force_wide=True)
        self._typo_button = UiButtonState("Typ'o'Shooter", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def update(self, dt: float) -> None:
        panel_was_hidden = not self.state.ui.opened
        if not self._advance(dt):
            return
        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if panel_was_hidden and self.state.ui.opened and self.state.audio is not None:
            # ui_element_update clicks as the panel element becomes enabled.
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)

        enabled = self.state.ui.opened
        if self.state.focus.escape and enabled:
            self._begin_close_transition(Route.MENU)
            return

        if not enabled:
            return

        panel_top_left = self._panel_rect().top_left
        button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET, END_NOTE_BUTTON_Y_OFFSET)

        resources = require_runtime_resources(self.state)
        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        if button_update(
            resources,
            self._survival_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.gameplay.mode = GameMode.SURVIVAL
            self._begin_close_transition(StartRun(GameMode.SURVIVAL))
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y)
        if button_update(
            resources,
            self._rush_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.gameplay.mode = GameMode.RUSH
            self._begin_close_transition(StartRun(GameMode.RUSH))
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y)
        if button_update(
            resources,
            self._typo_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.gameplay.mode = GameMode.TYPO
            self._begin_close_transition(StartRun(GameMode.TYPO), fade_to_black=True)
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y)
        if button_update(
            resources,
            self._main_menu_button,
            focus=self.state.focus,
            pos=button_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._begin_close_transition(Route.MENU)
            return

    def draw(self) -> None:
        self._assert_open()
        self._draw_background(entity_alpha=self._world_entity_alpha())

        resources = require_runtime_resources(self.state)

        panel = self._panel_rect()
        draw_ui_panel(resources, 35, panel, shadow=self.state.config.display.shadows_enabled)
        panel_top_left = panel.top_left

        font = resources.small_font
        hardcore = self.state.config.gameplay.hardcore
        header = "   Incredible!" if hardcore else "Congratulations!"
        levels_line = "You've completed all the levels but the battle"
        body_lines = (
            [
                "You've done the thing we all thought was",
                "virtually impossible. To reward your",
                "efforts a new weapon has been unlocked ",
                "for you: Splitter Gun.",
                "",
                "",
            ]
            if hardcore
            else [
                levels_line,
                "isn't over yet! With all of the unlocked perks",
                "and weapons your Survival is just a bit easier.",
                "You can also replay the quests in Hardcore.",
                "As an additional reward for your victorious",
                "playing, a completely new and different game",
                "mode is unlocked for you: Typ'o'Shooter.",
            ]
        )

        header_pos = panel_top_left + Vec2(END_NOTE_HEADER_X_OFFSET, END_NOTE_HEADER_Y_OFFSET)
        header_color = rl.Color(255, 255, 255, int(255 * 0.8))
        body_color = rl.Color(255, 255, 255, int(255 * 0.5))

        draw_small_text(font, header, header_pos, header_color)

        body_pos = Vec2(panel_top_left.x + END_NOTE_BODY_X_OFFSET, header_pos.y + END_NOTE_BODY_Y_GAP)
        for idx, line in enumerate(body_lines):
            draw_small_text(font, line, body_pos, body_color)
            if idx != len(body_lines) - 1:
                body_pos = body_pos.offset(dy=END_NOTE_LINE_STEP_Y)
        body_pos = body_pos.offset(dy=END_NOTE_AFTER_BODY_Y_GAP)
        draw_small_text(font, "Good luck with your battles, trooper!", body_pos, body_color)

        button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET, END_NOTE_BUTTON_Y_OFFSET)
        button_draw(resources, self._survival_button, focus=self.state.focus, pos=button_pos)
        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y)
        button_draw(resources, self._rush_button, focus=self.state.focus, pos=button_pos)
        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y)
        button_draw(resources, self._typo_button, focus=self.state.focus, pos=button_pos)
        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y)
        button_draw(resources, self._main_menu_button, focus=self.state.focus, pos=button_pos)

        ui_cursor_render(resources, dt=self.state.frame_dt)

    def _panel_rect(self) -> Rect:
        """`game_update_victory_screen` lays out on `ui_element_slot_35`'s panel."""
        return ui_panel_rect(35, self.state.ui.timeline_ms, canvas.width())

    def _world_entity_alpha(self) -> float:
        # `game_update_victory_screen` fades the run in with the timeline; Survival and Rush keep it lit on the way out.
        match self.state.ui.pending:
            case None:
                pending = None
            case StartRun(mode=GameMode.TYPO):
                pending = GameStateId.TYPO_GAMEPLAY
            case StartRun():
                pending = GameStateId.GAMEPLAY
            case _:
                pending = GameStateId.MAIN_MENU
        return ui_transition_alpha(self.state.ui.timeline_ms, state=GameStateId.FINAL_QUEST_END_NOTE, pending=pending)


__all__ = ["EndNoteView"]
