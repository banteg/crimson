from __future__ import annotations

from grim.assets import TextureId
from grim.fonts.small import draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...game_modes import GameMode
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..chrome.geometry import menu_widescreen_y_shift
from ..chrome.runtime import CloseTimelineEntityAlpha, NoOpenSfx
from ..panels.base import PANEL_TIMELINE_START_MS
from .base import _QuestChromeViewBase
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
    END_NOTE_PANEL_GEOM_X0,
    END_NOTE_PANEL_GEOM_Y0,
    END_NOTE_PANEL_H,
    END_NOTE_PANEL_POS_X,
    END_NOTE_PANEL_POS_Y,
    END_NOTE_PANEL_W,
)


class EndNoteView(_QuestChromeViewBase):
    """Final quest "Show End Note" flow.

    Classic:
      - quest_results_screen_update uses "Show End Note" instead of "Play Next" for quest 5.10
      - clicking it transitions to state 0x15 (game_update_victory_screen @ 0x00406350)
    """

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            open_sfx=NoOpenSfx(),
            fade_actions=frozenset({"start_typo"}),
            pause_background_close_alpha=CloseTimelineEntityAlpha(duration_ms=PANEL_TIMELINE_START_MS),
        )
        self._survival_button = UiButtonState("Survival", force_wide=True)
        self._rush_button = UiButtonState("  Rush  ", force_wide=True)
        self._typo_button = UiButtonState("Typ'o'Shooter", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def _reset_view_state(self) -> None:
        self._survival_button = UiButtonState("Survival", force_wide=True)
        self._rush_button = UiButtonState("  Rush  ", force_wide=True)
        self._typo_button = UiButtonState("Typ'o'Shooter", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def update(self, dt: float) -> None:
        tick = self._tick_chrome(dt)
        if self._chrome_state.closing:
            return
        dt_ms = float(tick.dt_ms)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and tick.interactive:
            self._begin_close_transition("back_to_menu")
            return

        if not tick.interactive:
            return

        screen_w = float(rl.get_screen_width())
        scale = 1.0

        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = menu_widescreen_y_shift(layout_w)

        panel_top_left = Vec2(
            (END_NOTE_PANEL_GEOM_X0 + END_NOTE_PANEL_POS_X) * scale,
            (END_NOTE_PANEL_GEOM_Y0 + END_NOTE_PANEL_POS_Y + widescreen_shift_y) * scale,
        )
        button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET * scale, END_NOTE_BUTTON_Y_OFFSET * scale)

        resources = require_runtime_resources(self.state)
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        survival_w = button_width(
            resources, self._survival_button.label, scale=scale, force_wide=self._survival_button.force_wide,
        )
        if button_update(
            self._survival_button,
            pos=button_pos,
            width=survival_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.game_mode = int(GameMode.SURVIVAL)
            self._begin_close_transition("start_survival")
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        rush_w = button_width(resources, self._rush_button.label, scale=scale, force_wide=self._rush_button.force_wide)
        if button_update(
            self._rush_button,
            pos=button_pos,
            width=rush_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.game_mode = int(GameMode.RUSH)
            self._begin_close_transition("start_rush")
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        typo_w = button_width(resources, self._typo_button.label, scale=scale, force_wide=self._typo_button.force_wide)
        if button_update(
            self._typo_button,
            pos=button_pos,
            width=typo_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.game_mode = int(GameMode.TYPO)
            self._begin_close_transition("start_typo")
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        main_w = button_width(
            resources, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide,
        )
        if button_update(
            self._main_menu_button,
            pos=button_pos,
            width=main_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._begin_close_transition("back_to_menu")
            return

    def draw(self) -> None:
        self._draw_chrome()
        resources = require_runtime_resources(self.state)

        screen_w = float(rl.get_screen_width())
        scale = 1.0
        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = menu_widescreen_y_shift(layout_w)

        panel_top_left = Vec2(
            (END_NOTE_PANEL_GEOM_X0 + END_NOTE_PANEL_POS_X) * scale,
            (END_NOTE_PANEL_GEOM_Y0 + END_NOTE_PANEL_POS_Y + widescreen_shift_y) * scale,
        )
        panel = rl.Rectangle(
            panel_top_left.x,
            panel_top_left.y,
            float(END_NOTE_PANEL_W * scale),
            float(END_NOTE_PANEL_H * scale),
        )

        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(resources.texture(TextureId.UI_MENU_PANEL), dst=panel, tint=rl.WHITE, shadow=fx_detail)

        font = resources.small_font
        hardcore = self.state.config.hardcore
        header = "   Incredible!" if hardcore else "Congratulations!"
        levels_line = (
            "You've completed all the levels but the battle"
            if bool(self.state.preserve_bugs)
            else "You've completed all the levels, but the battle"
        )
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

        header_pos = panel_top_left + Vec2(END_NOTE_HEADER_X_OFFSET * scale, END_NOTE_HEADER_Y_OFFSET * scale)
        header_color = rl.Color(255, 255, 255, int(255 * 0.8))
        body_color = rl.Color(255, 255, 255, int(255 * 0.5))

        draw_small_text(font, header, header_pos, header_color)

        body_pos = Vec2(panel_top_left.x + END_NOTE_BODY_X_OFFSET * scale, header_pos.y + END_NOTE_BODY_Y_GAP * scale)
        for idx, line in enumerate(body_lines):
            draw_small_text(font, line, body_pos, body_color)
            if idx != len(body_lines) - 1:
                body_pos = body_pos.offset(dy=END_NOTE_LINE_STEP_Y * scale)
        body_pos = body_pos.offset(dy=END_NOTE_AFTER_BODY_Y_GAP * scale)
        draw_small_text(font, "Good luck with your battles, trooper!", body_pos, body_color)

        button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET * scale, END_NOTE_BUTTON_Y_OFFSET * scale)
        survival_w = button_width(
            resources, self._survival_button.label, scale=scale, force_wide=self._survival_button.force_wide,
        )
        button_draw(resources, self._survival_button, pos=button_pos, width=survival_w, scale=scale)
        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        rush_w = button_width(resources, self._rush_button.label, scale=scale, force_wide=self._rush_button.force_wide)
        button_draw(resources, self._rush_button, pos=button_pos, width=rush_w, scale=scale)
        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        typo_w = button_width(resources, self._typo_button.label, scale=scale, force_wide=self._typo_button.force_wide)
        button_draw(resources, self._typo_button, pos=button_pos, width=typo_w, scale=scale)
        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        main_w = button_width(
            resources, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide,
        )
        button_draw(resources, self._main_menu_button, pos=button_pos, width=main_w, scale=scale)
        self._draw_cursor()


__all__ = ["EndNoteView"]
