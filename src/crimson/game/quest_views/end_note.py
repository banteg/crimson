from __future__ import annotations

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ...frontend.assets import _ensure_texture_cache
from ...frontend.menu import MenuView, _draw_menu_cursor, ensure_menu_ground, menu_ground_camera
from ...frontend.panels.base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS
from ...frontend.transitions import _draw_screen_fade
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..types import GameState
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

class EndNoteView:
    """Final quest "Show End Note" flow.

    Classic:
      - quest_results_screen_update uses "Show End Note" instead of "Play Next" for quest 5.10
      - clicking it transitions to state 0x15 (game_update_victory_screen @ 0x00406350)
    """

    def __init__(self, state: GameState) -> None:
        self.state = state
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._panel_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None

        self._survival_button = UiButtonState("Survival", force_wide=True)
        self._rush_button = UiButtonState("  Rush  ", force_wide=True)
        self._typo_button = UiButtonState("Typ'o'Shooter", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        self._action = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)

        cache = _ensure_texture_cache(self.state)
        self._panel_tex = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._small_font = None

    def close(self) -> None:
        self._ground = None
        self._small_font = None
        self._panel_tex = None
        self._button_textures = None
        self._closing = False
        self._close_action = None

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_step = min(float(dt), 0.1)
        self._cursor_pulse_time += dt_step * 1.1
        dt_ms = int(dt_step * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._action = self._close_action
                    self._close_action = None
            return
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)

        enabled = self._timeline_ms >= self._timeline_max_ms
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition("back_to_menu")
            return

        textures = self._button_textures
        if textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        if not enabled:
            return

        screen_w = float(rl.get_screen_width())
        scale = 1.0

        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = MenuView._menu_widescreen_y_shift(layout_w)

        panel_top_left = Vec2(
            (END_NOTE_PANEL_GEOM_X0 + END_NOTE_PANEL_POS_X) * scale,
            (END_NOTE_PANEL_GEOM_Y0 + END_NOTE_PANEL_POS_Y + widescreen_shift_y) * scale,
        )
        button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET * scale, END_NOTE_BUTTON_Y_OFFSET * scale)

        font = self._ensure_small_font()
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        survival_w = button_width(
            font, self._survival_button.label, scale=scale, force_wide=self._survival_button.force_wide
        )
        if button_update(
            self._survival_button,
            pos=button_pos,
            width=survival_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.game_mode = 1
            self._begin_close_transition("start_survival")
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        rush_w = button_width(font, self._rush_button.label, scale=scale, force_wide=self._rush_button.force_wide)
        if button_update(
            self._rush_button,
            pos=button_pos,
            width=rush_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.game_mode = 2
            self._begin_close_transition("start_rush")
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        typo_w = button_width(font, self._typo_button.label, scale=scale, force_wide=self._typo_button.force_wide)
        if button_update(
            self._typo_button,
            pos=button_pos,
            width=typo_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self.state.config.game_mode = 4
            self._begin_close_transition("start_typo", fade_to_black=True)
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        main_w = button_width(
            font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide
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
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        panel_tex = self._panel_tex
        if panel_tex is None:
            return

        screen_w = float(rl.get_screen_width())
        scale = 1.0
        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = MenuView._menu_widescreen_y_shift(layout_w)

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
        draw_classic_menu_panel(panel_tex, dst=panel, tint=rl.WHITE, shadow=fx_detail)

        font = self._ensure_small_font()
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

        draw_small_text(font, header, header_pos, 1.5 * scale, header_color)

        body_pos = Vec2(panel_top_left.x + END_NOTE_BODY_X_OFFSET * scale, header_pos.y + END_NOTE_BODY_Y_GAP * scale)
        for idx, line in enumerate(body_lines):
            draw_small_text(font, line, body_pos, 1.0 * scale, body_color)
            if idx != len(body_lines) - 1:
                body_pos = body_pos.offset(dy=END_NOTE_LINE_STEP_Y * scale)
        body_pos = body_pos.offset(dy=END_NOTE_AFTER_BODY_Y_GAP * scale)
        draw_small_text(font, "Good luck with your battles, trooper!", body_pos, 1.0 * scale, body_color)

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET * scale, END_NOTE_BUTTON_Y_OFFSET * scale)
            survival_w = button_width(
                font, self._survival_button.label, scale=scale, force_wide=self._survival_button.force_wide
            )
            button_draw(textures, font, self._survival_button, pos=button_pos, width=survival_w, scale=scale)
            button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
            rush_w = button_width(font, self._rush_button.label, scale=scale, force_wide=self._rush_button.force_wide)
            button_draw(textures, font, self._rush_button, pos=button_pos, width=rush_w, scale=scale)
            button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
            typo_w = button_width(font, self._typo_button.label, scale=scale, force_wide=self._typo_button.force_wide)
            button_draw(textures, font, self._typo_button, pos=button_pos, width=typo_w, scale=scale)
            button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
            main_w = button_width(
                font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide
            )
            button_draw(textures, font, self._main_menu_button, pos=button_pos, width=main_w, scale=scale)

        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font

    def _world_entity_alpha(self) -> float:
        if not self._closing:
            return 1.0
        span = PANEL_TIMELINE_START_MS - PANEL_TIMELINE_END_MS
        if span <= 0:
            return 0.0
        alpha = (float(self._timeline_ms) - PANEL_TIMELINE_END_MS) / float(span)
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _begin_close_transition(self, action: str, *, fade_to_black: bool = False) -> None:
        if self._closing:
            return
        if fade_to_black:
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._closing = True
        self._close_action = action



__all__ = ["EndNoteView"]
