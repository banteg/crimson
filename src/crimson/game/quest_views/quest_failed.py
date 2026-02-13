from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ...frontend.assets import _ensure_texture_cache
from ...frontend.menu import MenuView, _draw_menu_cursor, ensure_menu_ground, menu_ground_camera
from ...frontend.transitions import _draw_screen_fade
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..types import GameState
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
    QUEST_FAILED_PANEL_SLIDE_DURATION_MS,
    QUEST_FAILED_PANEL_W,
    QUEST_FAILED_SCORE_X_OFFSET,
    QUEST_FAILED_SCORE_Y_OFFSET,
    _player_name_default,
)

if TYPE_CHECKING:
    from ...modes.quest_mode import QuestRunOutcome
    from ...persistence.highscores import HighScoreRecord

class QuestFailedView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._ground: GroundRenderer | None = None
        self._outcome: QuestRunOutcome | None = None
        self._record: HighScoreRecord | None = None
        self._quest_title: str = ""
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._intro_ms = 0.0
        self._closing = False
        self._close_action: str | None = None
        self._small_font: SmallFontData | None = None
        self._panel_tex: rl.Texture | None = None
        self._reaper_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        self._action = None
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._cursor_pulse_time = 0.0
        self._intro_ms = 0.0
        self._closing = False
        self._close_action = None
        self._outcome = self.state.quest_outcome
        self.state.quest_outcome = None
        self._quest_title = ""
        self._record = None
        self._small_font = None
        self._panel_tex = None
        self._reaper_tex = None
        self._button_textures = None
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)
        outcome = self._outcome
        if outcome is not None:
            from ...quests import quest_by_level

            quest = quest_by_level(outcome.level)
            self._quest_title = quest.title if quest is not None else ""

        self._build_score_preview(outcome)

        cache = _ensure_texture_cache(self.state)
        self._panel_tex = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        self._reaper_tex = cache.get_or_load("ui_textReaper", "ui/ui_textReaper.jaz").texture
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)

    def close(self) -> None:
        self._ground = None
        self._outcome = None
        self._record = None
        self._quest_title = ""
        self._small_font = None
        self._panel_tex = None
        self._reaper_tex = None
        self._button_textures = None

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_step = min(float(dt), 0.1)
        self._cursor_pulse_time += dt_step * 1.1
        dt_ms = dt_step * 1000.0
        if self._closing:
            self._intro_ms = max(0.0, float(self._intro_ms) - dt_ms)
            if self._intro_ms <= 1e-3 and self._close_action is not None:
                self._action = self._close_action
                self._close_action = None
            return
        self._intro_ms = min(QUEST_FAILED_PANEL_SLIDE_DURATION_MS, self._intro_ms + dt_ms)

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
        textures = self._button_textures
        if outcome is None or textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        scale = 1.0

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        font = self._ensure_small_font()
        button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET * scale, QUEST_FAILED_BUTTON_Y_OFFSET * scale)

        retry_w = button_width(font, self._retry_button.label, scale=scale, force_wide=self._retry_button.force_wide)
        if button_update(
            self._retry_button,
            pos=button_pos,
            width=retry_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_retry()
            return
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y * scale)

        play_another_w = button_width(
            font,
            self._quest_list_button.label,
            scale=scale,
            force_wide=self._quest_list_button.force_wide,
        )
        if button_update(
            self._quest_list_button,
            pos=button_pos,
            width=play_another_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_play_another()
            return
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y * scale)

        main_menu_w = button_width(
            font,
            self._main_menu_button.label,
            scale=scale,
            force_wide=self._main_menu_button.force_wide,
        )
        if button_update(
            self._main_menu_button,
            pos=button_pos,
            width=main_menu_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_main_menu()
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        panel_top_left = self._panel_top_left()
        panel_tex = self._panel_tex
        if panel_tex is not None:
            panel = rl.Rectangle(
                panel_top_left.x,
                panel_top_left.y,
                float(QUEST_FAILED_PANEL_W),
                float(QUEST_FAILED_PANEL_H),
            )
            fx_detail = self.state.config.fx_detail(level=0, default=False)
            draw_classic_menu_panel(panel_tex, dst=panel, tint=rl.WHITE, shadow=fx_detail)

        reaper_tex = self._reaper_tex
        if reaper_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(reaper_tex.width), float(reaper_tex.height))
            banner_pos = panel_top_left + Vec2(QUEST_FAILED_BANNER_X_OFFSET, QUEST_FAILED_BANNER_Y_OFFSET)
            dst = rl.Rectangle(
                banner_pos.x,
                banner_pos.y,
                float(QUEST_FAILED_BANNER_W),
                float(QUEST_FAILED_BANNER_H),
            )
            rl.draw_texture_pro(reaper_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        font = self._ensure_small_font()
        text_color = rl.Color(235, 235, 235, 255)
        draw_small_text(
            font,
            self._failure_message(),
            panel_top_left + Vec2(QUEST_FAILED_MESSAGE_X_OFFSET, QUEST_FAILED_MESSAGE_Y_OFFSET),
            1.0,
            text_color,
        )
        self._draw_score_preview(font, panel_top_left=panel_top_left)

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 1.0
            button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET, QUEST_FAILED_BUTTON_Y_OFFSET)

            retry_w = button_width(
                font, self._retry_button.label, scale=scale, force_wide=self._retry_button.force_wide
            )
            button_draw(textures, font, self._retry_button, pos=button_pos, width=retry_w, scale=scale)
            button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

            play_another_w = button_width(
                font,
                self._quest_list_button.label,
                scale=scale,
                force_wide=self._quest_list_button.force_wide,
            )
            button_draw(
                textures,
                font,
                self._quest_list_button,
                pos=button_pos,
                width=play_another_w,
                scale=scale,
            )
            button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

            main_menu_w = button_width(
                font,
                self._main_menu_button.label,
                scale=scale,
                force_wide=self._main_menu_button.force_wide,
            )
            button_draw(
                textures,
                font,
                self._main_menu_button,
                pos=button_pos,
                width=main_menu_w,
                scale=scale,
            )

        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _panel_origin(self) -> Vec2:
        screen_w = float(rl.get_screen_width())
        widescreen_shift_y = MenuView._menu_widescreen_y_shift(screen_w)
        return Vec2(
            QUEST_FAILED_PANEL_GEOM_X0 + QUEST_FAILED_PANEL_POS_X,
            QUEST_FAILED_PANEL_GEOM_Y0 + QUEST_FAILED_PANEL_POS_Y + widescreen_shift_y,
        )

    def _panel_slide_x(self) -> float:
        if QUEST_FAILED_PANEL_SLIDE_DURATION_MS <= 1e-6:
            return 0.0
        t = float(self._intro_ms) / QUEST_FAILED_PANEL_SLIDE_DURATION_MS
        if t < 0.0:
            t = 0.0
        elif t > 1.0:
            t = 1.0
        eased = 1.0 - (1.0 - t) ** 3
        return -QUEST_FAILED_PANEL_W * (1.0 - eased)

    def _world_entity_alpha(self) -> float:
        if not self._closing:
            return 1.0
        if QUEST_FAILED_PANEL_SLIDE_DURATION_MS <= 1e-6:
            return 0.0
        alpha = float(self._intro_ms) / QUEST_FAILED_PANEL_SLIDE_DURATION_MS
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _panel_top_left(self) -> Vec2:
        return self._panel_origin().offset(dx=self._panel_slide_x())

    def _failure_message(self) -> str:
        retry_count = int(self.state.quest_fail_retry_count)
        if retry_count == 1:
            return "You didn't make it, do try again."
        if retry_count == 2:
            return "Third time no good."
        if retry_count == 3:
            return "No luck this time, have another go?"
        if retry_count == 4:
            if bool(self.state.preserve_bugs):
                return "Persistence will be rewared."
            return "Persistence will be rewarded."
        if retry_count == 5:
            return "Try one more time?"
        return "Quest failed, try again."

    def _build_score_preview(self, outcome: QuestRunOutcome | None) -> None:
        from ...persistence.highscores import HighScoreRecord

        self._record = None
        if outcome is None:
            return

        major = 0
        minor = 0
        try:
            major_text, minor_text = str(outcome.level).split(".", 1)
            major = int(major_text)
            minor = int(minor_text)
        except Exception:
            pass

        record = HighScoreRecord.blank()
        record.set_name(_player_name_default(self.state.config) or "Player")
        record.game_mode_id = 3
        record.quest_stage_major = major
        record.quest_stage_minor = minor
        record.survival_elapsed_ms = max(1, int(outcome.base_time_ms))
        record.score_xp = int(outcome.experience)
        record.creature_kill_count = int(outcome.kill_count)
        record.most_used_weapon_id = int(outcome.most_used_weapon_id)
        fired = max(0, int(outcome.shots_fired))
        hit = max(0, min(int(outcome.shots_hit), fired))
        record.shots_fired = fired
        record.shots_hit = hit

        self._record = record

    def _activate_retry(self) -> None:
        outcome = self._outcome
        if outcome is None:
            return
        self.state.quest_fail_retry_count = int(self.state.quest_fail_retry_count) + 1
        self.state.pending_quest_level = outcome.level
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._begin_close("start_quest")

    def _activate_play_another(self) -> None:
        self.state.quest_fail_retry_count = 0
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._begin_close("open_quests")

    def _activate_main_menu(self) -> None:
        self.state.quest_fail_retry_count = 0
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._begin_close("back_to_menu")

    def _begin_close(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _text_width(self, text: str, scale: float) -> float:
        font = self._small_font
        if font is None:
            return float(rl.measure_text(text, int(20 * scale)))
        return float(measure_small_text_width(font, text, scale))

    def _draw_score_preview(self, font: SmallFontData, *, panel_top_left: Vec2) -> None:
        record = self._record
        if record is None:
            return

        score_pos = panel_top_left + Vec2(QUEST_FAILED_SCORE_X_OFFSET, QUEST_FAILED_SCORE_Y_OFFSET)

        label_color = rl.Color(230, 230, 230, int(255 * 0.8))
        value_color = rl.Color(230, 230, 255, 255)
        # `ui_text_input_render`: data_4965f8/5fc/600 = (149,175,198)/255.
        separator_color = rl.Color(149, 175, 198, int(255 * 0.7))

        score_label = "Score"
        score_label_w = self._text_width(score_label, 1.0)
        draw_small_text(font, score_label, score_pos.offset(dx=32.0 - score_label_w * 0.5), 1.0, label_color)

        score_value = f"{float(int(record.survival_elapsed_ms)) * 0.001:.2f} secs"
        score_value_w = self._text_width(score_value, 1.0)
        draw_small_text(font, score_value, score_pos + Vec2(32.0 - score_value_w * 0.5, 15.0), 1.0, value_color)

        sep_pos = score_pos.offset(dx=80.0)
        rl.draw_line(int(sep_pos.x), int(sep_pos.y), int(sep_pos.x), int(sep_pos.y + 48.0), separator_color)

        col2_pos = score_pos.offset(dx=96.0)
        draw_small_text(font, "Experience", col2_pos, 1.0, value_color)
        xp_value = f"{int(record.score_xp)}"
        xp_w = self._text_width(xp_value, 1.0)
        draw_small_text(font, xp_value, col2_pos + Vec2(32.0 - xp_w * 0.5, 15.0), 1.0, label_color)

        # `FUN_004411c0`: horizontal 192px separator at x-16 after the score row.
        line_pos = score_pos + Vec2(-16.0, 52.0)
        rl.draw_rectangle(int(line_pos.x), int(line_pos.y), int(192.0), int(1.0), separator_color)

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font


__all__ = [
    "QUEST_FAILED_PANEL_SLIDE_DURATION_MS",
    "QUEST_FAILED_PANEL_W",
    "QuestFailedView",
]
