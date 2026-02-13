from __future__ import annotations

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..frontend.assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..frontend.high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_LOCAL_DATE_Y,
    HS_LOCAL_DATE_X,
    HS_LOCAL_FRAGS_X,
    HS_LOCAL_FRAGS_Y,
    HS_LOCAL_HIT_X,
    HS_LOCAL_HIT_Y,
    HS_LOCAL_LABEL_X,
    HS_LOCAL_LABEL_Y,
    HS_LOCAL_NAME_X,
    HS_LOCAL_NAME_Y,
    HS_LOCAL_RANK_X,
    HS_LOCAL_RANK_Y,
    HS_LOCAL_SCORE_LABEL_X,
    HS_LOCAL_SCORE_LABEL_Y,
    HS_LOCAL_SCORE_VALUE_X,
    HS_LOCAL_SCORE_VALUE_Y,
    HS_LOCAL_CLOCK_X,
    HS_LOCAL_CLOCK_Y,
    HS_LOCAL_TIME_LABEL_X,
    HS_LOCAL_TIME_LABEL_Y,
    HS_LOCAL_TIME_VALUE_X,
    HS_LOCAL_TIME_VALUE_Y,
    HS_LOCAL_WEAPON_Y,
    HS_LOCAL_WICON_X,
    HS_LOCAL_WICON_Y,
    HS_LEFT_PANEL_HEIGHT,
    HS_LEFT_PANEL_POS_X,
    HS_LEFT_PANEL_POS_Y,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_PANEL_HEIGHT,
    HS_RIGHT_PANEL_POS_Y,
    HS_RIGHT_GAME_MODE_DROP_X,
    HS_RIGHT_GAME_MODE_DROP_Y,
    HS_RIGHT_GAME_MODE_VALUE_X,
    HS_RIGHT_GAME_MODE_VALUE_Y,
    HS_RIGHT_GAME_MODE_WIDGET_W,
    HS_RIGHT_GAME_MODE_WIDGET_X,
    HS_RIGHT_GAME_MODE_WIDGET_Y,
    HS_RIGHT_GAME_MODE_X,
    HS_RIGHT_GAME_MODE_Y,
    HS_RIGHT_NUMBER_PLAYERS_X,
    HS_RIGHT_NUMBER_PLAYERS_Y,
    HS_RIGHT_PLAYER_COUNT_DROP_X,
    HS_RIGHT_PLAYER_COUNT_DROP_Y,
    HS_RIGHT_PLAYER_COUNT_VALUE_X,
    HS_RIGHT_PLAYER_COUNT_VALUE_Y,
    HS_RIGHT_PLAYER_COUNT_WIDGET_W,
    HS_RIGHT_PLAYER_COUNT_WIDGET_X,
    HS_RIGHT_PLAYER_COUNT_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_DROP_X,
    HS_RIGHT_SCORE_LIST_DROP_Y,
    HS_RIGHT_SCORE_LIST_VALUE_X,
    HS_RIGHT_SCORE_LIST_VALUE_Y,
    HS_RIGHT_SCORE_LIST_WIDGET_W,
    HS_RIGHT_SCORE_LIST_WIDGET_X,
    HS_RIGHT_SCORE_LIST_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_X,
    HS_RIGHT_SCORE_LIST_Y,
    HS_RIGHT_SHOW_INTERNET_X,
    HS_RIGHT_SHOW_INTERNET_Y,
    HS_RIGHT_SHOW_SCORES_DROP_X,
    HS_RIGHT_SHOW_SCORES_DROP_Y,
    HS_RIGHT_SHOW_SCORES_VALUE_X,
    HS_RIGHT_SHOW_SCORES_VALUE_Y,
    HS_RIGHT_SHOW_SCORES_WIDGET_W,
    HS_RIGHT_SHOW_SCORES_WIDGET_X,
    HS_RIGHT_SHOW_SCORES_WIDGET_Y,
    HS_RIGHT_SHOW_SCORES_X,
    HS_RIGHT_SHOW_SCORES_Y,
    HS_SCORE_FRAME_H,
    HS_SCORE_FRAME_W,
    HS_SCORE_FRAME_X,
    HS_SCORE_FRAME_Y,
    HS_TITLE_UNDERLINE_Y,
    hs_right_panel_pos_x,
)
from ..frontend.menu import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    UI_SHADOW_OFFSET,
    MenuView,
    _draw_menu_cursor,
    ensure_menu_ground,
    menu_ground_camera,
)
from ..frontend.panels.base import FADE_TO_GAME_ACTIONS, PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS
from ..frontend.transitions import _draw_screen_fade
from ..ui.menu_panel import draw_classic_menu_panel
from ..ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from .types import GameState, HighScoresRequest

class HighScoresView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._small_font: SmallFontData | None = None
        self._button_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._check_on: rl.Texture | None = None
        self._drop_off: rl.Texture | None = None
        self._arrow_tex: rl.Texture | None = None
        self._wicons_tex: rl.Texture | None = None
        self._clock_table_tex: rl.Texture | None = None
        self._clock_pointer_tex: rl.Texture | None = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._request: HighScoresRequest | None = None
        self._records: list = []
        self._scroll_index = 0

    def open(self) -> None:
        from ..persistence.highscores import read_highscore_table, scores_path_for_mode

        layout_w = float(self._state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._action = None
        self._assets = load_menu_assets(self._state)
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._small_font = None
        self._scroll_index = 0
        self._button_textures = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        cache = _ensure_texture_cache(self._state)
        self._button_tex = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=self._button_tex)
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._arrow_tex = cache.get_or_load("ui_arrow", "ui/ui_arrow.jaz").texture
        self._wicons_tex = cache.get_or_load("ui_wicons", "ui/ui_wicons.jaz").texture
        self._clock_table_tex = cache.get_or_load("ui_clockTable", "ui/ui_clockTable.jaz").texture
        self._clock_pointer_tex = cache.get_or_load("ui_clockPointer", "ui/ui_clockPointer.jaz").texture

        request = self._state.pending_high_scores
        self._state.pending_high_scores = None
        if request is None:
            request = HighScoresRequest(game_mode_id=self._state.config.game_mode)

        if int(request.game_mode_id) == 3 and (
            int(request.quest_stage_major) <= 0 or int(request.quest_stage_minor) <= 0
        ):
            major, minor = self._parse_quest_level(self._state.pending_quest_level)
            if major <= 0 or minor <= 0:
                major, minor = self._parse_quest_level(self._state.config.quest_level)
            if major <= 0 or minor <= 0:
                major = self._state.config.quest_stage_major
                minor = self._state.config.quest_stage_minor
            request.quest_stage_major = int(major)
            request.quest_stage_minor = int(minor)

        self._request = request
        path = scores_path_for_mode(
            self._state.base_dir,
            int(request.game_mode_id),
            hardcore=self._state.config.hardcore,
            quest_stage_major=int(request.quest_stage_major),
            quest_stage_minor=int(request.quest_stage_minor),
        )
        try:
            self._records = read_highscore_table(path, game_mode_id=int(request.game_mode_id))
        except Exception:
            self._records = []
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._wicons_tex = None
        self._clock_table_tex = None
        self._clock_pointer_tex = None
        self._assets = None
        self._button_tex = None
        self._button_textures = None
        self._check_on = None
        self._drop_off = None
        self._arrow_tex = None
        self._request = None
        self._records = []
        self._scroll_index = 0
        self._closing = False
        self._close_action = None

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._action = self._close_action
                    self._close_action = None
            return
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition("back_to_previous")
            return

        textures = self._button_textures
        if enabled and textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
            font = self._ensure_small_font()
            panel_top_left = self._panel_top_left(pos=Vec2(HS_LEFT_PANEL_POS_X, HS_LEFT_PANEL_POS_Y), scale=scale)
            button_base_pos = panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            w = button_width(font, self._update_button.label, scale=scale, force_wide=self._update_button.force_wide)
            if button_update(
                self._update_button,
                pos=button_base_pos,
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                # Reload scores from disk (no view transition).
                if self._state.audio is not None:
                    play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
                self.open()
                return
            w = button_width(font, self._play_button.label, scale=scale, force_wide=self._play_button.force_wide)
            if button_update(
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._begin_close_transition("open_play_game")
                return
            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            if button_update(
                self._back_button,
                pos=panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
                width=back_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._begin_close_transition("back_to_previous")
                return

        rows = 10
        max_scroll = max(0, len(self._records) - rows)

        if enabled:
            wheel = int(rl.get_mouse_wheel_move())
            if wheel:
                self._scroll_index = max(0, min(max_scroll, int(self._scroll_index) - wheel))

            if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
                self._scroll_index = max(0, int(self._scroll_index) - 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
                self._scroll_index = min(max_scroll, int(self._scroll_index) + 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
                self._scroll_index = max(0, int(self._scroll_index) - rows)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
                self._scroll_index = min(max_scroll, int(self._scroll_index) + rows)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
                self._scroll_index = 0
            if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
                self._scroll_index = max_scroll

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self._state))
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None or assets.panel is None:
            return

        font = self._ensure_small_font()
        request = self._request
        mode_id = (
            int(request.game_mode_id) if request is not None else self._state.config.game_mode
        )
        quest_major = int(request.quest_stage_major) if request is not None else 0
        quest_minor = int(request.quest_stage_minor) if request is not None else 0

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        fx_detail = self._state.config.fx_detail(level=0, default=False)
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, left_slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )

        left_top_left = self._panel_top_left(pos=Vec2(HS_LEFT_PANEL_POS_X, HS_LEFT_PANEL_POS_Y), scale=scale)
        right_panel_pos_x = hs_right_panel_pos_x(float(self._state.config.screen_width))
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, HS_LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, HS_RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        title = (
            "High scores - Quests"
            if int(mode_id) == 3
            else f"High scores - {self._mode_label(mode_id, quest_major, quest_minor)}"
        )
        title_x = 269.0
        if int(mode_id) == 1:
            # state_14:High scores - Survival title at x=168 (panel left_x0 is -98).
            title_x = 266.0
        title_draw_pos = left_panel_top_left + Vec2(title_x * scale, 41.0 * scale)
        draw_small_text(
            font,
            title,
            title_draw_pos,
            1.0 * scale,
            rl.Color(255, 255, 255, 255),
        )
        ul_w = measure_small_text_width(font, title, 1.0 * scale)
        ul_h = max(1, int(round(1.0 * scale)))
        ul_pos = left_panel_top_left + Vec2(title_x * scale, HS_TITLE_UNDERLINE_Y * scale)
        rl.draw_rectangle(
            int(round(ul_pos.x)),
            int(round(ul_pos.y)),
            int(round(ul_w)),
            ul_h,
            rl.Color(255, 255, 255, int(255 * 0.7)),
        )
        if int(mode_id) == 3:
            hardcore = self._state.config.hardcore
            if hardcore:
                quest_color = rl.Color(250, 70, 60, int(255 * 0.7))
            else:
                quest_color = rl.Color(70, 180, 240, int(255 * 0.7))
            quest_label = f"{int(quest_major)}.{int(quest_minor)}: {self._quest_title(quest_major, quest_minor)}"
            draw_small_text(
                font,
                quest_label,
                left_panel_top_left + Vec2(236.0 * scale, 63.0 * scale),
                1.0 * scale,
                quest_color,
            )
            arrow = self._arrow_tex
            if arrow is not None:
                dst_w = float(arrow.width) * scale
                dst_h = float(arrow.height) * scale
                # state_14 draws ui_arrow.jaz flipped (uv 1..0) to point left.
                src = rl.Rectangle(float(arrow.width), 0.0, -float(arrow.width), float(arrow.height))
                arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X * scale, HS_QUEST_ARROW_Y * scale)
                dst = rl.Rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
                rl.draw_texture_pro(arrow, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        header_color = rl.Color(255, 255, 255, 255)
        draw_small_text(
            font, "Rank", left_panel_top_left + Vec2(211.0 * scale, 84.0 * scale), 1.0 * scale, header_color
        )
        draw_small_text(
            font, "Score", left_panel_top_left + Vec2(246.0 * scale, 84.0 * scale), 1.0 * scale, header_color
        )
        draw_small_text(
            font, "Player", left_panel_top_left + Vec2(302.0 * scale, 84.0 * scale), 1.0 * scale, header_color
        )

        # Score list viewport frame (white 1px border + black interior).
        frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X * scale
        frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y * scale
        frame_w = HS_SCORE_FRAME_W * scale
        frame_h = HS_SCORE_FRAME_H * scale
        rl.draw_rectangle(int(round(frame_x)), int(round(frame_y)), int(round(frame_w)), int(round(frame_h)), rl.WHITE)
        rl.draw_rectangle(
            int(round(frame_x + 1.0 * scale)),
            int(round(frame_y + 1.0 * scale)),
            max(0, int(round(frame_w - 2.0 * scale))),
            max(0, int(round(frame_h - 2.0 * scale))),
            rl.BLACK,
        )

        row_step = 16.0 * scale
        rows = 10
        start = max(0, int(self._scroll_index))
        end = min(len(self._records), start + rows)
        y = left_panel_top_left.y + 103.0 * scale
        selected_rank = int(request.highlight_rank) if (request is not None and request.highlight_rank is not None) else None
        mouse = Vec2.from_xy(rl.get_mouse_position())
        frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X * scale
        frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y * scale
        frame_w = HS_SCORE_FRAME_W * scale
        frame_h = HS_SCORE_FRAME_H * scale
        if (
            frame_x <= mouse.x < frame_x + frame_w
            and frame_y <= mouse.y < frame_y + frame_h
            and y <= mouse.y < y + row_step * rows
        ):
            row = int((mouse.y - y) // row_step)
            hovered_idx = start + row
            if start <= hovered_idx < end:
                selected_rank = hovered_idx

        if start >= end:
            draw_small_text(
                font,
                "No scores yet.",
                Vec2(left_panel_top_left.x + 211.0 * scale, y + 8.0 * scale),
                1.0 * scale,
                rl.Color(190, 190, 200, 255),
            )
        else:
            for idx in range(start, end):
                entry = self._records[idx]
                name = ""
                try:
                    name = str(entry.name())
                except Exception:
                    name = ""
                if not name:
                    name = "???"
                if len(name) > 16:
                    name = name[:16]

                value = f"{int(getattr(entry, 'score_xp', 0))}"

                color = rl.Color(255, 255, 255, int(255 * 0.7))
                if selected_rank is not None and int(selected_rank) == idx:
                    color = rl.Color(255, 255, 255, 255)

                draw_small_text(font, f"{idx + 1}", Vec2(left_panel_top_left.x + 216.0 * scale, y), 1.0 * scale, color)
                draw_small_text(font, value, Vec2(left_panel_top_left.x + 246.0 * scale, y), 1.0 * scale, color)
                draw_small_text(font, name, Vec2(left_panel_top_left.x + 304.0 * scale, y), 1.0 * scale, color)
                y += row_step

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            button_base_pos = left_panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
            w = button_width(font, self._update_button.label, scale=scale, force_wide=self._update_button.force_wide)
            button_draw(textures, font, self._update_button, pos=button_base_pos, width=w, scale=scale)
            w = button_width(font, self._play_button.label, scale=scale, force_wide=self._play_button.force_wide)
            button_draw(
                textures,
                font,
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
                width=w,
                scale=scale,
            )
            w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=left_panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
                width=w,
                scale=scale,
            )

        self._draw_right_panel(
            font=font,
            right_top_left=right_panel_top_left,
            scale=scale,
            mode_id=mode_id,
            highlight_rank=selected_rank,
        )
        self._draw_sign(assets)
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _draw_right_panel(
        self,
        *,
        font: SmallFontData,
        right_top_left: Vec2,
        scale: float,
        mode_id: int,
        highlight_rank: int | None,
    ) -> None:
        if highlight_rank is None:
            self._draw_right_panel_quest_options(font=font, right_top_left=right_top_left, scale=scale)
            return
        self._draw_right_panel_local_score(
            font=font,
            right_top_left=right_top_left,
            scale=scale,
            highlight_rank=highlight_rank,
        )

    def _draw_right_panel_quest_options(self, *, font: SmallFontData, right_top_left: Vec2, scale: float) -> None:
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        check_on = self._check_on
        if check_on is not None:
            check_w = float(check_on.width) * scale
            check_h = float(check_on.height) * scale
            rl.draw_texture_pro(
                check_on,
                rl.Rectangle(0.0, 0.0, float(check_on.width), float(check_on.height)),
                rl.Rectangle(
                    right_top_left.x + HS_RIGHT_CHECK_X * scale,
                    right_top_left.y + HS_RIGHT_CHECK_Y * scale,
                    check_w,
                    check_h,
                ),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
        draw_small_text(
            font,
            "Show internet scores",
            right_top_left + Vec2(HS_RIGHT_SHOW_INTERNET_X * scale, HS_RIGHT_SHOW_INTERNET_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Number of players",
            right_top_left + Vec2(HS_RIGHT_NUMBER_PLAYERS_X * scale, HS_RIGHT_NUMBER_PLAYERS_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Game mode",
            right_top_left + Vec2(HS_RIGHT_GAME_MODE_X * scale, HS_RIGHT_GAME_MODE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Show scores:",
            right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_X * scale, HS_RIGHT_SHOW_SCORES_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Selected score list:",
            right_top_left + Vec2(HS_RIGHT_SCORE_LIST_X * scale, HS_RIGHT_SCORE_LIST_Y * scale),
            text_scale,
            text_color,
        )

        # Closed list widgets (state_14 quest variant): white border + black fill.
        widget_h = 16.0 * scale
        for widget_offset, widget_width in (
            (Vec2(HS_RIGHT_PLAYER_COUNT_WIDGET_X, HS_RIGHT_PLAYER_COUNT_WIDGET_Y), HS_RIGHT_PLAYER_COUNT_WIDGET_W),
            (Vec2(HS_RIGHT_GAME_MODE_WIDGET_X, HS_RIGHT_GAME_MODE_WIDGET_Y), HS_RIGHT_GAME_MODE_WIDGET_W),
            (Vec2(HS_RIGHT_SHOW_SCORES_WIDGET_X, HS_RIGHT_SHOW_SCORES_WIDGET_Y), HS_RIGHT_SHOW_SCORES_WIDGET_W),
            (Vec2(HS_RIGHT_SCORE_LIST_WIDGET_X, HS_RIGHT_SCORE_LIST_WIDGET_Y), HS_RIGHT_SCORE_LIST_WIDGET_W),
        ):
            widget_pos = right_top_left + widget_offset * scale
            w = float(widget_width) * scale
            rl.draw_rectangle(int(widget_pos.x), int(widget_pos.y), int(w), int(widget_h), rl.WHITE)
            rl.draw_rectangle(
                int(widget_pos.x) + 1,
                int(widget_pos.y) + 1,
                max(0, int(w) - 2),
                max(0, int(widget_h) - 2),
                rl.BLACK,
            )

        # Values (static in the oracle).
        player_count = self._state.config.player_count
        if player_count < 1:
            player_count = 1
        if player_count > 4:
            player_count = 4
        player_count_label = f"{player_count} player"
        if player_count != 1:
            player_count_label += "s"
        draw_small_text(
            font,
            player_count_label,
            right_top_left + Vec2(HS_RIGHT_PLAYER_COUNT_VALUE_X * scale, HS_RIGHT_PLAYER_COUNT_VALUE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Quests",
            right_top_left + Vec2(HS_RIGHT_GAME_MODE_VALUE_X * scale, HS_RIGHT_GAME_MODE_VALUE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Best of all time",
            right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_VALUE_X * scale, HS_RIGHT_SHOW_SCORES_VALUE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "default",
            right_top_left + Vec2(HS_RIGHT_SCORE_LIST_VALUE_X * scale, HS_RIGHT_SCORE_LIST_VALUE_Y * scale),
            text_scale,
            text_color,
        )

        drop_off = self._drop_off
        if drop_off is None:
            return
        drop_w = float(drop_off.width) * scale
        drop_h = float(drop_off.height) * scale
        for drop_offset in (
            Vec2(HS_RIGHT_PLAYER_COUNT_DROP_X, HS_RIGHT_PLAYER_COUNT_DROP_Y),
            Vec2(HS_RIGHT_GAME_MODE_DROP_X, HS_RIGHT_GAME_MODE_DROP_Y),
            Vec2(HS_RIGHT_SHOW_SCORES_DROP_X, HS_RIGHT_SHOW_SCORES_DROP_Y),
            Vec2(HS_RIGHT_SCORE_LIST_DROP_X, HS_RIGHT_SCORE_LIST_DROP_Y),
        ):
            drop_pos = right_top_left + drop_offset * scale
            rl.draw_texture_pro(
                drop_off,
                rl.Rectangle(0.0, 0.0, float(drop_off.width), float(drop_off.height)),
                rl.Rectangle(
                    drop_pos.x,
                    drop_pos.y,
                    drop_w,
                    drop_h,
                ),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )

    def _draw_right_panel_local_score(
        self,
        *,
        font: SmallFontData,
        right_top_left: Vec2,
        scale: float,
        highlight_rank: int | None,
    ) -> None:
        if not self._records:
            return
        idx = int(highlight_rank) if highlight_rank is not None else int(self._scroll_index)
        if idx < 0:
            idx = 0
        if idx >= len(self._records):
            idx = len(self._records) - 1
        entry = self._records[idx]

        text_scale = 1.0 * scale
        text_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.8))
        value_color = rl.Color(int(255 * 0.9), int(255 * 0.9), 255, 255)
        game_time_color = rl.Color(255, 255, 255, int(255 * 0.8))
        lower_section_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.7))
        separator_color = rl.Color(149, 175, 198, int(255 * 0.7))

        name = ""
        try:
            name = str(entry.name())
        except Exception:
            name = ""
        if not name:
            name = "???"
        draw_small_text(
            font,
            name,
            right_top_left + Vec2(HS_LOCAL_NAME_X * scale, HS_LOCAL_NAME_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Local score",
            right_top_left + Vec2(HS_LOCAL_LABEL_X * scale, HS_LOCAL_LABEL_Y * scale),
            text_scale,
            text_color,
        )
        rl.draw_line(
            int(right_top_left.x + 78.0 * scale),
            int(right_top_left.y + 57.0 * scale),
            int(right_top_left.x + 117.0 * scale),
            int(right_top_left.y + 57.0 * scale),
            separator_color,
        )

        date_text = self._format_score_date(entry)
        if date_text:
            draw_small_text(
                font,
                date_text,
                right_top_left + Vec2(HS_LOCAL_DATE_X * scale, HS_LOCAL_DATE_Y * scale),
                text_scale,
                text_color,
            )
        rl.draw_line(
            int(right_top_left.x + 74.0 * scale),
            int(right_top_left.y + 72.0 * scale),
            int(right_top_left.x + 266.0 * scale),
            int(right_top_left.y + 72.0 * scale),
            separator_color,
        )

        draw_small_text(
            font,
            "Score",
            right_top_left + Vec2(HS_LOCAL_SCORE_LABEL_X * scale, HS_LOCAL_SCORE_LABEL_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Game time",
            right_top_left + Vec2(HS_LOCAL_TIME_LABEL_X * scale, HS_LOCAL_TIME_LABEL_Y * scale),
            text_scale,
            game_time_color,
        )
        rl.draw_line(
            int(right_top_left.x + 170.0 * scale),
            int(right_top_left.y + 90.0 * scale),
            int(right_top_left.x + 170.0 * scale),
            int(right_top_left.y + 138.0 * scale),
            separator_color,
        )

        score_value = f"{int(getattr(entry, 'score_xp', 0))}"
        draw_small_text(
            font,
            score_value,
            right_top_left + Vec2(HS_LOCAL_SCORE_VALUE_X * scale, HS_LOCAL_SCORE_VALUE_Y * scale),
            text_scale,
            value_color,
        )

        elapsed_ms = int(getattr(entry, "survival_elapsed_ms", 0) or 0)
        self._draw_clock_gauge(
            elapsed_ms=elapsed_ms,
            pos=right_top_left + Vec2(HS_LOCAL_CLOCK_X * scale, HS_LOCAL_CLOCK_Y * scale),
            scale=scale,
        )
        draw_small_text(
            font,
            self._format_elapsed_mm_ss(elapsed_ms),
            right_top_left + Vec2(HS_LOCAL_TIME_VALUE_X * scale, HS_LOCAL_TIME_VALUE_Y * scale),
            text_scale,
            game_time_color,
        )

        draw_small_text(
            font,
            f"Rank: {self._ordinal(idx + 1)}",
            right_top_left + Vec2(HS_LOCAL_RANK_X * scale, HS_LOCAL_RANK_Y * scale),
            text_scale,
            text_color,
        )

        frags = int(getattr(entry, "creature_kill_count", 0) or 0)

        shots_fired = int(getattr(entry, "shots_fired", 0) or 0)
        shots_hit = int(getattr(entry, "shots_hit", 0) or 0)
        hit_pct = 0
        if shots_fired > 0:
            hit_pct = int((shots_hit * 100) // shots_fired)
        rl.draw_line(
            int(right_top_left.x + 74.0 * scale),
            int(right_top_left.y + 142.0 * scale),
            int(right_top_left.x + 266.0 * scale),
            int(right_top_left.y + 142.0 * scale),
            separator_color,
        )

        weapon_id = int(getattr(entry, "most_used_weapon_id", 0) or 0)
        weapon_name, icon_index = self._weapon_label_and_icon(weapon_id)
        if icon_index is not None:
            self._draw_wicon(
                icon_index,
                pos=right_top_left + Vec2(HS_LOCAL_WICON_X * scale, HS_LOCAL_WICON_Y * scale),
                scale=scale,
            )
        weapon_name_x = HS_LOCAL_WICON_X * scale + max(
            0.0,
            32.0 * scale - measure_small_text_width(font, weapon_name, text_scale) * 0.5,
        )
        draw_small_text(
            font,
            weapon_name,
            right_top_left + Vec2(weapon_name_x, HS_LOCAL_WEAPON_Y * scale),
            text_scale,
            lower_section_color,
        )
        draw_small_text(
            font,
            f"Frags: {frags}",
            right_top_left + Vec2(HS_LOCAL_FRAGS_X * scale, HS_LOCAL_FRAGS_Y * scale),
            text_scale,
            lower_section_color,
        )
        draw_small_text(
            font,
            f"Hit %: {hit_pct}%",
            right_top_left + Vec2(HS_LOCAL_HIT_X * scale, HS_LOCAL_HIT_Y * scale),
            text_scale,
            lower_section_color,
        )
        rl.draw_line(
            int(right_top_left.x + 74.0 * scale),
            int(right_top_left.y + 194.0 * scale),
            int(right_top_left.x + 266.0 * scale),
            int(right_top_left.y + 194.0 * scale),
            separator_color,
        )

    def _draw_clock_gauge(self, *, elapsed_ms: int, pos: Vec2, scale: float) -> None:
        table_tex = self._clock_table_tex
        pointer_tex = self._clock_pointer_tex
        if table_tex is None or pointer_tex is None:
            return
        draw_w = 32.0 * scale
        draw_h = 32.0 * scale
        dst = rl.Rectangle(pos.x, pos.y, draw_w, draw_h)
        src_table = rl.Rectangle(0.0, 0.0, float(table_tex.width), float(table_tex.height))
        src_pointer = rl.Rectangle(0.0, 0.0, float(pointer_tex.width), float(pointer_tex.height))
        rl.draw_texture_pro(
            table_tex,
            src_table,
            dst,
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )
        seconds = max(0, int(elapsed_ms) // 1000)
        rotation_deg = float(seconds) * 6.0
        center = Vec2(pos.x + draw_w * 0.5, pos.y + draw_h * 0.5)
        rl.draw_texture_pro(
            pointer_tex,
            src_pointer,
            rl.Rectangle(center.x, center.y, draw_w, draw_h),
            rl.Vector2(draw_w * 0.5, draw_h * 0.5),
            rotation_deg,
            rl.WHITE,
        )

    def _draw_wicon(self, icon_index: int, *, pos: Vec2, scale: float) -> None:
        tex = self._wicons_tex
        if tex is None:
            return
        idx = int(icon_index)
        if idx < 0 or idx > 31:
            return
        grid = 8
        cell_w = float(tex.width) / float(grid)
        cell_h = float(tex.height) / float(grid)
        frame = idx * 2
        src_x = float(frame % grid) * cell_w
        src_y = float(frame // grid) * cell_h
        icon_w = cell_w * 2.0
        icon_h = cell_h
        rl.draw_texture_pro(
            tex,
            rl.Rectangle(src_x, src_y, icon_w, icon_h),
            rl.Rectangle(pos.x, pos.y, icon_w * scale, icon_h * scale),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

    @staticmethod
    def _ordinal(value: int) -> str:
        n = int(value)
        if 10 <= (n % 100) <= 20:
            return f"{n}th"
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
        return f"{n}{suffix}"

    @staticmethod
    def _format_elapsed_mm_ss(value_ms: int) -> str:
        total = max(0, int(value_ms)) // 1000
        minutes, seconds = divmod(total, 60)
        return f"{minutes}:{seconds:02d}"

    @staticmethod
    def _format_score_date(entry: object) -> str:
        try:
            day = int(getattr(entry, "day", 0) or 0)
            month = int(getattr(entry, "month", 0) or 0)
            year_off = int(getattr(entry, "year_offset", 0) or 0)
        except Exception:
            return ""
        if day <= 0 or month <= 0:
            return ""
        months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        month_name = months[month - 1] if 1 <= month <= 12 else f"{month}"
        year = 2000 + year_off if year_off >= 0 else 2000
        return f"{day}. {month_name} {year}"

    def _weapon_label_and_icon(self, weapon_id: int) -> tuple[str, int | None]:
        from ..weapons import WEAPON_BY_ID, weapon_display_name

        weapon = WEAPON_BY_ID.get(int(weapon_id))
        if weapon is None:
            return f"Weapon {int(weapon_id)}", None
        name = weapon_display_name(int(weapon.weapon_id), preserve_bugs=bool(self._state.preserve_bugs))
        return name, weapon.icon_index

    def _draw_sign(self, assets: MenuAssets) -> None:
        if assets.sign is None:
            return
        sign = assets.sign
        screen_w = float(self._state.config.screen_width)
        sign_scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
        sign_w = MENU_SIGN_WIDTH * sign_scale
        sign_h = MENU_SIGN_HEIGHT * sign_scale
        offset_x = MENU_SIGN_OFFSET_X * sign_scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * sign_scale
        rotation_deg = 0.0
        fx_detail = self._state.config.fx_detail(level=0, default=False)
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(sign_pos.x + UI_SHADOW_OFFSET, sign_pos.y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(sign_pos.x, sign_pos.y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

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

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        if action in FADE_TO_GAME_ACTIONS:
            self._state.screen_fade_alpha = 0.0
            self._state.screen_fade_ramp = True
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._closing = True
        self._close_action = action

    @staticmethod
    def _quest_title(major: int, minor: int) -> str:
        try:
            from ..quests import quest_by_level

            q = quest_by_level(f"{int(major)}.{int(minor)}")
            if q is not None and q.title:
                return str(q.title)
        except Exception:
            pass
        return "???"

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _visible_rows(self, font: SmallFontData) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(rl.get_screen_height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))

    @staticmethod
    def _parse_quest_level(level: str | None) -> tuple[int, int]:
        if not level:
            return (0, 0)
        try:
            major_text, minor_text = str(level).split(".", 1)
            return (int(major_text), int(minor_text))
        except Exception:
            return (0, 0)

    @staticmethod
    def _mode_label(mode_id: int, quest_major: int, quest_minor: int) -> str:
        if int(mode_id) == 1:
            return "Survival"
        if int(mode_id) == 2:
            return "Rush"
        if int(mode_id) == 4:
            return "Typ-o Shooter"
        if int(mode_id) == 3:
            if int(quest_major) > 0 and int(quest_minor) > 0:
                return f"Quest {int(quest_major)}.{int(quest_minor)}"
            return "Quests"
        return f"Mode {int(mode_id)}"

