from __future__ import annotations

from dataclasses import dataclass
import math

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.fonts.small import (
    SmallFontData,
    draw_small_text,
    load_small_font,
)
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
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
)
from ..transitions import _draw_screen_fade
from ..types import GameState
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS


_BOARD_SIDE = 6
_BOARD_CELLS = _BOARD_SIDE * _BOARD_SIDE
_TILE_SIZE = 32.0
_BOARD_SIZE = 192.0

_TIMER_RESET_MS = 0x2580
_MATCH_TIMER_BONUS_MS = 2000

# Directly mirrored from the native flow for 1024x768 mode:
#   data_489df8 = -35, data_489dfc = 275, data_489e1c = -63, data_489e20 = -81.
_LAYOUT_OFFSET_X = -35.0
_LAYOUT_OFFSET_X_SMALL = -85.0
_LAYOUT_POS_X = -63.0
_LAYOUT_POS_Y = -81.0
_LAYOUT_BASE_Y = 275.0
_TITLE_BASE_Y_OFFSET = 50.0
_BOARD_X_OFFSET = 220.0  # 300 - 80
_BOARD_Y_OFFSET = 40.0

_TITLE = "AlienZooKeeper"
_SUBTITLE_1 = "a puzzle game unfinished"
_SUBTITLE_2 = "..or something more?"
_LABEL_SCORE = "score: %d"
_LABEL_GAME_OVER = "Game Over"

_RESET_LABEL = "Reset"
_BACK_LABEL = "Back"


@dataclass(slots=True)
class _AzkLayout:
    scale: float
    panel_x: float
    panel_y: float
    board_x: float
    board_y: float
    tile_size: float
    board_size: float
    title_x: float
    title_y: float
    subtitle_1_x: float
    subtitle_1_y: float
    subtitle_2_x: float
    subtitle_2_y: float
    score_x: float
    score_y: float
    game_over_x: float
    game_over_y: float
    reset_pos: Vec2
    back_pos: Vec2


def _to_color(r: float, g: float, b: float, a: float) -> rl.Color:
    return rl.Color(
        int(max(0.0, min(1.0, r)) * 255.0 + 0.5),
        int(max(0.0, min(1.0, g)) * 255.0 + 0.5),
        int(max(0.0, min(1.0, b)) * 255.0 + 0.5),
        int(max(0.0, min(1.0, a)) * 255.0 + 0.5),
    )


def _mouse_inside_rect(mouse: rl.Vector2, *, x: float, y: float, w: float, h: float) -> bool:
    return (x <= mouse.x <= (x + w)) and (y <= mouse.y <= (y + h))


def _credits_secret_match3_find(board: list[int]) -> tuple[bool, int, int]:
    # Native order: horizontal first, then vertical.
    for row in range(_BOARD_SIDE):
        base = row * _BOARD_SIDE
        for col in range(_BOARD_SIDE - 2):
            idx = base + col
            v = board[idx]
            if v < 0:
                continue
            if board[idx + 1] == v and board[idx + 2] == v:
                return True, idx, 1

    for col in range(_BOARD_SIDE):
        for row in range(_BOARD_SIDE - 2):
            idx = row * _BOARD_SIDE + col
            v = board[idx]
            if v < 0:
                continue
            if board[idx + _BOARD_SIDE] == v and board[idx + (_BOARD_SIDE * 2)] == v:
                return True, idx, 0

    return False, 0, 0


class AlienZooKeeperView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._alien_texture: rl.Texture | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None
        self._action: str | None = None

        self._board: list[int] = [0] * _BOARD_CELLS
        self._selected_index = -1
        self._timer_ms = _TIMER_RESET_MS
        self._anim_time_ms = 0
        self._score = 0

        self._reset_button = UiButtonState(_RESET_LABEL, force_wide=False)
        self._back_button = UiButtonState(_BACK_LABEL, force_wide=False)

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self._state)
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._small_font = None

        cache = _ensure_texture_cache(self._state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._alien_texture = cache.get_or_load("alien", "game/alien.jaz").texture

        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

        self._reset_button = UiButtonState(_RESET_LABEL, force_wide=False)
        self._back_button = UiButtonState(_BACK_LABEL, force_wide=False)

        self._anim_time_ms = 0
        self._reset_state()

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_textures = None
        self._assets = None
        self._ground = None
        self._alien_texture = None
        self._action = None
        self._closing = False
        self._close_action = None
        self._pending_action = None

    def take_action(self) -> str | None:
        if self._pending_action is not None:
            action = self._pending_action
            self._pending_action = None
            self._closing = False
            self._close_action = None
            self._timeline_ms = self._timeline_max_ms
            return action
        action = self._action
        self._action = None
        return action

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _panel_slide_x(self, *, scale: float) -> float:
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        return float(slide_x)

    def _layout(self, *, scale: float) -> _AzkLayout:
        layout_offset_x = _LAYOUT_OFFSET_X_SMALL if float(self._state.config.screen_width) < 641.0 else _LAYOUT_OFFSET_X
        slide_x = self._panel_slide_x(scale=scale)
        anchor_x = _LAYOUT_POS_X + layout_offset_x + _BOARD_X_OFFSET + slide_x
        title_base_y = _LAYOUT_BASE_Y + _LAYOUT_POS_Y + _TITLE_BASE_Y_OFFSET + self._widescreen_y_shift
        board_x = anchor_x + (22.0 * scale)
        board_y = title_base_y + (_BOARD_Y_OFFSET * scale)

        tile_size = _TILE_SIZE * scale
        board_size = _BOARD_SIZE * scale

        return _AzkLayout(
            scale=scale,
            panel_x=_LAYOUT_POS_X + layout_offset_x + slide_x,
            panel_y=_LAYOUT_BASE_Y + _LAYOUT_POS_Y + self._widescreen_y_shift,
            board_x=board_x,
            board_y=board_y,
            tile_size=tile_size,
            board_size=board_size,
            title_x=anchor_x,
            title_y=title_base_y - (14.0 * scale),
            subtitle_1_x=anchor_x + (12.0 * scale),
            subtitle_1_y=title_base_y + (10.0 * scale),
            subtitle_2_x=anchor_x + (18.0 * scale),
            subtitle_2_y=title_base_y + (23.0 * scale),
            score_x=board_x + (124.0 * scale),
            score_y=board_y - (16.0 * scale),
            game_over_x=board_x + (38.0 * scale),
            game_over_y=board_y + (74.0 * scale),  # 96 - 22
            reset_pos=Vec2(anchor_x + (38.0 * scale), title_base_y + (256.0 * scale)),
            back_pos=Vec2(anchor_x + (138.0 * scale), title_base_y + (256.0 * scale)),
        )

    def _fill_empty_cells(self) -> None:
        for i, value in enumerate(self._board):
            if value == -1:
                self._board[i] = self._state.rng.randrange(5)

    def _reroll_board_no_initial_match(self) -> None:
        for _ in range(4096):
            for i in range(_BOARD_CELLS):
                self._board[i] = self._state.rng.randrange(5)
            has_match, _out_idx, _out_dir = _credits_secret_match3_find(self._board)
            if not has_match:
                return
        # Fallback to avoid a hard loop even though this should never happen in practice.
        for i in range(_BOARD_CELLS):
            self._board[i] = self._state.rng.randrange(5)

    def _reset_state(self) -> None:
        self._reroll_board_no_initial_match()
        self._selected_index = -1
        self._score = 0
        self._timer_ms = _TIMER_RESET_MS

    def _resolve_tile_click(self, *, layout: _AzkLayout, mouse: rl.Vector2) -> None:
        if self._timer_ms <= 0:
            return

        for index, cell_value in enumerate(self._board):
            if cell_value == -3:
                continue
            row = index // _BOARD_SIDE
            col = index % _BOARD_SIDE
            x = layout.board_x + col * layout.tile_size
            y = layout.board_y + row * layout.tile_size
            if not _mouse_inside_rect(mouse, x=x, y=y, w=layout.tile_size, h=layout.tile_size):
                continue

            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_clink_01", rng=self._state.rng)

            if self._selected_index == -1:
                self._selected_index = index
                return

            selected = self._selected_index
            self._board[index], self._board[selected] = self._board[selected], self._board[index]
            self._selected_index = -1

            has_match, out_idx, out_dir = _credits_secret_match3_find(self._board)
            if not has_match:
                return

            self._board[out_idx] = -3
            if out_dir == 0:
                if (out_idx + _BOARD_SIDE) < _BOARD_CELLS:
                    self._board[out_idx + _BOARD_SIDE] = -3
                if (out_idx + (_BOARD_SIDE * 2)) < _BOARD_CELLS:
                    self._board[out_idx + (_BOARD_SIDE * 2)] = -3
            else:
                if (out_idx + 1) < _BOARD_CELLS:
                    self._board[out_idx + 1] = -3
                if (out_idx + 2) < _BOARD_CELLS:
                    self._board[out_idx + 2] = -3

            self._score += 1
            self._timer_ms += _MATCH_TIMER_BONUS_MS
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_bonus", rng=self._state.rng)
            return

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()

        dt_clamped = min(float(dt), 0.1)
        dt_ms = int(dt_clamped * 1000.0)
        self._cursor_pulse_time += dt_clamped * 1.1

        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))
            self._anim_time_ms += dt_ms
            if self._timer_ms > 0:
                self._timer_ms -= dt_ms
                if self._timer_ms <= 0:
                    self._timer_ms = 0
                    if self._state.audio is not None:
                        play_sfx(self._state.audio, "sfx_trooper_die_01", rng=self._state.rng)
            elif self._timer_ms < 0:
                self._timer_ms = 0

        self._fill_empty_cells()

        interactive = self._timeline_ms >= self._timeline_max_ms
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and interactive:
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._begin_close_transition("open_statistics")
            return
        if not interactive:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        layout = self._layout(scale=scale)
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if click:
            self._resolve_tile_click(layout=layout, mouse=mouse)

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return
        font = self._ensure_small_font()
        dt_ms_f = dt_clamped * 1000.0

        reset_w = button_width(font, self._reset_button.label, scale=scale, force_wide=self._reset_button.force_wide)
        if button_update(
            self._reset_button,
            pos=layout.reset_pos,
            width=reset_w,
            dt_ms=dt_ms_f,
            mouse=mouse,
            click=click,
        ):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._reset_state()
            return

        back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=layout.back_pos,
            width=back_w,
            dt_ms=dt_ms_f,
            mouse=mouse,
            click=click,
        ):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._begin_close_transition("open_statistics")
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(Vec2())
        _draw_screen_fade(self._state)

        font = self._ensure_small_font()
        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        layout = self._layout(scale=scale)

        assets = self._assets
        if assets is not None and assets.panel is not None:
            dst = rl.Rectangle(
                layout.panel_x,
                layout.panel_y,
                MENU_PANEL_WIDTH * scale,
                378.0 * scale,
            )
            fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
            draw_classic_menu_panel(assets.panel, dst=dst, tint=rl.WHITE, shadow=fx_detail)

        draw_small_text(font, _TITLE, Vec2(layout.title_x, layout.title_y), 1.0 * scale, rl.WHITE)
        draw_small_text(font, _SUBTITLE_1, Vec2(layout.subtitle_1_x, layout.subtitle_1_y), 1.0 * scale, rl.WHITE)
        draw_small_text(font, _SUBTITLE_2, Vec2(layout.subtitle_2_x, layout.subtitle_2_y), 1.0 * scale, rl.WHITE)

        score_text = _LABEL_SCORE % int(self._score)
        draw_small_text(
            font,
            score_text,
            Vec2(layout.score_x, layout.score_y),
            1.0 * scale,
            _to_color(1.0, 1.0, 1.0, 0.7),
        )

        board_bg = rl.Rectangle(layout.board_x, layout.board_y, layout.board_size, layout.board_size)
        rl.draw_rectangle_rec(board_bg, _to_color(0.0, 0.0, 0.0, 0.6))
        rl.draw_rectangle_lines_ex(board_bg, max(1.0, scale), rl.WHITE)

        timer_value = self._timer_ms // 100
        if timer_value > 0xC0:
            timer_value = 0xC0
        timer_h = 6.0 * scale
        timer_y = layout.board_y + (200.0 * scale)
        timer_fill_w = float(timer_value) * scale
        rl.draw_rectangle_rec(
            rl.Rectangle(layout.board_x, timer_y, timer_fill_w, timer_h),
            _to_color(0.2, 0.6, 1.0, 0.6),
        )
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(layout.board_x, timer_y, layout.board_size, timer_h),
            max(1.0, scale),
            rl.WHITE,
        )

        if self._selected_index >= 0:
            row = self._selected_index // _BOARD_SIDE
            col = self._selected_index % _BOARD_SIDE
            sel_rect = rl.Rectangle(
                layout.board_x + col * layout.tile_size + (4.0 * scale),
                layout.board_y + row * layout.tile_size + (4.0 * scale),
                24.0 * scale,
                24.0 * scale,
            )
            rl.draw_rectangle_rec(sel_rect, _to_color(0.2, 0.4, 0.7, 0.4))
            rl.draw_rectangle_lines_ex(sel_rect, max(1.0, scale), rl.WHITE)

        alien = self._alien_texture
        if alien is not None:
            frame_w = float(alien.width) / 8.0
            frame_h = float(alien.height) / 8.0
            for index, tile in enumerate(self._board):
                if tile == -3:
                    continue
                row = index // _BOARD_SIDE
                col = index % _BOARD_SIDE
                anim_frame = ((self._anim_time_ms // 50) + (tile * 2)) % 32
                src_col = anim_frame % 8
                src_row = anim_frame // 8
                src = rl.Rectangle(src_col * frame_w, src_row * frame_h, frame_w, frame_h)
                dst = rl.Rectangle(
                    layout.board_x + col * layout.tile_size,
                    layout.board_y + row * layout.tile_size,
                    layout.tile_size,
                    layout.tile_size,
                )
                if tile == 0:
                    tint = _to_color(1.0, 0.5, 0.5, 1.0)
                elif tile == 1:
                    tint = _to_color(0.5, 0.5, 1.0, 1.0)
                elif tile == 2:
                    tint = _to_color(1.0, 0.5, 1.0, 1.0)
                elif tile == 3:
                    tint = _to_color(0.5, 1.0, 1.0, 1.0)
                elif tile == 4:
                    tint = _to_color(1.0, 1.0, 0.5, 1.0)
                else:
                    tint = rl.WHITE
                rl.draw_texture_pro(alien, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)

        if self._timer_ms == 0 and math.cos(float(self._anim_time_ms) * 0.005) > 0.0:
            draw_small_text(
                font,
                _LABEL_GAME_OVER,
                Vec2(layout.game_over_x, layout.game_over_y),
                1.0 * scale,
                rl.WHITE,
            )

        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            reset_w = button_width(font, self._reset_button.label, scale=scale, force_wide=self._reset_button.force_wide)
            button_draw(
                textures,
                font,
                self._reset_button,
                pos=layout.reset_pos,
                width=reset_w,
                scale=scale,
            )

            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=layout.back_pos,
                width=back_w,
                scale=scale,
            )

        self._draw_sign()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
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
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
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
