from __future__ import annotations

import math

import msgspec

from grim.assets import TextureId
from grim.audio import play_sfx
from grim.fonts.small import draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..chrome import MENU_PANEL_WIDTH, ActionDispatchPolicy, BackdropPolicy, ChromeSpec, SignPolicy
from .base import _ChromePanelView

_BOARD_SIDE = 6
_BOARD_CELLS = _BOARD_SIDE * _BOARD_SIDE
_TILE_SIZE = 32.0
_BOARD_SIZE = 192.0

_TIMER_RESET_MS = 0x2580
_MATCH_TIMER_BONUS_MS = 2000

_LAYOUT_OFFSET_X = -35.0
_LAYOUT_OFFSET_X_SMALL = -85.0
_LAYOUT_POS_X = -63.0
_LAYOUT_POS_Y = -81.0
_LAYOUT_BASE_Y = 275.0
_TITLE_BASE_Y_OFFSET = 50.0
_BOARD_X_OFFSET = 220.0
_BOARD_Y_OFFSET = 40.0

_TITLE = "AlienZooKeeper"
_SUBTITLE_1 = "a puzzle game unfinished"
_SUBTITLE_2 = "..or something more?"
_LABEL_SCORE = "score: %d"
_LABEL_GAME_OVER = "Game Over"

_RESET_LABEL = "Reset"
_BACK_LABEL = "Back"


class _AzkLayout(msgspec.Struct):
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
    for row in range(_BOARD_SIDE):
        base = row * _BOARD_SIDE
        for col in range(_BOARD_SIDE - 2):
            idx = base + col
            value = board[idx]
            if value < 0:
                continue
            if board[idx + 1] == value and board[idx + 2] == value:
                return True, idx, 1

    for col in range(_BOARD_SIDE):
        for row in range(_BOARD_SIDE - 2):
            idx = row * _BOARD_SIDE + col
            value = board[idx]
            if value < 0:
                continue
            if board[idx + _BOARD_SIDE] == value and board[idx + (_BOARD_SIDE * 2)] == value:
                return True, idx, 0

    return False, 0, 0


class AlienZooKeeperView(_ChromePanelView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(),
                sign=SignPolicy(),
                dispatch=ActionDispatchPolicy(mode="pending_rearm"),
                open_sfx=None,
                close_sfx="sfx_ui_buttonclick",
            ),
        )
        self._board: list[int] = [0] * _BOARD_CELLS
        self._selected_index = -1
        self._timer_ms = _TIMER_RESET_MS
        self._anim_time_ms = 0
        self._score = 0
        self._reset_button = UiButtonState(_RESET_LABEL, force_wide=False)
        self._back_button = UiButtonState(_BACK_LABEL, force_wide=False)

    def _reset_view_state(self) -> None:
        self._reset_button = UiButtonState(_RESET_LABEL, force_wide=False)
        self._back_button = UiButtonState(_BACK_LABEL, force_wide=False)
        self._anim_time_ms = 0
        self._reset_state()

    def _layout(self, *, scale: float) -> _AzkLayout:
        layout_offset_x = _LAYOUT_OFFSET_X_SMALL if float(self.state.config.screen_width) < 641.0 else _LAYOUT_OFFSET_X
        frame = self._panel_frame(
            panel_pos=Vec2(_LAYOUT_POS_X + layout_offset_x, _LAYOUT_BASE_Y + _LAYOUT_POS_Y),
            panel_height=378.0,
            panel_offset=Vec2(),
            small_scale=0.9,
        )
        anchor_x = frame.panel_top_left.x + _BOARD_X_OFFSET
        title_base_y = frame.panel_top_left.y + _TITLE_BASE_Y_OFFSET
        board_x = anchor_x + (22.0 * scale)
        board_y = title_base_y + (_BOARD_Y_OFFSET * scale)

        tile_size = _TILE_SIZE * scale
        board_size = _BOARD_SIZE * scale

        return _AzkLayout(
            scale=scale,
            panel_x=frame.panel_top_left.x,
            panel_y=frame.panel_top_left.y,
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
            game_over_y=board_y + (74.0 * scale),
            reset_pos=Vec2(anchor_x + (38.0 * scale), title_base_y + (256.0 * scale)),
            back_pos=Vec2(anchor_x + (138.0 * scale), title_base_y + (256.0 * scale)),
        )

    def _fill_empty_cells(self) -> None:
        for index, value in enumerate(self._board):
            if value == -1:
                self._board[index] = int(self.state.rng.rand() % 5)

    def _reroll_board_no_initial_match(self) -> None:
        for _ in range(4096):
            for index in range(_BOARD_CELLS):
                self._board[index] = int(self.state.rng.rand() % 5)
            has_match, _out_idx, _out_dir = _credits_secret_match3_find(self._board)
            if not has_match:
                return
        for index in range(_BOARD_CELLS):
            self._board[index] = int(self.state.rng.rand() % 5)

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

            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_clink_01", rng=self.state.rng)

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
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_bonus", rng=self.state.rng)
            return

    def update(self, dt: float) -> None:
        self._assert_open()
        tick = self._chrome.update(dt)
        if self._chrome.chrome.closing:
            return

        if tick.dt_ms > 0:
            self._anim_time_ms += tick.dt_ms
            if self._timer_ms > 0:
                self._timer_ms -= tick.dt_ms
                if self._timer_ms <= 0:
                    self._timer_ms = 0
                    if self.state.audio is not None:
                        play_sfx(self.state.audio, "sfx_trooper_die_01", rng=self.state.rng)
            elif self._timer_ms < 0:
                self._timer_ms = 0

        self._fill_empty_cells()

        if tick.interactive and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition("open_statistics")
            return
        if not tick.interactive:
            return

        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
        layout = self._layout(scale=scale)
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if click:
            self._resolve_tile_click(layout=layout, mouse=mouse)

        resources = require_runtime_resources(self.state)
        dt_ms = min(float(dt), 0.1) * 1000.0

        reset_w = button_width(resources, self._reset_button.label, scale=scale, force_wide=self._reset_button.force_wide)
        if button_update(
            self._reset_button,
            pos=layout.reset_pos,
            width=reset_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=bool(click),
        ):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._reset_state()
            return

        back_w = button_width(resources, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=layout.back_pos,
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=bool(click),
        ):
            self._begin_close_transition("open_statistics")

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        self._chrome.draw_fade()

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
        layout = self._layout(scale=scale)

        dst = rl.Rectangle(
            layout.panel_x,
            layout.panel_y,
            MENU_PANEL_WIDTH * scale,
            378.0 * scale,
        )
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(resources.texture(TextureId.UI_MENU_PANEL), dst=dst, tint=rl.WHITE, shadow=fx_detail)

        draw_small_text(font, _TITLE, Vec2(layout.title_x, layout.title_y), rl.WHITE)
        draw_small_text(font, _SUBTITLE_1, Vec2(layout.subtitle_1_x, layout.subtitle_1_y), rl.WHITE)
        draw_small_text(font, _SUBTITLE_2, Vec2(layout.subtitle_2_x, layout.subtitle_2_y), rl.WHITE)

        score_text = _LABEL_SCORE % int(self._score)
        draw_small_text(font, score_text, Vec2(layout.score_x, layout.score_y), _to_color(1.0, 1.0, 1.0, 0.7))

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

        alien = resources.texture(TextureId.ALIEN)
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
            draw_small_text(font, _LABEL_GAME_OVER, Vec2(layout.game_over_x, layout.game_over_y), rl.WHITE)

        reset_w = button_width(resources, self._reset_button.label, scale=scale, force_wide=self._reset_button.force_wide)
        button_draw(
            resources,
            self._reset_button,
            pos=layout.reset_pos,
            width=reset_w,
            scale=scale,
        )

        back_w = button_width(resources, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        button_draw(
            resources,
            self._back_button,
            pos=layout.back_pos,
            width=back_w,
            scale=scale,
        )

        self._draw_sign()
        self._draw_cursor()
