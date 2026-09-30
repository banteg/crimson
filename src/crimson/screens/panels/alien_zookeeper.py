from __future__ import annotations

import math

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.actions import Route
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.menu_chrome import draw_menu_sign
from grim import canvas
from grim.assets import TextureId
from grim.audio import play_sfx
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import (
    draw_small_text,
)
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game.types import GameState
from ...rng_caller_static import RngCallerStatic
from ...ui.focus import UiFocusTarget
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.perk_menu import UiButtonState, button_draw, button_update
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen

_BOARD_SIDE = 6
_BOARD_CELLS = _BOARD_SIDE * _BOARD_SIDE
_TILE_SIZE = 32.0
_BOARD_SIZE = 192.0

_TIMER_RESET_MS = 0x2580
_MATCH_TIMER_BONUS_MS = 2000

# `credits_secret_alien_zookeeper_update` lays out from `ui_element_slot_09`'s panel top-left.
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


class _AzkLayout(msgspec.Struct):
    panel: Rect
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


class AlienZooKeeperView(MenuScreen):
    game_state = GameStateId.CREDITS_SECRET

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._board: list[int] = [0] * _BOARD_CELLS
        self._selected_index = -1
        self._timer_ms = 0
        self._anim_time_ms = 0
        self._score = 0

        self._reset_button = UiButtonState(_RESET_LABEL, force_wide=False)
        self._back_button = UiButtonState(_BACK_LABEL, force_wide=False)
        # The port's keyboard path to the mouse-only board: focused, the arrows move a cell cursor and Enter clicks it.
        self._board_focus = UiFocusTarget()
        self._cursor_index = 0

    def open(self) -> None:
        super().open()
        self._reset_button = UiButtonState(_RESET_LABEL, force_wide=False)
        self._back_button = UiButtonState(_BACK_LABEL, force_wide=False)

        # Native puzzle state is process-lifetime storage. The initial board
        # and timer are zeroed, and leaving/re-entering the screen does not
        # reroll or restart it; only the Reset button calls _reset_state().

    def _layout(self) -> _AzkLayout:
        panel = ui_panel_rect(9, self.state.ui.timeline_ms, self.state.config.display.width)
        anchor_x = panel.left + _BOARD_X_OFFSET
        title_base_y = panel.top + _TITLE_BASE_Y_OFFSET
        board_x = anchor_x + 22.0
        board_y = title_base_y + _BOARD_Y_OFFSET
        return _AzkLayout(
            panel=panel,
            board_x=board_x,
            board_y=board_y,
            tile_size=_TILE_SIZE,
            board_size=_BOARD_SIZE,
            title_x=anchor_x,
            title_y=title_base_y - 14.0,
            subtitle_1_x=anchor_x + 12.0,
            subtitle_1_y=title_base_y + 10.0,
            subtitle_2_x=anchor_x + 18.0,
            subtitle_2_y=title_base_y + 23.0,
            score_x=board_x + 124.0,
            score_y=board_y - 16.0,
            game_over_x=board_x + 38.0,
            game_over_y=board_y + 74.0,  # 96 - 22
            reset_pos=Vec2(anchor_x + 38.0, title_base_y + 256.0),
            back_pos=Vec2(anchor_x + 138.0, title_base_y + 256.0),
        )

    def _fill_empty_cells(self) -> None:
        for i, value in enumerate(self._board):
            if value == -1:
                self._board[i] = int(
                    self.state.rng.rand_tagged(RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_FILL_EMPTY) % 5,
                )

    def _reroll_board_no_initial_match(self) -> None:
        while True:
            for i in range(_BOARD_CELLS):
                self._board[i] = int(
                    self.state.rng.rand_tagged(RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_REROLL_FILL) % 5,
                )
            has_match, _out_idx, _out_dir = _credits_secret_match3_find(self._board)
            if not has_match:
                return

    def _reset_state(self) -> None:
        self._reroll_board_no_initial_match()
        self._selected_index = -1
        self._score = 0
        self._timer_ms = _TIMER_RESET_MS

    def _resolve_tile_click(self, *, layout: _AzkLayout, mouse: rl.Vector2) -> None:
        for index in range(_BOARD_CELLS):
            row = index // _BOARD_SIDE
            col = index % _BOARD_SIDE
            x = layout.board_x + col * layout.tile_size
            y = layout.board_y + row * layout.tile_size
            if _mouse_inside_rect(mouse, x=x, y=y, w=layout.tile_size, h=layout.tile_size):
                self._click_tile(index)
                return

    def _update_board_focus(self) -> None:
        focus = self.state.focus
        self._board_focus.focused = focus.update(self._board_focus)
        if not self._board_focus.focused:
            return
        row, col = divmod(self._cursor_index, _BOARD_SIDE)
        col = max(0, min(_BOARD_SIDE - 1, col + int(focus.right) - int(focus.left)))
        row = max(0, min(_BOARD_SIDE - 1, row + int(focus.down) - int(focus.up)))
        self._cursor_index = row * _BOARD_SIDE + col
        # The pad's up/down walk the rows until the board's edge, then move the focus on.
        focus.hold(up=row > 0, down=row < _BOARD_SIDE - 1)
        if focus.enter:
            self._click_tile(self._cursor_index)

    def _click_tile(self, index: int) -> None:
        if self._timer_ms <= 0:
            return
        if self._board[index] == -3:
            return

        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_CLINK_01)

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
            play_sfx(self.state.audio, SfxId.UI_BONUS)

    def update(self, dt: float) -> None:
        if not self._advance(dt):
            return
        dt_clamped = min(float(dt), 0.1)
        dt_ms = int(dt_clamped * 1000.0)

        if dt_ms > 0:
            self._anim_time_ms += dt_ms
            if self._timer_ms > 0:
                self._timer_ms -= dt_ms
                if self._timer_ms <= 0:
                    self._timer_ms = 0
                    if self.state.audio is not None:
                        play_sfx(self.state.audio, SfxId.TROOPER_DIE_01)
            elif self._timer_ms < 0:
                self._timer_ms = 0

        self._fill_empty_cells()

        interactive = self.state.ui.opened
        if self.state.focus.escape and interactive:
            self._begin_close_transition(Route.BACK)
            return
        if not interactive:
            return

        layout = self._layout()
        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if click:
            self._resolve_tile_click(layout=layout, mouse=mouse)
        # Focus order: the port's board stop, then Reset and Back.
        self._update_board_focus()

        resources = require_runtime_resources(self.state)
        dt_ms_f = dt_clamped * 1000.0

        if button_update(
            resources,
            self._reset_button,
            focus=self.state.focus,
            pos=layout.reset_pos,
            dt_ms=dt_ms_f,
            mouse=mouse,
            click=click,
        ):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._reset_state()
            return

        if button_update(
            resources,
            self._back_button,
            focus=self.state.focus,
            pos=layout.back_pos,
            dt_ms=dt_ms_f,
            mouse=mouse,
            click=click,
        ):
            self._begin_close_transition(Route.BACK)
            return

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        layout = self._layout()

        draw_ui_panel(resources, 9, layout.panel, shadow=self.state.config.display.shadows_enabled)

        draw_small_text(font, _TITLE, Vec2(layout.title_x, layout.title_y), rl.WHITE)
        draw_small_text(font, _SUBTITLE_1, Vec2(layout.subtitle_1_x, layout.subtitle_1_y), rl.WHITE)
        draw_small_text(font, _SUBTITLE_2, Vec2(layout.subtitle_2_x, layout.subtitle_2_y), rl.WHITE)

        score_text = _LABEL_SCORE % int(self._score)
        draw_small_text(font, score_text, Vec2(layout.score_x, layout.score_y), _to_color(1.0, 1.0, 1.0, 0.7))

        board_bg = rl.Rectangle(layout.board_x, layout.board_y, layout.board_size, layout.board_size)
        rl.draw_rectangle_rec(board_bg, _to_color(0.0, 0.0, 0.0, 0.6))
        grim_draw_rect_outline(Vec2(board_bg.x, board_bg.y), board_bg.width, board_bg.height, rl.WHITE)

        timer_value = self._timer_ms // 100
        if timer_value > 0xC0:
            timer_value = 0xC0
        timer_h = 6.0
        timer_y = layout.board_y + 200.0
        timer_fill_w = float(timer_value)
        rl.draw_rectangle_rec(
            rl.Rectangle(layout.board_x, timer_y, timer_fill_w, timer_h),
            _to_color(0.2, 0.6, 1.0, 0.6),
        )
        grim_draw_rect_outline(Vec2(layout.board_x, timer_y), layout.board_size, timer_h, rl.WHITE)

        if self._selected_index >= 0:
            row = self._selected_index // _BOARD_SIDE
            col = self._selected_index % _BOARD_SIDE
            sel_rect = rl.Rectangle(
                layout.board_x + col * layout.tile_size + 4.0,
                layout.board_y + row * layout.tile_size + 4.0,
                24.0,
                24.0,
            )
            rl.draw_rectangle_rec(sel_rect, _to_color(0.2, 0.4, 0.7, 0.4))
            grim_draw_rect_outline(Vec2(sel_rect.x, sel_rect.y), sel_rect.width, sel_rect.height, rl.WHITE)

        if self._board_focus.focused:
            row, col = divmod(self._cursor_index, _BOARD_SIDE)
            cursor = rl.Rectangle(
                layout.board_x + col * layout.tile_size, layout.board_y + row * layout.tile_size, layout.tile_size, layout.tile_size,
            )
            grim_draw_rect_outline(Vec2(cursor.x, cursor.y), cursor.width, cursor.height, _to_color(0.8, 0.8, 0.6, 0.8))
            self.state.focus.draw(Vec2(layout.board_x - 16.0, cursor.y))

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

        button_draw(
            resources,
            self._reset_button,
            focus=self.state.focus,
            pos=layout.reset_pos,
        )

        button_draw(
            resources,
            self._back_button,
            focus=self.state.focus,
            pos=layout.back_pos,
        )

        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=True,
            timeline_ms=self.state.ui.timeline_ms,
        )
        ui_cursor_render(resources, dt=self.state.frame_dt)
