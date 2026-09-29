from __future__ import annotations

import msgspec

from grim.color import grim_color
from grim.geom import Vec2
from grim.raylib_api import rl

UI_FOCUS_SLOTS = 32
UI_FOCUS_TIMER_MS = 1000


def _slots() -> list[object | None]:
    return [None] * UI_FOCUS_SLOTS


class UiFocus(msgspec.Struct):
    """Native keyboard focus: `ui_focus_candidates`, `ui_focus_count`, `ui_focus_index`, `ui_focus_timer_ms`.

    Every focusable widget registers itself each frame (`ui_focus_update`) in update order, so Tab walks the
    widgets in the order the screen updates them. Native starts a frame from its first registration (the
    `ui_focus_frame_marker_ms` check); the port's game loop calls `begin_frame` once per frame instead, which
    also samples this frame's navigation keys for the widgets.
    """

    candidates: list[object | None] = msgspec.field(default_factory=_slots)
    count: int = 0
    index: int = 0
    timer_ms: int = 0
    # Native `ui_focus_input_locked`: Tab and checkbox Enter are ignored while a rebind waits for its input.
    input_locked: bool = False
    # The next registration starts the candidate list over (native `ui_focus_frame_marker_ms != game_time_ms`).
    restart: bool = True
    # This frame's navigation presses.
    enter: bool = False
    escape: bool = False
    up: bool = False
    down: bool = False
    left: bool = False
    right: bool = False
    page_up: bool = False
    page_down: bool = False

    def begin_frame(self, dt_ms: int) -> None:
        """`ui_focus_update`'s once-per-frame half: decay the marker timer, then Tab / Shift+Tab."""
        self.timer_ms = max(0, self.timer_ms - dt_ms)
        self.enter = rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER)
        self.escape = rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE)
        self.up = rl.is_key_pressed(rl.KeyboardKey.KEY_UP)
        self.down = rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN)
        self.left = rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT)
        self.right = rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT)
        self.page_up = rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP)
        self.page_down = rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN)
        step = 0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            shift = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
            step = -1 if shift else 1
        if step and not self.input_locked:
            self.index += step
            self.timer_ms = UI_FOCUS_TIMER_MS
        # Wraps against the previous frame's candidate count.
        if self.index < 0:
            self.index = self.count - 1
        if self.index > self.count - 1:
            self.index = 0
        self.restart = True

    def update(self, widget: object) -> bool:
        """`ui_focus_update`: register `widget` as the next candidate; True when it holds the focus."""
        focused = 0 <= self.index < UI_FOCUS_SLOTS and self.candidates[self.index] is widget
        if self.restart:
            self.restart = False
            slot = 0
        else:
            slot = min(self.count, UI_FOCUS_SLOTS - 1)
        self.candidates[slot] = widget
        self.count = slot + 1
        return focused

    def set(self, widget: object, *, reset_timer: bool = False) -> None:
        """`ui_focus_set`: move the focus to a registered widget; hovering passes `reset_timer=False`."""
        if 0 <= self.index < UI_FOCUS_SLOTS and self.candidates[self.index] is widget:
            return
        if reset_timer:
            self.timer_ms = UI_FOCUS_TIMER_MS
        for index in range(self.count):
            if self.candidates[index] is widget:
                self.index = index
                return

    def draw(self, pos: Vec2) -> None:
        """`ui_focus_draw`: the 6x6 marker at `pos + (0, 4)`, fading out with the timer.

        Widgets pass their position less 16px. A spent timer draws a fully transparent quad natively.
        """
        if self.timer_ms <= 0:
            return
        color = grim_color(0.8, 0.8, 0.6, float(self.timer_ms) * (0.8 / UI_FOCUS_TIMER_MS))
        rl.draw_rectangle_rec(rl.Rectangle(pos.x, pos.y + 4.0, 6.0, 6.0), color)


class UiFocusTarget(msgspec.Struct):
    """A port-only focus stop: a keyboard path to a mouse-only native control (credits lines, the secret's board)."""

    focused: bool = False


__all__ = ["UI_FOCUS_SLOTS", "UI_FOCUS_TIMER_MS", "UiFocus", "UiFocusTarget"]
