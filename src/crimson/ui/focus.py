from __future__ import annotations

import math

import msgspec

from grim import canvas
from grim.color import grim_color
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2

from ..input_codes import PadCode, pad_nav_down, pad_nav_pressed, pad_nav_stick

UI_FOCUS_SLOTS = 32
UI_FOCUS_TIMER_MS = 1000

_STICK_THRESHOLD = 0.5
_STICK_REPEAT_DELAY_MS = 400
_STICK_REPEAT_MS = 120
_STICK_UP, _STICK_DOWN, _STICK_LEFT, _STICK_RIGHT = 1, 2, 3, 4
# A pad step goes to the nearest widget at least this far that way, sideways distance weighing half; left and right
# look within 56 degrees of straight (sideways at most 1.5 times along).
_STEP_MIN = 4.0
_STEP_ACROSS_WEIGHT = 0.5
_STEP_SIDEWAYS_CONE = 1.5
# The right stick steers the cursor past this tilt, at sensitivity x this many points a second at full tilt.
_CURSOR_DEAD_ZONE = 0.2
_CURSOR_SPEED = 2160.0


def _slots() -> list[object | None]:
    return [None] * UI_FOCUS_SLOTS


def _places() -> list[Vec2]:
    return [Vec2()] * UI_FOCUS_SLOTS


class UiFocus(msgspec.Struct):
    """Native keyboard focus: `ui_focus_candidates`, `ui_focus_count`, `ui_focus_index`, `ui_focus_timer_ms`.

    Every focusable widget registers itself each frame (`ui_focus_update`) in update order, with where it draws,
    so Tab walks the widgets in the order the screen updates them. Native starts a frame from its first
    registration (the `ui_focus_frame_marker_ms` check); the port's game loop calls `begin_frame` once per frame
    instead, which also samples this frame's navigation keys for the widgets, pads included, as the recovered
    client's pad does (crimson-core/game/pad.cpp):

    - D-pad or left stick steps the focus to the nearest widget that way (`_step`); up/down wrap as Tab does, and
      are Up/Down instead while the focused widget holds them (an open list, a scroll list or board that can still
      move that way);
    - left/right with nothing that way, or while the focused widget holds them (a slider), are the arrow keys;
    - A is Enter, B is Escape, and LB/RB are PgUp/PgDn;
    - in menus the right stick steers the cursor, which stays where it leaves it until the mouse moves, and A
      clicks there until the focus steps again.
    """

    candidates: list[object | None] = msgspec.field(default_factory=_slots)
    # Where each candidate draws, its top left corner (a menu item's clickable bounds, left middle).
    places: list[Vec2] = msgspec.field(default_factory=_places)
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
    # The focused widget takes the pad's up/down or left/right as arrow keys next frame instead of moving the focus.
    hold_up: bool = False
    hold_down: bool = False
    hold_sideways: bool = False
    # The left stick's held direction (see `_STICK_*`) and the ms until it repeats.
    stick: int = 0
    stick_repeat_ms: int = 0
    # Port: once a pad navigates, the marker and the focused button's highlight stay up instead of fading
    # a second after each move, so a pad player always sees the focus. Moving the mouse returns to native, and
    # while the pad leads, hovering leaves the focus where the pad put it.
    pad_active: bool = False
    # The right stick must let go before it steers the cursor after gameplay, where it aimed.
    aim_held: bool = False
    # The right stick moved the cursor since the pad last stepped the focus: A clicks where it points.
    pointing: bool = False
    # A holds the mouse button it pressed while pointing.
    clicking: bool = False

    def begin_frame(self, dt_ms: int, *, stick: bool = True, sensitivity: float = 0.5) -> None:
        """`ui_focus_update`'s once-per-frame half: decay the marker timer, then Tab / Shift+Tab and the pad.

        `stick` is off while gameplay runs, where the sticks move and aim the player; `sensitivity` is the cursor's
        (crimson.cfg's mouse sensitivity).
        """
        stick_press = self._stick_press(dt_ms, enabled=stick)
        pad_up = pad_nav_pressed(PadCode.DPAD_UP) or stick_press == _STICK_UP
        pad_down = pad_nav_pressed(PadCode.DPAD_DOWN) or stick_press == _STICK_DOWN
        pad_left = pad_nav_pressed(PadCode.DPAD_LEFT) or stick_press == _STICK_LEFT
        pad_right = pad_nav_pressed(PadCode.DPAD_RIGHT) or stick_press == _STICK_RIGHT
        pad_accept = pad_nav_pressed(PadCode.FACE_DOWN)
        pad_escape = pad_nav_pressed(PadCode.FACE_RIGHT)
        pad_page_up = pad_nav_pressed(PadCode.L1)
        pad_page_down = pad_nav_pressed(PadCode.R1)
        mouse = canvas.mouse_delta()
        if mouse.x or mouse.y:
            canvas.steer_mouse(None)
            self.pointing = False
        steered = self._steer_cursor(dt_ms, enabled=stick, sensitivity=sensitivity)
        if pad_up or pad_down or pad_left or pad_right:
            self.pointing = False
        self.clicking = stick and pad_nav_down(PadCode.FACE_DOWN) and (self.clicking or (pad_accept and self.pointing))
        canvas.press_mouse(self.clicking)
        pad_enter = pad_accept and not self.clicking
        if pad_up or pad_down or pad_left or pad_right or pad_accept or pad_escape or pad_page_up or pad_page_down:
            self.pad_active = True
        elif mouse.x or mouse.y or steered:
            self.pad_active = False
        self.timer_ms = UI_FOCUS_TIMER_MS if self.pad_active else max(0, self.timer_ms - dt_ms)
        self.enter = (
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER) or pad_enter
        )
        self.escape = rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_escape
        self.up = rl.is_key_pressed(rl.KeyboardKey.KEY_UP) or (pad_up and self.hold_up)
        self.down = rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN) or (pad_down and self.hold_down)
        self.left = rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT) or (
            pad_left and (self.hold_sideways or not self._pad_step(-1.0, 0.0))
        )
        self.right = rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT) or (
            pad_right and (self.hold_sideways or not self._pad_step(1.0, 0.0))
        )
        self.page_up = rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP) or pad_page_up
        self.page_down = rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN) or pad_page_down
        if pad_up and not self.hold_up:
            self._pad_step(0.0, -1.0)
        if pad_down and not self.hold_down:
            self._pad_step(0.0, 1.0)
        self.hold_up = self.hold_down = self.hold_sideways = False
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

    def screen_changed(self) -> None:
        """Port: a newly shown screen starts on its first widget, not on the previous screen's focus index."""
        self.index = 0
        self.restart = True

    def hold(self, *, up: bool = False, down: bool = False, sideways: bool = False) -> None:
        """A focused widget that moves with the arrow keys takes the pad's directions while it can move that way."""
        self.hold_up = up
        self.hold_down = down
        self.hold_sideways = sideways

    def _pad_step(self, dx: float, dy: float) -> bool:
        """A pad step of the focus that way, unless a rebind locks it; True when it moved."""
        if self.input_locked or not self._step(dx, dy):
            return False
        self.timer_ms = UI_FOCUS_TIMER_MS
        return True

    def _step(self, dx: float, dy: float) -> bool:
        """Move the focus to the nearest candidate that way from where the focused one draws, by the last frame's
        registrations.

        Sideways distance weighs half, so the next row's widget is reached however far across it sits. Left and right
        look within the cone and report nothing there, which leaves the arrow keys to page the quest list and the
        high scores; up and down wrap as Tab does, to the first or last widget as the screen shows them.
        """
        count = self.count
        if not count:
            return False
        nearest = None
        if 0 <= self.index < count:
            origin = self.places[self.index]
            best = math.inf
            for slot in range(count):
                offset = self.places[slot] - origin
                along = offset.x * dx + offset.y * dy
                across = abs(offset.x * dy - offset.y * dx)
                score = along + across * _STEP_ACROSS_WEIGHT
                if along > _STEP_MIN and (not dx or across <= along * _STEP_SIDEWAYS_CONE) and score < best:
                    best = score
                    nearest = slot
        if nearest is None:
            if dx:
                return False
            # Row by row, top first, then left to right.
            def rank(slot: int) -> tuple[float, float]:
                return (math.floor(self.places[slot].y / 8.0), self.places[slot].x)

            nearest = (min if dy > 0.0 else max)(range(count), key=rank)
        self.index = nearest
        return True

    def _steer_cursor(self, dt_ms: int, *, enabled: bool, sensitivity: float) -> bool:
        """The right stick past its dead zone moves the cursor, quadratically: fine near the centre, and across the
        screen in about a second at full tilt and the default sensitivity. True when it moved.

        While disabled (gameplay) the window's cursor leads again, and a push held over waits for a release.
        """
        x, y = pad_nav_stick(PadCode.RIGHT_STICK_X, PadCode.RIGHT_STICK_Y)
        tilt = math.hypot(x, y)
        if not enabled:
            self.aim_held = True
            self.pointing = False
            canvas.steer_mouse(None)
            return False
        self.aim_held = self.aim_held and tilt > _CURSOR_DEAD_ZONE
        if tilt <= _CURSOR_DEAD_ZONE or self.aim_held:
            return False
        scale = sensitivity * _CURSOR_SPEED * min(tilt, 1.0) * dt_ms / 1000.0
        pos = canvas.mouse_position()
        canvas.steer_mouse(
            rl_vector2(
                min(max(pos.x + x * scale, 0.0), float(canvas.width())),
                min(max(pos.y + y * scale, 0.0), float(canvas.height())),
            ),
        )
        self.pointing = True
        return True

    def _stick_press(self, dt_ms: int, *, enabled: bool) -> int:
        """The left stick as a D-pad: a press when pushed past half travel, repeating while held.

        While disabled it only tracks the stick, so a push held over from gameplay steps no sooner than a repeat.
        """
        x, y = pad_nav_stick()
        if max(abs(x), abs(y)) < _STICK_THRESHOLD:
            direction = 0
        elif abs(y) >= abs(x):
            direction = _STICK_DOWN if y > 0.0 else _STICK_UP
        else:
            direction = _STICK_RIGHT if x > 0.0 else _STICK_LEFT
        if not enabled:
            self.stick = direction
            self.stick_repeat_ms = _STICK_REPEAT_DELAY_MS
            return 0
        if direction != self.stick:
            self.stick = direction
            self.stick_repeat_ms = _STICK_REPEAT_DELAY_MS
            return direction
        if direction:
            self.stick_repeat_ms -= dt_ms
            if self.stick_repeat_ms <= 0:
                self.stick_repeat_ms = _STICK_REPEAT_MS
                return direction
        return 0

    def update(self, widget: object, place: Vec2) -> bool:
        """`ui_focus_update`: register `widget`, which draws at `place`, as the next candidate; True when it holds
        the focus."""
        focused = 0 <= self.index < UI_FOCUS_SLOTS and self.candidates[self.index] is widget
        if self.restart:
            self.restart = False
            slot = 0
        else:
            slot = min(self.count, UI_FOCUS_SLOTS - 1)
        self.candidates[slot] = widget
        self.places[slot] = place
        self.count = slot + 1
        if focused:
            # Port: the focus stays on its widget when the list above it changes length (ticking Ranked drops
            # three Play Game modes), rather than on a slot that now holds another widget or none.
            self.index = slot
        return focused

    def set(self, widget: object, *, reset_timer: bool = False) -> None:
        """`ui_focus_set`: move the focus to a registered widget; hovering passes `reset_timer=False`, and takes the
        focus only while the mouse leads."""
        if 0 <= self.index < UI_FOCUS_SLOTS and self.candidates[self.index] is widget:
            return
        if self.pad_active and not reset_timer:
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
        rl.draw_rectangle_rec(rl_rectangle(pos.x, pos.y + 4.0, 6.0, 6.0), color)


class UiFocusTarget(msgspec.Struct):
    """A port-only focus stop: a keyboard path to a mouse-only native control (credits lines, the secret's board)."""

    focused: bool = False


__all__ = ["UI_FOCUS_SLOTS", "UI_FOCUS_TIMER_MS", "UiFocus", "UiFocusTarget"]
