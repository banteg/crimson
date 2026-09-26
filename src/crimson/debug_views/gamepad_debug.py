from __future__ import annotations

from grim.config import default_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext

from ..gamepad_profile import apply_pad_profile
from ..input_codes import GAMEPAD_SLOT_COUNT, gamepad_snapshot, input_begin_frame
from ..local_input import LocalInputInterpreter
from ..sim.state_types import PlayerState
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import ViewInstance, register_view

BG_COLOR = rl.Color(12, 12, 14, 255)
TEXT_COLOR = rl.Color(220, 220, 220, 255)
HINT_COLOR = rl.Color(140, 140, 140, 255)
HELD_COLOR = rl.Color(255, 200, 80, 255)
RING_COLOR = rl.Color(70, 70, 84, 255)
MOVE_COLOR = rl.Color(120, 220, 120, 255)
AIM_COLOR = rl.Color(255, 110, 110, 255)

PANEL_HEIGHT = 170.0
ARENA_RADIUS = 60.0


class GamepadDebugView:
    """Live gamepad readout plus what the auto-applied pad profile makes of it.

    Each connected pad drives a player on the pad profile through the real
    `LocalInputInterpreter`: the green arrow is the move direction handed to the
    sim, the red dot is the aim point.
    """

    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._small: SmallFontData | None = None
        self._config = default_crimson_cfg()
        for player_index in range(GAMEPAD_SLOT_COUNT):
            apply_pad_profile(self._config.controls, player_index)
        self._config.gameplay.player_count = GAMEPAD_SLOT_COUNT
        self._interpreter = LocalInputInterpreter()
        self._players = [
            PlayerState(index=idx, pos=Vec2(), aim=Vec2(0.0, -ARENA_RADIUS)) for idx in range(GAMEPAD_SLOT_COUNT)
        ]
        self._move = [Vec2() for _ in range(GAMEPAD_SLOT_COUNT)]
        self._aim = [Vec2() for _ in range(GAMEPAD_SLOT_COUNT)]
        self._fire = [False] * GAMEPAD_SLOT_COUNT

    def open(self) -> None:
        self._small = load_small_font(self._assets_root)

    def close(self) -> None:
        self._small = None

    def update(self, dt: float) -> None:
        input_begin_frame()
        for idx, player in enumerate(self._players):
            out = self._interpreter.build_player_input(
                player_index=idx,
                player=player,
                config=self._config,
                mouse_screen=Vec2(),
                mouse_world=Vec2(),
                screen_center=Vec2(),
                dt=float(dt),
            )
            player.aim = out.aim
            self._move[idx] = out.move
            self._aim[idx] = out.aim
            self._fire[idx] = bool(out.fire_down)

    def draw(self) -> None:
        rl.clear_background(BG_COLOR)
        margin = 16.0
        line_h = float(ui_line_height(self._small))
        draw_ui_text(
            self._small,
            "gamepad view: left stick moves (green), right stick aims (red), R2/RT fires",
            Vec2(margin, margin),
            color=TEXT_COLOR,
        )
        y = margin + line_h * 1.5
        for pad in range(GAMEPAD_SLOT_COUNT):
            self._draw_pad(pad, Vec2(margin, y), line_h)
            y += PANEL_HEIGHT

    def _draw_pad(self, pad: int, origin: Vec2, line_h: float) -> None:
        snapshot = gamepad_snapshot(pad)
        if snapshot is None:
            draw_ui_text(self._small, f"pad {pad}: not connected", origin, color=HINT_COLOR)
            return
        draw_ui_text(self._small, f"pad {pad}: {snapshot.name}", origin, color=TEXT_COLOR)
        y = origin.y + line_h
        for label, value in snapshot.axes:
            draw_ui_text(self._small, f"{label:<14} {value:+.3f}", Vec2(origin.x, y), color=TEXT_COLOR)
            y += line_h
        held = ", ".join(snapshot.held) if snapshot.held else "-"
        draw_ui_text(self._small, f"held: {held}", Vec2(origin.x, y), color=HELD_COLOR)

        center = Vec2(float(rl.get_screen_width()) - ARENA_RADIUS * 2.0, origin.y + PANEL_HEIGHT * 0.5)
        rl.draw_circle_lines(int(center.x), int(center.y), ARENA_RADIUS, RING_COLOR)
        move = self._move[pad]
        if move.length_sq() > 0.0:
            rl.draw_line_ex(center.to_rl(), (center + move * ARENA_RADIUS).to_rl(), 3.0, MOVE_COLOR)
        aim_point = center + self._aim[pad] * 0.4
        rl.draw_circle(int(aim_point.x), int(aim_point.y), 8.0 if self._fire[pad] else 5.0, AIM_COLOR)
        draw_ui_text(
            self._small,
            f"move {move.x:+.2f} {move.y:+.2f}",
            Vec2(center.x - ARENA_RADIUS * 3.5, center.y - line_h),
            color=MOVE_COLOR,
        )


@register_view("gamepad", "Gamepad")
def view_gamepad(ctx: ViewContext) -> ViewInstance:
    return ViewInstance(GamepadDebugView(ctx))
