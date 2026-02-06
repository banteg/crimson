from __future__ import annotations

import math

import pyray as rl

from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.math import clamp
from grim.view import ViewContext

from ..game_world import GameWorld
from ..gameplay import PlayerInput
from ..paths import default_runtime_dir
from ..ui.cursor import draw_cursor_glow
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


class AimDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=WORLD_SIZE,
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            preserve_bugs=bool(ctx.preserve_bugs),
        )
        self._player = self._world.players[0] if self._world.players else None

        self.close_requested = False

        self._ui_mouse_x = 0.0
        self._ui_mouse_y = 0.0
        self._cursor_pulse_time = 0.0

        self._simulate = False
        self._draw_world = True
        self._draw_world_aim = True
        self._show_cursor_glow = False
        self._draw_expected_overlay = True
        self._draw_test_circle = True

        self._force_heat = True
        self._forced_heat = 0.18
        self._test_circle_radius = 96.0

    def _update_ui_mouse(self) -> None:
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        self._ui_mouse_x = clamp(float(mouse.x), 0.0, max(0.0, screen_w - 1.0))
        self._ui_mouse_y = clamp(float(mouse.y), 0.0, max(0.0, screen_h - 1.0))

    def _draw_cursor_glow(self, *, x: float, y: float) -> None:
        draw_cursor_glow(self._world.particles_texture, x=x, y=y)

    def _handle_debug_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._simulate = not self._simulate

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._draw_world = not self._draw_world
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._draw_world_aim = not self._draw_world_aim
        if rl.is_key_pressed(rl.KeyboardKey.KEY_THREE):
            self._draw_expected_overlay = not self._draw_expected_overlay
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._show_cursor_glow = not self._show_cursor_glow
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FIVE):
            self._draw_test_circle = not self._draw_test_circle

        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._force_heat = not self._force_heat

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._forced_heat = max(0.0, self._forced_heat - 0.02)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._forced_heat = min(0.48, self._forced_heat + 0.02)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_MINUS):
            self._test_circle_radius = max(8.0, self._test_circle_radius - 8.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EQUAL):
            self._test_circle_radius = min(512.0, self._test_circle_radius + 8.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._world.reset(seed=0xBEEF, player_count=1)
            self._player = self._world.players[0] if self._world.players else None
            self._world.update_camera(0.0)

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        runtime_dir = default_runtime_dir()
        if runtime_dir.is_dir():
            try:
                self._world.config = ensure_crimson_cfg(runtime_dir)
            except Exception:
                self._world.config = None
        else:
            self._world.config = None

        self._world.reset(seed=0xBEEF, player_count=1)
        self._player = self._world.players[0] if self._world.players else None
        self._world.open()
        self._world.update_camera(0.0)
        self._ui_mouse_x = float(rl.get_screen_width()) * 0.5
        self._ui_mouse_y = float(rl.get_screen_height()) * 0.5
        self._cursor_pulse_time = 0.0

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        self._world.close()

    def update(self, dt: float) -> None:
        dt_frame = float(dt)
        self._update_ui_mouse()
        self._handle_debug_input()
        self._cursor_pulse_time += dt_frame * 1.1

        aim_x, aim_y = self._world.screen_to_world(self._ui_mouse_x, self._ui_mouse_y)
        if self._player is not None:
            self._player.aim_x = float(aim_x)
            self._player.aim_y = float(aim_y)
            if self._force_heat:
                self._player.spread_heat = float(self._forced_heat)

        move_x = 0.0
        move_y = 0.0
        if rl.is_key_down(rl.KeyboardKey.KEY_A):
            move_x -= 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_D):
            move_x += 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_W):
            move_y -= 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_S):
            move_y += 1.0

        dt_world = dt_frame if self._simulate else 0.0
        self._world.update(
            dt_world,
            inputs=[
                PlayerInput(
                    move_x=move_x,
                    move_y=move_y,
                    aim_x=float(aim_x),
                    aim_y=float(aim_y),
                    fire_down=False,
                    fire_pressed=False,
                    reload_pressed=False,
                )
            ],
            auto_pick_perks=False,
            perk_progression_enabled=False,
        )

        if self._player is not None and self._force_heat:
            self._player.spread_heat = float(self._forced_heat)

    def draw(self) -> None:
        if self._draw_world:
            self._world.draw(draw_aim_indicators=self._draw_world_aim)
        else:
            rl.clear_background(rl.Color(10, 10, 12, 255))

        mouse_x = float(self._ui_mouse_x)
        mouse_y = float(self._ui_mouse_y)

        if self._draw_test_circle:
            cx = float(rl.get_screen_width()) * 0.5
            cy = float(rl.get_screen_height()) * 0.5
            self._world._draw_aim_circle(x=cx, y=cy, radius=float(self._test_circle_radius))
            rl.draw_circle_lines(int(cx), int(cy), int(max(1.0, self._test_circle_radius)), rl.Color(255, 80, 80, 220))

        if self._show_cursor_glow:
            self._draw_cursor_glow(x=mouse_x, y=mouse_y)

        mouse_world_x, mouse_world_y = self._world.screen_to_world(mouse_x, mouse_y)
        mouse_back_x, mouse_back_y = self._world.world_to_screen(float(mouse_world_x), float(mouse_world_y))

        if self._draw_expected_overlay and self._player is not None:
            dist = math.hypot(float(self._player.aim_x) - float(self._player.pos.x), float(self._player.aim_y) - float(self._player.pos.y))
            radius = max(6.0, dist * float(self._player.spread_heat) * 0.5)
            cam_x, cam_y, scale_x, scale_y = self._world._world_params()
            scale = (scale_x + scale_y) * 0.5
            screen_radius = max(1.0, radius * scale)
            aim_screen_x, aim_screen_y = self._world.world_to_screen(float(self._player.aim_x), float(self._player.aim_y))

            rl.draw_circle_lines(
                int(aim_screen_x),
                int(aim_screen_y),
                int(max(1.0, screen_radius)),
                rl.Color(80, 220, 120, 240),
            )
            rl.draw_line(
                int(mouse_x),
                int(mouse_y),
                int(aim_screen_x),
                int(aim_screen_y),
                rl.Color(80, 220, 120, 200),
            )

            lines = [
                "Aim debug view",
                "SPACE simulate world update",
                "1 world  2 aim-indicators  3 expected overlay  4 cursor glow  5 test circle",
                f"H force_heat={self._force_heat}  forced_heat={self._forced_heat:.2f}  [ ] adjust",
                f"test_circle_radius={self._test_circle_radius:.0f}  -/+ adjust",
                (
                    f"mouse=({mouse_x:.1f},{mouse_y:.1f}) -> "
                    f"world=({mouse_world_x:.1f},{mouse_world_y:.1f}) -> "
                    f"screen=({mouse_back_x:.1f},{mouse_back_y:.1f})"
                ),
                f"player_aim_world=({float(self._player.aim_x):.1f},{float(self._player.aim_y):.1f})  "
                f"player_aim_screen=({aim_screen_x:.1f},{aim_screen_y:.1f})",
                f"player=({float(self._player.pos.x):.1f},{float(self._player.pos.y):.1f})  dist={dist:.1f}",
                f"spread_heat={float(self._player.spread_heat):.3f}  r_world={radius:.2f}  r_screen={screen_radius:.2f}",
                f"cam=({cam_x:.2f},{cam_y:.2f})  scale=({scale_x:.3f},{scale_y:.3f})  demo_mode={self._world.demo_mode_active}",
                f"bulletTrail={'yes' if self._world.bullet_trail_texture is not None else 'no'}  "
                f"particles={'yes' if self._world.particles_texture is not None else 'no'}",
            ]
            x0 = 16.0
            y0 = 16.0
            lh = float(ui_line_height(self._small, scale=UI_TEXT_SCALE))
            for idx, line in enumerate(lines):
                draw_ui_text(
                    self._small,
                    line,
                    x0,
                    y0 + lh * float(idx),
                    scale=UI_TEXT_SCALE,
                    color=UI_TEXT_COLOR if idx < 6 else UI_HINT_COLOR,
                )
        elif self._draw_expected_overlay and self._player is None:
            draw_ui_text(self._small, "Aim debug view: missing player", 16.0, 16.0, scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)


@register_view("aim-debug", "Aim indicator debug")
def _create_aim_debug_view(*, ctx: ViewContext) -> AimDebugView:
    return AimDebugView(ctx)
