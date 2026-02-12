from __future__ import annotations

import pyray as rl

from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.math import clamp
from grim.view import ViewContext

from ..game_world import GameWorld
from ..sim.input import PlayerInput
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

        self._ui_mouse_pos = Vec2()
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
        self._ui_mouse_pos = Vec2(
            clamp(mouse.x, 0.0, max(0.0, screen_w - 1.0)),
            clamp(mouse.y, 0.0, max(0.0, screen_h - 1.0)),
        )

    def _draw_cursor_glow(self, *, pos: Vec2) -> None:
        draw_cursor_glow(self._world.particles_texture, pos=pos)

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
        self._ui_mouse_pos = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5)
        self._cursor_pulse_time = 0.0

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        self._world.close()

    def update(self, dt: float) -> None:
        dt_frame = dt
        self._update_ui_mouse()
        self._handle_debug_input()
        self._cursor_pulse_time += dt_frame * 1.1

        aim = self._world.screen_to_world(self._ui_mouse_pos)
        if self._player is not None:
            self._player.aim = aim
            if self._force_heat:
                self._player.spread_heat = self._forced_heat

        move = Vec2(
            float(rl.is_key_down(rl.KeyboardKey.KEY_D)) - float(rl.is_key_down(rl.KeyboardKey.KEY_A)),
            float(rl.is_key_down(rl.KeyboardKey.KEY_S)) - float(rl.is_key_down(rl.KeyboardKey.KEY_W)),
        )

        dt_world = dt_frame if self._simulate else 0.0
        self._world.update(
            dt_world,
            inputs=[
                PlayerInput(
                    move=move,
                    aim=aim,
                    fire_down=False,
                    fire_pressed=False,
                    reload_pressed=False,
                )
            ],
            auto_pick_perks=False,
            perk_progression_enabled=False,
        )

        if self._player is not None and self._force_heat:
            self._player.spread_heat = self._forced_heat

    def draw(self) -> None:
        if self._draw_world:
            self._world.draw(draw_aim_indicators=self._draw_world_aim)
        else:
            rl.clear_background(rl.Color(10, 10, 12, 255))

        mouse_screen = self._ui_mouse_pos

        if self._draw_test_circle:
            cx = float(rl.get_screen_width()) * 0.5
            cy = float(rl.get_screen_height()) * 0.5
            self._world.renderer._draw_aim_circle(center=Vec2(cx, cy), radius=self._test_circle_radius)
            rl.draw_circle_lines(int(cx), int(cy), int(max(1.0, self._test_circle_radius)), rl.Color(255, 80, 80, 220))

        if self._show_cursor_glow:
            self._draw_cursor_glow(pos=mouse_screen)

        mouse_world = self._world.screen_to_world(mouse_screen)
        mouse_back = self._world.world_to_screen(mouse_world)

        if self._draw_expected_overlay and self._player is not None:
            aim_pos = self._player.aim
            dist = (aim_pos - self._player.pos).length()
            radius = max(6.0, dist * self._player.spread_heat * 0.5)
            camera, view_scale = self._world.renderer._world_params()
            scale = view_scale.avg_component()
            screen_radius = max(1.0, radius * scale)
            aim_screen = self._world.world_to_screen(aim_pos)

            rl.draw_circle_lines(
                int(aim_screen.x),
                int(aim_screen.y),
                int(max(1.0, screen_radius)),
                rl.Color(80, 220, 120, 240),
            )
            rl.draw_line(
                int(mouse_screen.x),
                int(mouse_screen.y),
                int(aim_screen.x),
                int(aim_screen.y),
                rl.Color(80, 220, 120, 200),
            )

            lines = [
                "Aim debug view",
                "SPACE simulate world update",
                "1 world  2 aim-indicators  3 expected overlay  4 cursor glow  5 test circle",
                f"H force_heat={self._force_heat}  forced_heat={self._forced_heat:.2f}  [ ] adjust",
                f"test_circle_radius={self._test_circle_radius:.0f}  -/+ adjust",
                (
                    f"mouse=({mouse_screen.x:.1f},{mouse_screen.y:.1f}) -> "
                    f"world=({mouse_world.x:.1f},{mouse_world.y:.1f}) -> "
                    f"screen=({mouse_back.x:.1f},{mouse_back.y:.1f})"
                ),
                f"player_aim_world=({aim_pos.x:.1f},{aim_pos.y:.1f})  "
                f"player_aim_screen=({aim_screen.x:.1f},{aim_screen.y:.1f})",
                f"player=({self._player.pos.x:.1f},{self._player.pos.y:.1f})  dist={dist:.1f}",
                f"spread_heat={self._player.spread_heat:.3f}  r_world={radius:.2f}  r_screen={screen_radius:.2f}",
                f"cam=({camera.x:.2f},{camera.y:.2f})  scale=({view_scale.x:.3f},{view_scale.y:.3f})  demo_mode={self._world.demo_mode_active}",
                f"bulletTrail={'yes' if self._world.bullet_trail_texture is not None else 'no'}  "
                f"particles={'yes' if self._world.particles_texture is not None else 'no'}",
            ]
            x0 = 16.0
            y0 = 16.0
            lh = ui_line_height(self._small, scale=UI_TEXT_SCALE)
            for idx, line in enumerate(lines):
                draw_ui_text(
                    self._small,
                    line,
                    Vec2(x0, y0 + lh * idx),
                    scale=UI_TEXT_SCALE,
                    color=UI_TEXT_COLOR if idx < 6 else UI_HINT_COLOR,
                )
        elif self._draw_expected_overlay and self._player is None:
            draw_ui_text(
                self._small,
                "Aim debug view: missing player",
                Vec2(16.0, 16.0),
                scale=UI_TEXT_SCALE,
                color=UI_ERROR_COLOR,
            )


@register_view("aim-debug", "Aim indicator debug")
def _create_aim_debug_view(*, ctx: ViewContext) -> AimDebugView:
    return AimDebugView(ctx)
