from __future__ import annotations

from dataclasses import dataclass
import math

import pyray as rl

from grim.assets import resolve_asset_path
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.view import View, ViewContext
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view


WORLD_SIZE = 1024.0
WINDOW_W = 640
WINDOW_H = 480
GRID_STEP = 64.0

SPRITE_GRID = 8
SPRITE_PAD_PX = 2.0
LEG_FRAME_COUNT = 15

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(slots=True)
class PlayerSpriteAssets:
    trooper: rl.Texture


class PlayerSpriteDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._assets: PlayerSpriteAssets | None = None

        self._player_pos = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)
        self._player_size = 50.0
        self._move_phase = 0.0
        self._move_heading = 0.0
        self._aim_heading = 0.0
        self._muzzle_flash = 0.0

        self._leg_base = 0
        self._torso_base = 16
        self._frame_count = LEG_FRAME_COUNT
        self._show_grid = True
        self._show_shadow = True
        self._use_torso_offset = True

    def _frame_src(self, texture: rl.Texture, frame_index: int) -> rl.Rectangle:
        cell = float(texture.width) / float(SPRITE_GRID)
        pad = SPRITE_PAD_PX
        frame = max(0, int(frame_index)) % (SPRITE_GRID * SPRITE_GRID)
        col = frame % SPRITE_GRID
        row = frame // SPRITE_GRID
        u0 = col * cell + pad
        v0 = row * cell + pad
        size = cell - pad * 2.0
        return rl.Rectangle(u0, v0, size, size)

    def _draw_sprite(
        self,
        texture: rl.Texture,
        frame_index: int,
        *,
        pos: Vec2,
        size: float,
        rotation_rad: float,
        tint: rl.Color,
        shadow: bool,
        offset: Vec2 = Vec2(),
    ) -> None:
        src = self._frame_src(texture, frame_index)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        rotation_deg = float(rotation_rad * 57.29577951308232)
        draw_pos = pos + offset

        if shadow:
            shadow_color = rl.Color(0, 0, 0, 90)
            dst = rl.Rectangle(draw_pos.x + 1.0, draw_pos.y + 1.0, size, size)
            rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, shadow_color)

        dst = rl.Rectangle(draw_pos.x, draw_pos.y, size, size)
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    def open(self) -> None:
        rl.set_window_size(WINDOW_W, WINDOW_H)
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        trooper_path = resolve_asset_path(self._assets_root, "game/trooper.png")
        if trooper_path is None:
            self._missing_assets.append("game/trooper.png")
        if self._missing_assets:
            raise FileNotFoundError("Missing assets: " + ", ".join(self._missing_assets))
        trooper = rl.load_texture(str(trooper_path))
        self._assets = PlayerSpriteAssets(trooper=trooper)

    def close(self) -> None:
        if self._assets is not None:
            rl.unload_texture(self._assets.trooper)
            self._assets = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F1):
            self._show_grid = not self._show_grid
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
            self._show_shadow = not self._show_shadow
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
            self._use_torso_offset = not self._use_torso_offset

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._torso_base = max(0, self._torso_base - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._torso_base = min(63, self._torso_base + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SEMICOLON):
            self._leg_base = max(0, self._leg_base - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_APOSTROPHE):
            self._leg_base = min(63, self._leg_base + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_COMMA):
            self._frame_count = max(1, self._frame_count - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD):
            self._frame_count = min(64, self._frame_count + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._player_pos = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)
            self._move_phase = 0.0
            self._move_heading = 0.0

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

        move = Vec2(move_x, move_y)
        moving = move.length_sq() > 0.0
        if moving:
            move = move.normalized()
            speed = 120.0
            if rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT):
                speed *= 2.0
            self._player_pos = (self._player_pos + move * speed * dt).clamp_rect(0.0, 0.0, WORLD_SIZE, WORLD_SIZE)
            self._move_heading = move.to_heading()

            move_speed = 2.0
            self._move_phase += dt * move_speed * 19.0
            while self._move_phase > 14.0:
                self._move_phase -= 14.0

        camera = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5) - self._player_pos
        mouse = rl.get_mouse_position()
        aim_world = Vec2.from_xy(mouse) - camera
        aim_delta = aim_world - self._player_pos
        if aim_delta.length_sq() > 1e-6:
            self._aim_heading = aim_delta.to_heading()

        if rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._muzzle_flash = 0.8
        else:
            self._muzzle_flash = max(0.0, self._muzzle_flash - dt * 2.5)

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))
        if self._assets is None:
            draw_ui_text(
                self._small, "Trooper sprite not loaded.", Vec2(16, 16), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR
            )
            return

        camera = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5) - self._player_pos

        if self._show_grid:
            grid_major = rl.Color(70, 80, 95, 180)
            grid_minor = rl.Color(40, 50, 65, 140)
            for i in range(0, int(WORLD_SIZE) + 1, int(GRID_STEP)):
                color = grid_major if i % 256 == 0 else grid_minor
                vertical_start = Vec2(float(i) + camera.x, camera.y)
                vertical_end = Vec2(vertical_start.x, WORLD_SIZE + camera.y)
                rl.draw_line(
                    int(vertical_start.x),
                    int(vertical_start.y),
                    int(vertical_end.x),
                    int(vertical_end.y),
                    color,
                )
                horizontal_start = Vec2(camera.x, float(i) + camera.y)
                horizontal_end = Vec2(WORLD_SIZE + camera.x, horizontal_start.y)
                rl.draw_line(
                    int(horizontal_start.x),
                    int(horizontal_start.y),
                    int(horizontal_end.x),
                    int(horizontal_end.y),
                    color,
                )

        player_screen = self._player_pos + camera
        px = player_screen.x
        py = player_screen.y

        frame = int(self._move_phase + 0.5)
        if self._frame_count > 0:
            frame %= self._frame_count
        leg_frame = self._leg_base + frame
        torso_frame = leg_frame
        if self._use_torso_offset:
            torso_frame = self._torso_base + frame

        recoil_dir = self._aim_heading + math.pi / 2.0
        recoil_offset = self._muzzle_flash * 12.0
        torso_offset = Vec2.from_angle(recoil_dir) * recoil_offset

        tint = rl.Color(240, 240, 255, 255)
        self._draw_sprite(
            self._assets.trooper,
            leg_frame,
            pos=Vec2(px, py),
            size=self._player_size,
            rotation_rad=self._move_heading,
            tint=tint,
            shadow=self._show_shadow,
        )
        self._draw_sprite(
            self._assets.trooper,
            torso_frame,
            pos=Vec2(px, py),
            size=self._player_size,
            rotation_rad=self._aim_heading,
            tint=tint,
            shadow=self._show_shadow,
            offset=torso_offset,
        )

        # Aim/debug helpers.
        mouse = rl.get_mouse_position()
        rl.draw_circle(int(mouse.x), int(mouse.y), 3.0, rl.Color(120, 200, 255, 255))
        rl.draw_line(int(px), int(py), int(mouse.x), int(mouse.y), rl.Color(120, 200, 255, 180))

        hud_x = 16.0
        hud_y = 16.0
        line = ui_line_height(self._small, scale=UI_TEXT_SCALE)
        draw_ui_text(
            self._small,
            f"legs frame={leg_frame} (base {self._leg_base}, count {self._frame_count})",
            Vec2(hud_x, hud_y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        hud_y += line
        torso_label = "offset" if self._use_torso_offset else "match"
        draw_ui_text(
            self._small,
            f"torso frame={torso_frame} (base {self._torso_base}, mode {torso_label})",
            Vec2(hud_x, hud_y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        hud_y += line
        draw_ui_text(
            self._small,
            f"move_heading={self._move_heading:.2f}  aim_heading={self._aim_heading:.2f}",
            Vec2(hud_x, hud_y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        hud_y += line
        draw_ui_text(
            self._small,
            "WASD move, mouse aim, LMB recoil, F1 grid, F2 shadow, F3 torso mode",
            Vec2(hud_x, hud_y),
            scale=UI_TEXT_SCALE,
            color=UI_HINT_COLOR,
        )
        hud_y += line
        draw_ui_text(
            self._small,
            "[/] torso base, ;/' legs base, ,/. frame count, R reset",
            Vec2(hud_x, hud_y),
            scale=UI_TEXT_SCALE,
            color=UI_HINT_COLOR,
        )


@register_view("player-sprite-debug", "Player sprite debug")
def build_player_sprite_debug_view(*, ctx: ViewContext) -> View:
    return PlayerSpriteDebugView(ctx)
