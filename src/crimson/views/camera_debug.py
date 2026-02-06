from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import time

import pyray as rl

from grim.assets import resolve_asset_path
from grim.config import ensure_crimson_cfg
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, load_small_font
from grim.view import View, ViewContext

from ..paths import default_runtime_dir
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view


WORLD_SIZE = 1024.0
WINDOW_W = 640
WINDOW_H = 480
GRID_STEP = 64.0
LOG_INTERVAL_S = 0.1

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(slots=True)
class CameraDebugAssets:
    base: rl.Texture
    overlay: rl.Texture | None
    detail: rl.Texture | None


class CameraDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._assets: CameraDebugAssets | None = None
        self._renderer: GroundRenderer | None = None
        self._config_screen_w = float(WINDOW_W)
        self._config_screen_h = float(WINDOW_H)
        self._texture_scale = 1.0
        self._use_config_screen = False
        self._player = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)
        self._camera = Vec2(-1.0, -1.0)
        self._camera_target = Vec2(-1.0, -1.0)
        self._log_timer = 0.0
        self._log_path: Path | None = None
        self._log_file = None

    def _load_runtime_config(self) -> None:
        runtime_dir = default_runtime_dir()
        if not runtime_dir.is_dir():
            return
        try:
            cfg = ensure_crimson_cfg(runtime_dir)
        except Exception:
            return
        self._config_screen_w = float(cfg.screen_width)
        self._config_screen_h = float(cfg.screen_height)
        self._texture_scale = float(cfg.texture_scale)

    def _camera_screen_size(self) -> Vec2:
        if self._use_config_screen:
            screen_w = float(self._config_screen_w)
            screen_h = float(self._config_screen_h)
        else:
            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE
        return Vec2(screen_w, screen_h)

    def _clamp_camera(self, camera: Vec2, screen_w: float, screen_h: float) -> Vec2:
        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        return camera.clamp_rect(min_x, min_y, -1.0, -1.0)

    def _world_params(self) -> tuple[Vec2, Vec2, Vec2]:
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        screen_size = self._camera_screen_size()
        camera = self._clamp_camera(self._camera, screen_size.x, screen_size.y)
        scale_x = out_size.x / screen_size.x if screen_size.x > 0 else 1.0
        scale_y = out_size.y / screen_size.y if screen_size.y > 0 else 1.0
        return camera, Vec2(scale_x, scale_y), screen_size

    def _write_log(self, payload: dict) -> None:
        if self._log_file is None:
            return
        try:
            self._log_file.write(json.dumps(payload, sort_keys=True) + "\n")
            self._log_file.flush()
        except Exception:
            self._log_file = None

    def open(self) -> None:
        rl.set_window_size(WINDOW_W, WINDOW_H)
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        base_path = resolve_asset_path(self._assets_root, "ter/ter_q1_base.png")
        overlay_path = resolve_asset_path(self._assets_root, "ter/ter_q1_tex1.png")
        if base_path is None:
            self._missing_assets.append("ter/ter_q1_base.png")
        if overlay_path is None:
            self._missing_assets.append("ter/ter_q1_tex1.png")
        if self._missing_assets:
            raise FileNotFoundError("Missing assets: " + ", ".join(self._missing_assets))
        base = rl.load_texture(str(base_path))
        overlay = rl.load_texture(str(overlay_path)) if overlay_path is not None else None
        detail = overlay or base
        self._assets = CameraDebugAssets(base=base, overlay=overlay, detail=detail)

        self._load_runtime_config()
        self._renderer = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=int(WORLD_SIZE),
            height=int(WORLD_SIZE),
            texture_scale=self._texture_scale,
            screen_width=self._config_screen_w if self._use_config_screen else None,
            screen_height=self._config_screen_h if self._use_config_screen else None,
        )
        self._renderer.schedule_generate(seed=0, layers=3)

        log_dir = Path("artifacts") / "debug"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_dir = Path("artifacts")
        self._log_path = log_dir / "camera_debug.jsonl"
        try:
            self._log_file = self._log_path.open("w", encoding="utf-8")
        except Exception:
            self._log_file = None

    def close(self) -> None:
        if self._assets is not None:
            rl.unload_texture(self._assets.base)
            if self._assets.overlay is not None:
                rl.unload_texture(self._assets.overlay)
            self._assets = None
        if self._renderer is not None:
            if self._renderer.render_target is not None:
                rl.unload_render_texture(self._renderer.render_target)
            self._renderer = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F1):
            self._use_config_screen = not self._use_config_screen
        speed = 120.0
        if rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT):
            speed *= 2.0
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
        if move.length_sq() > 0.0:
            self._player = (self._player + move.normalized() * (speed * dt)).clamp_rect(
                0.0, 0.0, WORLD_SIZE, WORLD_SIZE
            )

        screen_size = self._camera_screen_size()
        desired = Vec2(
            (screen_size.x * 0.5) - self._player.x,
            (screen_size.y * 0.5) - self._player.y,
        )
        desired = self._clamp_camera(desired, screen_size.x, screen_size.y)
        self._camera_target = desired

        t = max(0.0, min(dt * 6.0, 1.0))
        self._camera = Vec2.lerp(self._camera, desired, t)

        if self._renderer is not None:
            self._renderer.texture_scale = self._texture_scale
            if self._use_config_screen:
                self._renderer.screen_width = self._config_screen_w
                self._renderer.screen_height = self._config_screen_h
            else:
                self._renderer.screen_width = None
                self._renderer.screen_height = None
            self._renderer.process_pending()

        self._log_timer += dt
        if self._log_timer >= LOG_INTERVAL_S:
            self._log_timer -= LOG_INTERVAL_S
            camera, view_scale, screen_size = self._world_params()
            payload = {
                "ts": time.time(),
                "dt": dt,
                "player": {"x": self._player.x, "y": self._player.y},
                "camera": {"x": camera.x, "y": camera.y},
                "camera_raw": {"x": self._camera.x, "y": self._camera.y},
                "camera_target": {"x": self._camera_target.x, "y": self._camera_target.y},
                "world": {"size": WORLD_SIZE},
                "screen": {
                    "window": {"w": rl.get_screen_width(), "h": rl.get_screen_height()},
                    "camera": {"w": screen_size.x, "h": screen_size.y},
                    "config": {"w": self._config_screen_w, "h": self._config_screen_h},
                    "use_config": self._use_config_screen,
                },
                "texture_scale": self._texture_scale,
                "scale": {"x": view_scale.x, "y": view_scale.y},
                "uv": {
                    "u0": -camera.x / WORLD_SIZE,
                    "v0": -camera.y / WORLD_SIZE,
                    "u1": (-camera.x + screen_size.x) / WORLD_SIZE,
                    "v1": (-camera.y + screen_size.y) / WORLD_SIZE,
                },
            }
            if self._log_path is not None:
                payload["log_path"] = str(self._log_path)
            self._write_log(payload)

    def draw(self) -> None:
        clear_color = rl.Color(10, 10, 12, 255)
        rl.clear_background(clear_color)

        if self._renderer is None:
            draw_ui_text(
                self._small, "Ground renderer not initialized.", Vec2(16, 16), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR
            )
            return

        camera, view_scale, screen_size = self._world_params()
        self._renderer.draw(camera, screen_w=screen_size.x, screen_h=screen_size.y)

        # Grid in world space
        grid_major = rl.Color(70, 80, 95, 180)
        grid_minor = rl.Color(40, 50, 65, 140)
        for i in range(0, int(WORLD_SIZE) + 1, int(GRID_STEP)):
            color = grid_major if i % 256 == 0 else grid_minor
            vertical_start = (Vec2(float(i), 0.0) + camera).mul_components(view_scale)
            vertical_end = (Vec2(float(i), WORLD_SIZE) + camera).mul_components(view_scale)
            rl.draw_line(
                int(vertical_start.x),
                int(vertical_start.y),
                int(vertical_end.x),
                int(vertical_end.y),
                color,
            )
            horizontal_start = (Vec2(0.0, float(i)) + camera).mul_components(view_scale)
            horizontal_end = (Vec2(WORLD_SIZE, float(i)) + camera).mul_components(view_scale)
            rl.draw_line(
                int(horizontal_start.x),
                int(horizontal_start.y),
                int(horizontal_end.x),
                int(horizontal_end.y),
                color,
            )

        # Player
        player_screen = (self._player + camera).mul_components(view_scale)
        rl.draw_circle(
            int(player_screen.x),
            int(player_screen.y),
            max(2, int(6 * view_scale.avg_component())),
            rl.Color(255, 200, 120, 255),
        )

        # Minimap
        out_w = float(rl.get_screen_width())
        map_size = 160.0
        margin = 12.0
        map_x = out_w - map_size - margin
        map_y = margin
        rl.draw_rectangle(int(map_x), int(map_y), int(map_size), int(map_size), rl.Color(12, 12, 18, 220))
        rl.draw_rectangle_lines(int(map_x), int(map_y), int(map_size), int(map_size), rl.Color(180, 180, 200, 220))

        map_scale = map_size / WORLD_SIZE
        view_left = -camera.x
        view_top = -camera.y
        view_w = screen_size.x
        view_h = screen_size.y
        vx = map_x + view_left * map_scale
        vy = map_y + view_top * map_scale
        vw = view_w * map_scale
        vh = view_h * map_scale
        rl.draw_rectangle_lines(int(vx), int(vy), int(vw), int(vh), rl.Color(120, 200, 255, 220))
        mx = map_x + self._player.x * map_scale
        my = map_y + self._player.y * map_scale
        rl.draw_circle(int(mx), int(my), 3, rl.Color(255, 200, 120, 255))

        # HUD
        x = 16.0
        y = 16.0
        line = ui_line_height(self._small, scale=UI_TEXT_SCALE)
        mode = "config" if self._use_config_screen else "window"
        draw_ui_text(
            self._small,
            f"window={int(out_w)}x{int(rl.get_screen_height())}  camera={int(screen_size.x)}x{int(screen_size.y)} ({mode})",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        y += line
        draw_ui_text(
            self._small,
            f"config={int(self._config_screen_w)}x{int(self._config_screen_h)}  "
            f"scale={view_scale.x:.3f},{view_scale.y:.3f}  tex={self._texture_scale:.2f}",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        y += line
        draw_ui_text(
            self._small,
            f"player={self._player.x:.1f},{self._player.y:.1f}",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        y += line
        draw_ui_text(
            self._small, f"camera={camera.x:.1f},{camera.y:.1f}", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR
        )
        y += line
        if self._log_path is not None:
            draw_ui_text(self._small, f"log: {self._log_path}", Vec2(x, y), scale=0.9, color=UI_HINT_COLOR)
            y += line
        draw_ui_text(
            self._small, "F1: toggle camera size (config/window)", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR
        )


@register_view("camera-debug", "Camera debug")
def build_camera_debug_view(*, ctx: ViewContext) -> View:
    return CameraDebugView(ctx)
