from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
import time

import pyray as rl

from grim.assets import resolve_asset_path
from grim.config import ensure_crimson_cfg
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext
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
        self._player_x = WORLD_SIZE * 0.5
        self._player_y = WORLD_SIZE * 0.5
        self._camera_x = -1.0
        self._camera_y = -1.0
        self._camera_target_x = -1.0
        self._camera_target_y = -1.0
        self._log_timer = 0.0
        self._log_path: Path | None = None
        self._log_file = None

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _draw_ui_text(
        self,
        text: str,
        x: float,
        y: float,
        color: rl.Color,
        scale: float = UI_TEXT_SCALE,
    ) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _load_runtime_config(self) -> None:
        runtime_dir = Path("artifacts") / "runtime"
        if not runtime_dir.is_dir():
            return
        try:
            cfg = ensure_crimson_cfg(runtime_dir)
        except Exception:
            return
        self._config_screen_w = float(cfg.screen_width)
        self._config_screen_h = float(cfg.screen_height)
        self._texture_scale = float(cfg.texture_scale)

    def _camera_screen_size(self) -> tuple[float, float]:
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
        return screen_w, screen_h

    def _clamp_camera(self, cam_x: float, cam_y: float, screen_w: float, screen_h: float) -> tuple[float, float]:
        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_y > -1.0:
            cam_y = -1.0
        if cam_x < min_x:
            cam_x = min_x
        if cam_y < min_y:
            cam_y = min_y
        return cam_x, cam_y

    def _world_params(self) -> tuple[float, float, float, float, float, float]:
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w, screen_h = self._camera_screen_size()
        cam_x, cam_y = self._clamp_camera(self._camera_x, self._camera_y, screen_w, screen_h)
        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        return cam_x, cam_y, scale_x, scale_y, screen_w, screen_h

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
        if move_x != 0.0 or move_y != 0.0:
            length = math.hypot(move_x, move_y)
            if length > 0.0:
                move_x /= length
                move_y /= length
            self._player_x += move_x * speed * dt
            self._player_y += move_y * speed * dt
            self._player_x = max(0.0, min(WORLD_SIZE, self._player_x))
            self._player_y = max(0.0, min(WORLD_SIZE, self._player_y))

        screen_w, screen_h = self._camera_screen_size()
        desired_x = (screen_w * 0.5) - self._player_x
        desired_y = (screen_h * 0.5) - self._player_y
        desired_x, desired_y = self._clamp_camera(desired_x, desired_y, screen_w, screen_h)
        self._camera_target_x = desired_x
        self._camera_target_y = desired_y

        t = max(0.0, min(dt * 6.0, 1.0))
        self._camera_x = self._camera_x + (desired_x - self._camera_x) * t
        self._camera_y = self._camera_y + (desired_y - self._camera_y) * t

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
            cam_x, cam_y, scale_x, scale_y, screen_w, screen_h = self._world_params()
            payload = {
                "ts": time.time(),
                "dt": dt,
                "player": {"x": self._player_x, "y": self._player_y},
                "camera": {"x": cam_x, "y": cam_y},
                "camera_raw": {"x": self._camera_x, "y": self._camera_y},
                "camera_target": {"x": self._camera_target_x, "y": self._camera_target_y},
                "world": {"size": WORLD_SIZE},
                "screen": {
                    "window": {"w": rl.get_screen_width(), "h": rl.get_screen_height()},
                    "camera": {"w": screen_w, "h": screen_h},
                    "config": {"w": self._config_screen_w, "h": self._config_screen_h},
                    "use_config": self._use_config_screen,
                },
                "texture_scale": self._texture_scale,
                "scale": {"x": scale_x, "y": scale_y},
                "uv": {
                    "u0": -cam_x / WORLD_SIZE,
                    "v0": -cam_y / WORLD_SIZE,
                    "u1": (-cam_x + screen_w) / WORLD_SIZE,
                    "v1": (-cam_y + screen_h) / WORLD_SIZE,
                },
            }
            if self._log_path is not None:
                payload["log_path"] = str(self._log_path)
            self._write_log(payload)

    def draw(self) -> None:
        clear_color = rl.Color(10, 10, 12, 255)
        rl.clear_background(clear_color)

        if self._renderer is None:
            self._draw_ui_text("Ground renderer not initialized.", 16, 16, UI_ERROR_COLOR)
            return

        cam_x, cam_y, scale_x, scale_y, screen_w, screen_h = self._world_params()
        self._renderer.draw(cam_x, cam_y, screen_w=screen_w, screen_h=screen_h)

        # Grid in world space
        grid_major = rl.Color(70, 80, 95, 180)
        grid_minor = rl.Color(40, 50, 65, 140)
        for i in range(0, int(WORLD_SIZE) + 1, int(GRID_STEP)):
            color = grid_major if i % 256 == 0 else grid_minor
            sx = (float(i) + cam_x) * scale_x
            sy0 = (0.0 + cam_y) * scale_y
            sy1 = (WORLD_SIZE + cam_y) * scale_y
            rl.draw_line(int(sx), int(sy0), int(sx), int(sy1), color)
            sy = (float(i) + cam_y) * scale_y
            sx0 = (0.0 + cam_x) * scale_x
            sx1 = (WORLD_SIZE + cam_x) * scale_x
            rl.draw_line(int(sx0), int(sy), int(sx1), int(sy), color)

        # Player
        px = (self._player_x + cam_x) * scale_x
        py = (self._player_y + cam_y) * scale_y
        rl.draw_circle(int(px), int(py), max(2, int(6 * (scale_x + scale_y) * 0.5)), rl.Color(255, 200, 120, 255))

        # Minimap
        out_w = float(rl.get_screen_width())
        map_size = 160.0
        margin = 12.0
        map_x = out_w - map_size - margin
        map_y = margin
        rl.draw_rectangle(int(map_x), int(map_y), int(map_size), int(map_size), rl.Color(12, 12, 18, 220))
        rl.draw_rectangle_lines(int(map_x), int(map_y), int(map_size), int(map_size), rl.Color(180, 180, 200, 220))

        map_scale = map_size / WORLD_SIZE
        view_left = -cam_x
        view_top = -cam_y
        view_w = screen_w
        view_h = screen_h
        vx = map_x + view_left * map_scale
        vy = map_y + view_top * map_scale
        vw = view_w * map_scale
        vh = view_h * map_scale
        rl.draw_rectangle_lines(int(vx), int(vy), int(vw), int(vh), rl.Color(120, 200, 255, 220))
        mx = map_x + self._player_x * map_scale
        my = map_y + self._player_y * map_scale
        rl.draw_circle(int(mx), int(my), 3, rl.Color(255, 200, 120, 255))

        # HUD
        x = 16.0
        y = 16.0
        line = self._ui_line_height()
        mode = "config" if self._use_config_screen else "window"
        self._draw_ui_text(
            f"window={int(out_w)}x{int(rl.get_screen_height())}  camera={int(screen_w)}x{int(screen_h)} ({mode})",
            x,
            y,
            UI_TEXT_COLOR,
        )
        y += line
        self._draw_ui_text(
            f"config={int(self._config_screen_w)}x{int(self._config_screen_h)}  "
            f"scale={scale_x:.3f},{scale_y:.3f}  tex={self._texture_scale:.2f}",
            x,
            y,
            UI_TEXT_COLOR,
        )
        y += line
        self._draw_ui_text(f"player={self._player_x:.1f},{self._player_y:.1f}", x, y, UI_TEXT_COLOR)
        y += line
        self._draw_ui_text(f"camera={cam_x:.1f},{cam_y:.1f}", x, y, UI_TEXT_COLOR)
        y += line
        if self._log_path is not None:
            self._draw_ui_text(f"log: {self._log_path}", x, y, UI_HINT_COLOR, scale=0.9)
            y += line
        self._draw_ui_text("F1: toggle camera size (config/window)", x, y, UI_HINT_COLOR)


@register_view("camera-debug", "Camera debug")
def build_camera_debug_view(*, ctx: ViewContext) -> View:
    return CameraDebugView(ctx)
