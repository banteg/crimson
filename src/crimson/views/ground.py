from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from ..config import ensure_crimson_cfg
from ..terrain_render import GroundRenderer
from .font_small import SmallFontData, draw_small_text, load_small_font
from .registry import register_view
from .types import View, ViewContext


UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(slots=True)
class GroundAssets:
    base: rl.Texture
    overlay: rl.Texture | None


class GroundView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._assets: GroundAssets | None = None
        self._renderer: GroundRenderer | None = None
        self._camera_x = 0.0
        self._camera_y = 0.0

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _draw_ui_text(
        self, text: str, x: float, y: float, color: rl.Color, scale: float = UI_TEXT_SCALE
    ) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        base_path = self._resolve_asset("ter/ter_q1_base.png")
        overlay_path = self._resolve_asset("ter/ter_q1_tex1.png")
        if base_path is None:
            self._missing_assets.append("ter/ter_q1_base.png")
            return
        base = rl.load_texture(str(base_path))
        overlay = rl.load_texture(str(overlay_path)) if overlay_path else None
        self._assets = GroundAssets(base=base, overlay=overlay)
        texture_scale, screen_w, screen_h = self._load_runtime_config()
        self._renderer = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=base,
            width=1024,
            height=1024,
            texture_scale=texture_scale,
            screen_width=screen_w,
            screen_height=screen_h,
        )
        self._renderer.generate(seed=1)

    def close(self) -> None:
        if self._assets is not None:
            rl.unload_texture(self._assets.base)
            if self._assets.overlay is not None:
                rl.unload_texture(self._assets.overlay)
            self._assets = None
        if self._renderer is not None and self._renderer.render_target is not None:
            rl.unload_render_texture(self._renderer.render_target)
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        speed = 240.0
        if rl.is_key_down(rl.KeyboardKey.KEY_LEFT):
            self._camera_x += speed * dt
        if rl.is_key_down(rl.KeyboardKey.KEY_RIGHT):
            self._camera_x -= speed * dt
        if rl.is_key_down(rl.KeyboardKey.KEY_UP):
            self._camera_y += speed * dt
        if rl.is_key_down(rl.KeyboardKey.KEY_DOWN):
            self._camera_y -= speed * dt

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return
        if self._renderer is None:
            self._draw_ui_text("Ground renderer not initialized.", 24, 24, UI_ERROR_COLOR)
            return
        self._renderer.draw(self._camera_x, self._camera_y)
        self._draw_ui_text(
            "Arrow keys: pan camera", 24, 24, UI_TEXT_COLOR, scale=0.9
        )

    def _resolve_asset(self, rel_path: str) -> Path | None:
        direct = self._assets_root / rel_path
        if direct.is_file():
            return direct
        legacy = self._assets_root / "crimson" / rel_path
        if legacy.is_file():
            return legacy
        return None

    def _load_runtime_config(self) -> tuple[float, float | None, float | None]:
        runtime_dir = Path("artifacts") / "runtime"
        if runtime_dir.is_dir():
            try:
                cfg = ensure_crimson_cfg(runtime_dir)
                return cfg.texture_scale, float(cfg.screen_width), float(cfg.screen_height)
            except Exception:
                return 1.0, None, None
        return 1.0, None, None


@register_view("ground", "Ground texture")
def build_ground_view(ctx: ViewContext) -> View:
    return GroundView(ctx)
