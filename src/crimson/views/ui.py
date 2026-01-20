from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from .font_small import SmallFontData, draw_small_text, load_small_font
from .registry import register_view
from .types import View, ViewContext

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(frozen=True, slots=True)
class UiTexture:
    name: str
    texture: rl.Texture


class UiTextureView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._textures: list[UiTexture] = []
        self._index = 0
        self._small: SmallFontData | None = None

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
        self._textures.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        ui_dir = self._assets_root / "crimson" / "ui"
        if not ui_dir.is_dir():
            self._missing_assets.append("ui/")
            return
        for path in sorted(ui_dir.glob("*.png")):
            texture = rl.load_texture(str(path))
            self._textures.append(UiTexture(name=path.name, texture=texture))

    def close(self) -> None:
        for entry in self._textures:
            rl.unload_texture(entry.texture)
        self._textures.clear()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        del dt

    def _advance(self, delta: int) -> None:
        if not self._textures:
            return
        self._index = (self._index + delta) % len(self._textures)

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._advance(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._advance(-1)

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return
        if not self._textures:
            self._draw_ui_text("No UI textures loaded.", 24, 24, UI_TEXT_COLOR)
            return

        self._handle_input()
        entry = self._textures[self._index]

        margin = 24
        header_y = margin
        line_height = self._ui_line_height()
        title = f"{self._index + 1}/{len(self._textures)} {entry.name}"
        self._draw_ui_text(title, margin, header_y, UI_TEXT_COLOR)
        header_y += line_height + 6
        self._draw_ui_text("Left/Right: texture", margin, header_y, UI_HINT_COLOR)

        available_width = rl.get_screen_width() - margin * 2
        available_height = rl.get_screen_height() - (header_y + line_height + margin)
        scale = min(
            2.0,
            available_width / entry.texture.width,
            available_height / entry.texture.height,
        )
        draw_w = entry.texture.width * scale
        draw_h = entry.texture.height * scale
        x = margin + (available_width - draw_w) / 2
        y = header_y + line_height + (available_height - draw_h) / 2

        src = rl.Rectangle(0.0, 0.0, float(entry.texture.width), float(entry.texture.height))
        dst = rl.Rectangle(float(x), float(y), float(draw_w), float(draw_h))
        rl.draw_texture_pro(entry.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)


@register_view("ui", "UI texture preview")
def build_ui_view(ctx: ViewContext) -> View:
    return UiTextureView(ctx)
