from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from ..weapons import WEAPON_TABLE, Weapon
from .font_small import SmallFontData, draw_small_text, load_small_font
from .registry import register_view
from grim.view import View, ViewContext

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_HOVER_COLOR = rl.Color(240, 200, 80, 255)


@dataclass(frozen=True, slots=True)
class WeaponIconGroup:
    icon_index: int
    weapons: tuple[Weapon, ...]


def _build_icon_groups() -> dict[int, WeaponIconGroup]:
    grouped: dict[int, list[Weapon]] = {}
    for entry in WEAPON_TABLE:
        icon_index = entry.icon_index
        if icon_index is None or icon_index < 0 or icon_index > 31:
            continue
        grouped.setdefault(icon_index, []).append(entry)
    return {
        icon_index: WeaponIconGroup(icon_index=icon_index, weapons=tuple(entries))
        for icon_index, entries in grouped.items()
    }


WEAPON_ICON_GROUPS = _build_icon_groups()


class WeaponIconView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._texture: rl.Texture | None = None
        self._small: SmallFontData | None = None

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

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        path = self._assets_root / "crimson" / "ui" / "ui_wicons.png"
        if not path.is_file():
            self._missing_assets.append("ui/ui_wicons.png")
            raise FileNotFoundError(f"Missing asset: {path}")
        self._texture = rl.load_texture(str(path))

    def close(self) -> None:
        if self._texture is not None:
            rl.unload_texture(self._texture)
            self._texture = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        del dt

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return
        if self._texture is None:
            self._draw_ui_text("No weapon icon texture loaded.", 24, 24, UI_TEXT_COLOR)
            return

        margin = 24
        panel_gap = 32
        panel_width = min(420, int(rl.get_screen_width() * 0.4))
        available_width = rl.get_screen_width() - margin * 2 - panel_gap - panel_width
        available_height = rl.get_screen_height() - margin * 2 - 60

        cols = 4
        rows = 8
        icon_w = self._texture.width / cols
        icon_h = self._texture.height / rows
        scale = min(2.5, available_width / (cols * icon_w), available_height / (rows * icon_h))

        x = margin
        y = margin + 60
        hovered_index = None
        mouse = rl.get_mouse_position()

        for idx in range(cols * rows):
            row = idx // cols
            col = idx % cols
            dst_x = x + col * icon_w * scale
            dst_y = y + row * icon_h * scale
            dst = rl.Rectangle(float(dst_x), float(dst_y), float(icon_w * scale), float(icon_h * scale))
            src = rl.Rectangle(float(col * icon_w), float(row * icon_h), float(icon_w), float(icon_h))
            rl.draw_texture_pro(self._texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

            if dst_x <= mouse.x <= dst_x + dst.width and dst_y <= mouse.y <= dst_y + dst.height:
                hovered_index = idx
                rl.draw_rectangle_lines_ex(dst, 3, UI_HOVER_COLOR)

            self._draw_ui_text(
                f"{idx:02d}",
                dst_x + 4,
                dst_y + 4,
                UI_HINT_COLOR,
                scale=0.75,
            )

        info_x = x + cols * icon_w * scale + panel_gap
        info_y = margin
        self._draw_ui_text(
            "ui_wicons.png (8x8 grid, 2x1 subrects)",
            info_x,
            info_y,
            UI_TEXT_COLOR,
        )
        info_y += self._ui_line_height() + 12

        if hovered_index is not None:
            frame = hovered_index * 2
            self._draw_ui_text(
                f"icon_index {hovered_index}  frame {frame}",
                info_x,
                info_y,
                UI_TEXT_COLOR,
            )
            info_y += self._ui_line_height() + 6
            group = WEAPON_ICON_GROUPS.get(hovered_index)
            if group is None:
                self._draw_ui_text("no weapon mapping", info_x, info_y, UI_HINT_COLOR)
                info_y += self._ui_line_height() + 6
            else:
                for weapon in group.weapons:
                    name = weapon.name or f"weapon_{weapon.weapon_id}"
                    self._draw_ui_text(name, info_x, info_y, UI_TEXT_COLOR)
                    info_y += self._ui_line_height() + 4


@register_view("wicons", "Weapon icon preview")
def build_weapon_icon_view(ctx: ViewContext) -> View:
    return WeaponIconView(ctx)
