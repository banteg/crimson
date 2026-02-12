from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from ..weapons import WEAPON_TABLE, Weapon, weapon_display_name
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view
from grim.fonts.small import SmallFontData, load_small_font
from grim.view import View, ViewContext
from grim.geom import Vec2

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
        self._preserve_bugs = bool(ctx.preserve_bugs)
        self._missing_assets: list[str] = []
        self._texture: rl.Texture | None = None
        self._small: SmallFontData | None = None

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
            draw_ui_text(self._small, message, Vec2(24, 24), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return
        if self._texture is None:
            draw_ui_text(
                self._small,
                "No weapon icon texture loaded.",
                Vec2(24, 24),
                scale=UI_TEXT_SCALE,
                color=UI_TEXT_COLOR,
            )
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

            draw_ui_text(
                self._small,
                f"{idx:02d}",
                Vec2(dst_x + 4, dst_y + 4),
                scale=0.75,
                color=UI_HINT_COLOR,
            )

        info_x = x + cols * icon_w * scale + panel_gap
        info_y = margin
        draw_ui_text(
            self._small,
            "ui_wicons.png (8x8 grid, 2x1 subrects)",
            Vec2(info_x, info_y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 12

        if hovered_index is not None:
            frame = hovered_index * 2
            draw_ui_text(
                self._small,
                f"icon_index {hovered_index}  frame {frame}",
                Vec2(info_x, info_y),
                scale=UI_TEXT_SCALE,
                color=UI_TEXT_COLOR,
            )
            info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
            group = WEAPON_ICON_GROUPS.get(hovered_index)
            if group is None:
                draw_ui_text(
                    self._small, "no weapon mapping", Vec2(info_x, info_y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR
                )
                info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
            else:
                for weapon in group.weapons:
                    name = weapon_display_name(int(weapon.weapon_id), preserve_bugs=bool(self._preserve_bugs))
                    draw_ui_text(self._small, name, Vec2(info_x, info_y), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
                    info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 4


@register_view("wicons", "Weapon icon preview")
def build_weapon_icon_view(ctx: ViewContext) -> View:
    return WeaponIconView(ctx)
