from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from ..bonuses import BONUS_TABLE, BonusMeta
from ..weapons import WEAPON_TABLE
from .registry import register_view
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_HOVER_COLOR = rl.Color(240, 200, 80, 255)


@dataclass(frozen=True, slots=True)
class BonusIconGroup:
    icon_id: int
    bonuses: tuple[BonusMeta, ...]


def _build_icon_groups() -> dict[int, BonusIconGroup]:
    grouped: dict[int, list[BonusMeta]] = {}
    for entry in BONUS_TABLE:
        if entry.icon_id is None or entry.icon_id < 0:
            continue
        grouped.setdefault(entry.icon_id, []).append(entry)
    return {icon_id: BonusIconGroup(icon_id=icon_id, bonuses=tuple(entries)) for icon_id, entries in grouped.items()}


BONUS_ICON_GROUPS = _build_icon_groups()
WEAPON_BONUS = next(
    (entry for entry in BONUS_TABLE if entry.icon_id is not None and entry.icon_id < 0),
    None,
)


class BonusIconView:
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
        path = self._assets_root / "crimson" / "game" / "bonuses.png"
        if not path.is_file():
            self._missing_assets.append("game/bonuses.png")
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
            self._draw_ui_text("No bonuses texture loaded.", 24, 24, UI_TEXT_COLOR)
            return

        margin = 24
        panel_gap = 32
        panel_width = min(420, int(rl.get_screen_width() * 0.4))
        available_width = rl.get_screen_width() - margin * 2 - panel_gap - panel_width
        available_height = rl.get_screen_height() - margin * 2 - 60
        scale = min(
            3.0,
            available_width / self._texture.width,
            available_height / self._texture.height,
        )
        draw_w = self._texture.width * scale
        draw_h = self._texture.height * scale
        x = margin
        y = margin + 60

        src = rl.Rectangle(0.0, 0.0, float(self._texture.width), float(self._texture.height))
        dst = rl.Rectangle(float(x), float(y), float(draw_w), float(draw_h))
        rl.draw_texture_pro(self._texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        grid = 4
        cell_w = draw_w / grid
        cell_h = draw_h / grid
        for i in range(1, grid):
            rl.draw_line(
                int(x + i * cell_w),
                int(y),
                int(x + i * cell_w),
                int(y + draw_h),
                rl.Color(60, 60, 70, 255),
            )
            rl.draw_line(
                int(x),
                int(y + i * cell_h),
                int(x + draw_w),
                int(y + i * cell_h),
                rl.Color(60, 60, 70, 255),
            )

        hovered_index = None
        mouse = rl.get_mouse_position()
        if x <= mouse.x <= x + draw_w and y <= mouse.y <= y + draw_h:
            col = int((mouse.x - x) // cell_w)
            row = int((mouse.y - y) // cell_h)
            if 0 <= col < grid and 0 <= row < grid:
                hovered_index = row * grid + col
                hl = rl.Rectangle(
                    float(x + col * cell_w),
                    float(y + row * cell_h),
                    float(cell_w),
                    float(cell_h),
                )
                rl.draw_rectangle_lines_ex(hl, 3, UI_HOVER_COLOR)

        info_x = x + draw_w + panel_gap
        info_y = margin
        self._draw_ui_text("bonuses.png (grid 4x4)", info_x, info_y, UI_TEXT_COLOR)
        info_y += self._ui_line_height() + 12

        if hovered_index is not None:
            group = BONUS_ICON_GROUPS.get(hovered_index)
            self._draw_ui_text(f"icon_id {hovered_index}", info_x, info_y, UI_TEXT_COLOR)
            info_y += self._ui_line_height() + 6
            if group is None:
                self._draw_ui_text("no bonus mapping", info_x, info_y, UI_HINT_COLOR)
                info_y += self._ui_line_height() + 6
            else:
                for entry in group.bonuses:
                    bonus_id = int(entry.bonus_id)
                    amount = entry.default_amount
                    amount_label = f" default={amount}" if amount is not None else ""
                    self._draw_ui_text(
                        f"id {bonus_id:02d} {entry.name}{amount_label}",
                        info_x,
                        info_y,
                        UI_TEXT_COLOR,
                    )
                    info_y += self._ui_line_height() + 4
                    if entry.description:
                        self._draw_ui_text(
                            entry.description,
                            info_x,
                            info_y,
                            UI_HINT_COLOR,
                        )
                        info_y += self._ui_line_height() + 4
            info_y += 8

        if WEAPON_BONUS is not None:
            self._draw_ui_text("Weapon bonus icon", info_x, info_y, UI_TEXT_COLOR)
            info_y += self._ui_line_height() + 4
            weapon_id = WEAPON_BONUS.default_amount
            weapon_name = None
            if weapon_id is not None:
                for weapon in WEAPON_TABLE:
                    if weapon.weapon_id == weapon_id:
                        weapon_name = weapon.name
                        break
            name_label = f" ({weapon_name})" if weapon_name else ""
            weapon_label = f"icon_id = -1 → ui_wicons (default weapon {weapon_id}{name_label})"
            self._draw_ui_text(weapon_label, info_x, info_y, UI_HINT_COLOR)


@register_view("bonuses", "Bonus icon preview")
def build_bonus_view(ctx: ViewContext) -> View:
    return BonusIconView(ctx)
