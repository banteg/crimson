from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ..menu import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuView,
)
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView

if TYPE_CHECKING:
    from ...game import GameState


class ModsMenuView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Mods")
        self._small_font: SmallFontData | None = None
        self._lines: list[str] = []

    def open(self) -> None:
        super().open()
        self._lines = self._build_lines()

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _content_layout(self) -> dict[str, float]:
        panel_scale, _local_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        panel_x = self._panel_pos_x + slide_x
        panel_y = self._panel_pos_y + self._widescreen_y_shift
        origin_x = -(MENU_PANEL_OFFSET_X * panel_scale)
        origin_y = -(MENU_PANEL_OFFSET_Y * panel_scale)
        panel_left = panel_x - origin_x
        panel_top = panel_y - origin_y
        base_x = panel_left + 212.0 * panel_scale
        base_y = panel_top + 32.0 * panel_scale
        label_x = base_x + 8.0 * panel_scale
        return {
            "base_x": base_x,
            "base_y": base_y,
            "label_x": label_x,
            "scale": panel_scale,
        }

    def _build_lines(self) -> list[str]:
        mods_dir = self._state.base_dir / "mods"
        dlls: list[Path] = []
        try:
            dlls = sorted(mods_dir.glob("*.dll"))
        except Exception:
            dlls = []

        if not dlls:
            return [
                "No mod DLLs found.",
                "",
                "Expected location:",
                f"  {mods_dir}",
                "",
                "Mod loading is not implemented yet.",
            ]

        lines = [f"Found {len(dlls)} mod DLL(s):", ""]
        for path in dlls[:10]:
            lines.append(f"  {path.name}")
        if len(dlls) > 10:
            lines.append(f"  ... ({len(dlls) - 10} more)")
        lines.append("")
        lines.append("Mod loading is not implemented yet.")
        return lines

    def _draw_contents(self) -> None:
        layout = self._content_layout()
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        label_x = layout["label_x"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        title_scale = 1.2 * scale
        text_scale = 1.0 * scale

        title_color = rl.Color(255, 255, 255, 255)
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        draw_small_text(font, "MODS", base_x, base_y, title_scale, title_color)
        line_y = base_y + 44.0 * scale
        line_step = (font.cell_size + 4.0) * scale
        for line in self._lines:
            draw_small_text(font, line, label_x, line_y, text_scale, text_color)
            line_y += line_step
