from __future__ import annotations
from dataclasses import dataclass

from grim.geom import Vec2

from pathlib import Path

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ..menu import (
    MENU_PANEL_WIDTH,
    MenuView,
)
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView

from ..types import GameState


@dataclass(frozen=True, slots=True)
class _ModsContentLayout:
    scale: float
    base_pos: Vec2
    label_pos: Vec2


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

    def _content_layout(self) -> _ModsContentLayout:
        panel_scale, _local_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        panel_top_left = (
            Vec2(
                self._panel_pos.x + slide_x,
                self._panel_pos.y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )
        base_pos = panel_top_left + Vec2(212.0 * panel_scale, 32.0 * panel_scale)
        label_pos = base_pos + Vec2(8.0 * panel_scale, 0.0)
        return _ModsContentLayout(scale=panel_scale, base_pos=base_pos, label_pos=label_pos)

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
        base_pos = layout.base_pos
        label_pos = layout.label_pos
        scale = layout.scale

        font = self._ensure_small_font()
        title_scale = 1.2 * scale
        text_scale = 1.0 * scale

        title_color = rl.Color(255, 255, 255, 255)
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        draw_small_text(font, "MODS", base_pos, title_scale, title_color)
        line_pos = label_pos.offset(dy=44.0 * scale)
        line_step = (font.cell_size + 4.0) * scale
        for line in self._lines:
            draw_small_text(font, line, line_pos, text_scale, text_color)
            line_pos = line_pos.offset(dy=line_step)
