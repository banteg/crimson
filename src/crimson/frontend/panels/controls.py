from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ..menu import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuView,
    _draw_menu_cursor,
)
from ..transitions import _draw_screen_fade
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from ...input_codes import config_keybinds, input_code_name, player_move_fire_binds

if TYPE_CHECKING:
    from ...game import GameState


class ControlsMenuView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Controls", back_action="open_options")
        self._small_font: SmallFontData | None = None
        self._lines: list[str] = []

    def open(self) -> None:
        super().open()
        self._lines = self._build_lines()

    def draw(self) -> None:
        self._draw_background()
        _draw_screen_fade(self._state)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

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
        config = self._state.config
        pick_perk_key = int(config.data.get("keybind_pick_perk", 0x101) or 0x101)
        reload_key = int(config.data.get("keybind_reload", 0x102) or 0x102)

        keybinds = config_keybinds(config)
        if not keybinds:
            keybinds = (0x11, 0x1F, 0x1E, 0x20, 0x100) + (0x17E,) * 11 + (0xC8, 0xD0, 0xCB, 0xCD, 0x9D)

        p1_up, p1_down, p1_left, p1_right, p1_fire = player_move_fire_binds(keybinds, 0)
        p2_up, p2_down, p2_left, p2_right, p2_fire = player_move_fire_binds(keybinds, 1)

        return [
            f"Level up: {input_code_name(pick_perk_key)} / Space / KeyPad+",
            f"Reload: {input_code_name(reload_key)}",
            "",
            "Player 1:",
            f"  Up: {input_code_name(p1_up)}",
            f"  Down: {input_code_name(p1_down)}",
            f"  Left: {input_code_name(p1_left)}",
            f"  Right: {input_code_name(p1_right)}",
            f"  Fire: {input_code_name(p1_fire)}",
            "",
            "Player 2:",
            f"  Up: {input_code_name(p2_up)}",
            f"  Down: {input_code_name(p2_down)}",
            f"  Left: {input_code_name(p2_left)}",
            f"  Right: {input_code_name(p2_right)}",
            f"  Fire: {input_code_name(p2_fire)}",
        ]

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

        draw_small_text(font, "CONTROLS", base_x, base_y, title_scale, title_color)
        line_y = base_y + 44.0 * scale
        line_step = (font.cell_size + 4.0) * scale
        for line in self._lines:
            draw_small_text(font, line, label_x, line_y, text_scale, text_color)
            line_y += line_step
