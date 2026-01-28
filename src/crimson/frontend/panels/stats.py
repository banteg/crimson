from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_LABEL_WIDTH,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuView,
    _draw_menu_cursor,
)
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView

from ...persistence.save_status import MODE_COUNT_ORDER
from ...weapons import WEAPON_BY_ID

if TYPE_CHECKING:
    from ...game import GameState


class StatisticsMenuView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Statistics")
        self._small_font: SmallFontData | None = None
        self._stats_lines: list[str] = []

    def open(self) -> None:
        super().open()
        self._stats_lines = self._build_stats_lines()

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_stats_contents()
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
            "panel_left": panel_left,
            "panel_top": panel_top,
            "base_x": base_x,
            "base_y": base_y,
            "label_x": label_x,
            "scale": panel_scale,
        }

    def _build_stats_lines(self) -> list[str]:
        status = self._state.status
        mode_counts = {name: status.mode_play_count(name) for name, _offset in MODE_COUNT_ORDER}
        quest_counts = status.data.get("quest_play_counts", [])
        if isinstance(quest_counts, list):
            quest_total = int(sum(int(v) for v in quest_counts[:40]))
        else:
            quest_total = 0

        checksum_text = "unknown"
        try:
            from ...persistence.save_status import load_status

            blob = load_status(status.path)
            ok = "ok" if blob.checksum_valid else "BAD"
            checksum_text = f"0x{blob.checksum:08x} ({ok})"
        except Exception as exc:
            checksum_text = f"error: {type(exc).__name__}"

        lines = [
            f"Quest unlock: {status.quest_unlock_index} (full {status.quest_unlock_index_full})",
            f"Quest plays (1-40): {quest_total}",
            f"Mode plays: surv {mode_counts['survival']}  rush {mode_counts['rush']}",
            f"            typo {mode_counts['typo']}  other {mode_counts['other']}",
            f"Sequence id: {status.game_sequence_id}",
            f"Checksum: {checksum_text}",
        ]

        usage = status.data.get("weapon_usage_counts", [])
        top_weapons: list[tuple[int, int]] = []
        if isinstance(usage, list):
            for idx, count in enumerate(usage):
                count = int(count)
                if count > 0:
                    top_weapons.append((idx, count))
        top_weapons.sort(key=lambda item: (-item[1], item[0]))
        top_weapons = top_weapons[:4]

        if top_weapons:
            lines.append("Top weapons:")
            for idx, count in top_weapons:
                weapon = WEAPON_BY_ID.get(idx)
                name = weapon.name if weapon is not None and weapon.name else f"weapon_{idx}"
                lines.append(f"  {name}: {count}")
        else:
            lines.append("Top weapons: none")

        return lines

    def _draw_stats_contents(self) -> None:
        assets = self._assets
        if assets is None:
            return
        labels_tex = assets.labels
        layout = self._content_layout()
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        label_x = layout["label_x"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        if labels_tex is not None:
            src = rl.Rectangle(
                0.0,
                float(MENU_LABEL_ROW_STATISTICS) * MENU_LABEL_ROW_HEIGHT,
                MENU_LABEL_WIDTH,
                MENU_LABEL_ROW_HEIGHT,
            )
            dst = rl.Rectangle(
                base_x,
                base_y,
                MENU_LABEL_WIDTH * scale,
                MENU_LABEL_ROW_HEIGHT * scale,
            )
            MenuView._draw_ui_quad(
                texture=labels_tex,
                src=src,
                dst=dst,
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )
        else:
            rl.draw_text(self._title, int(base_x), int(base_y), int(24 * scale), rl.WHITE)

        line_y = base_y + 44.0 * scale
        line_step = (font.cell_size + 4.0) * scale
        for line in self._stats_lines:
            draw_small_text(font, line, label_x, line_y, text_scale, text_color)
            line_y += line_step
