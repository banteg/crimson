from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.audio import play_music, stop_music
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_LABEL_WIDTH,
    MENU_PANEL_HEIGHT,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuView,
    _draw_menu_cursor,
)
from ..transitions import _draw_screen_fade
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView

from ...persistence.save_status import MODE_COUNT_ORDER
from ...weapons import WEAPON_BY_ID, WeaponId

if TYPE_CHECKING:
    from ...game import GameState


class StatisticsMenuView(PanelMenuView):
    _PAGES = ("Summary", "Weapons", "Quests")

    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Statistics")
        self._small_font: SmallFontData | None = None
        self._page_index = 0
        self._scroll_index = 0
        self._page_lines: list[list[str]] = []

    def open(self) -> None:
        super().open()
        self._page_index = 0
        self._scroll_index = 0
        self._page_lines = self._build_pages()
        if self._state.audio is not None:
            if self._state.audio.music.active_track != "shortie_monk":
                stop_music(self._state.audio)
            play_music(self._state.audio, "shortie_monk")

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
        self._draw_stats_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return
        entry = self._entry
        if entry is None or not self._entry_enabled(entry):
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._switch_page(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._switch_page(1)

        font = self._ensure_small_font()
        layout = self._content_layout()
        rows = self._visible_rows(font, layout)
        max_scroll = max(0, len(self._active_page_lines()) - rows)

        wheel = int(rl.get_mouse_wheel_move())
        if wheel:
            self._scroll_index = max(0, min(max_scroll, int(self._scroll_index) - wheel))

        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._scroll_index = max(0, int(self._scroll_index) - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._scroll_index = min(max_scroll, int(self._scroll_index) + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
            self._scroll_index = max(0, int(self._scroll_index) - rows)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._scroll_index = min(max_scroll, int(self._scroll_index) + rows)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
            self._scroll_index = 0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
            self._scroll_index = max_scroll

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

    def _switch_page(self, delta: int) -> None:
        if not self._page_lines:
            return
        count = len(self._page_lines)
        self._page_index = (int(self._page_index) + int(delta)) % count
        self._scroll_index = 0

    def _active_page_lines(self) -> list[str]:
        if not self._page_lines:
            return []
        idx = int(self._page_index)
        if idx < 0:
            idx = 0
        if idx >= len(self._page_lines):
            idx = len(self._page_lines) - 1
        return self._page_lines[idx]

    def _build_pages(self) -> list[list[str]]:
        return [
            self._build_summary_lines(),
            self._build_weapon_usage_lines(),
            self._build_quest_progress_lines(),
        ]

    def _build_summary_lines(self) -> list[str]:
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

        playtime_ms = int(status.game_sequence_id)
        seconds = max(0, playtime_ms // 1000)
        minutes = seconds // 60
        hours = minutes // 60
        minutes %= 60
        seconds %= 60

        lines = [
            f"Played for: {hours}h {minutes:02d}m {seconds:02d}s",
            f"Quest unlock: {status.quest_unlock_index} (full {status.quest_unlock_index_full})",
            f"Quest plays (1-40): {quest_total}",
            f"Mode plays: surv {mode_counts['survival']}  rush {mode_counts['rush']}",
            f"            typo {mode_counts['typo']}  other {mode_counts['other']}",
            f"Playtime ms: {int(status.game_sequence_id)}",
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

    def _build_weapon_usage_lines(self) -> list[str]:
        status = self._state.status
        usage = status.data.get("weapon_usage_counts", [])
        if not isinstance(usage, list):
            return ["Weapon usage: error (missing weapon_usage_counts)"]

        items: list[tuple[int, int, str]] = []
        for idx, count in enumerate(usage):
            weapon_id = int(idx)
            if weapon_id == WeaponId.NONE:
                continue
            count = int(count)
            weapon = WEAPON_BY_ID.get(weapon_id)
            name = weapon.name if weapon is not None and weapon.name else f"weapon_{weapon_id}"
            items.append((weapon_id, count, name))

        items.sort(key=lambda item: (-item[1], item[0]))
        total = sum(count for _weapon_id, count, _name in items)
        max_id_width = max(2, len(str(max((weapon_id for weapon_id, _count, _name in items), default=0))))

        lines = [
            f"Weapon uses (total {total}):",
            "",
        ]
        for weapon_id, count, name in items:
            lines.append(f"{weapon_id:>{max_id_width}}  {count:>8}  {name}")
        return lines

    def _build_quest_progress_lines(self) -> list[str]:
        status = self._state.status
        completed_total = 0
        played_total = 0

        lines = [
            "Quest progress (stages 1-4):",
            "",
        ]
        for global_index in range(40):
            stage = (global_index // 10) + 1
            row = global_index % 10
            level = f"{stage}.{row + 1}"
            title = "???"
            try:
                from ...quests import quest_by_level

                quest = quest_by_level(level)
                if quest is not None:
                    title = quest.title
            except Exception:
                title = "???"

            count_index = global_index + 10
            games_idx = 1 + count_index
            completed_idx = 41 + count_index
            games = int(status.quest_play_count(games_idx))
            completed = int(status.quest_play_count(completed_idx))

            completed_total += completed
            played_total += games
            lines.append(f"{level:>4}  {completed:>3}/{games:<3}  {title}")

        lines.extend(
            [
                "",
                f"Completed: {completed_total}",
                f"Played:    {played_total}",
            ]
        )
        return lines

    def _visible_rows(self, font: SmallFontData, layout: dict[str, float]) -> int:
        scale = float(layout["scale"])
        line_step = (float(font.cell_size) + 4.0) * scale
        line_y0 = float(layout["base_y"]) + 66.0 * scale
        panel_bottom = float(layout["panel_top"]) + (MENU_PANEL_HEIGHT * scale)
        available = max(0.0, panel_bottom - line_y0 - 8.0 * scale)
        return max(1, int(available // line_step))

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

        tabs_y = base_y + 44.0 * scale
        x = label_x
        for idx, label in enumerate(self._PAGES):
            active = idx == int(self._page_index)
            color = rl.Color(255, 255, 255, 255 if active else int(255 * 0.55))
            draw_small_text(font, label, x, tabs_y, text_scale, color)
            x += (len(label) * font.cell_size + 18.0) * scale

        lines = self._active_page_lines()
        rows = self._visible_rows(font, layout)
        start = max(0, int(self._scroll_index))
        end = min(len(lines), start + rows)

        line_y = base_y + 66.0 * scale
        line_step = (font.cell_size + 4.0) * scale
        for line in lines[start:end]:
            draw_small_text(font, line, label_x, line_y, text_scale, text_color)
            line_y += line_step
