from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.audio import update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2

from ...debug import debug_enabled
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width

from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_PLAY_GAME,
    MENU_PANEL_WIDTH,
    MenuView,
)
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView

from ..types import GameState


@dataclass(slots=True)
class _PlayGameModeEntry:
    key: str
    label: str
    tooltip: str
    action: str
    game_mode: int | None = None
    show_count: bool = False


class PlayGameMenuView(PanelMenuView):
    """Play Game mode select panel.

    Layout and gating are based on `sub_44ed80` (crimsonland.exe).
    """

    _PLAYER_COUNT_LABELS = ("1 player", "2 players", "3 players", "4 players")

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Play Game",
            panel_offset_x=-63.0,
            panel_height=278.0,
            back_pos_y=462.0,
        )
        self._small_font: SmallFontData | None = None
        self._button_sm: rl.Texture2D | None = None
        self._button_md: rl.Texture2D | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._drop_on: rl.Texture2D | None = None
        self._drop_off: rl.Texture2D | None = None

        self._player_list_open = False
        self._dirty = False

        # Hover fade timers for tooltips (0..1000ms-ish; original uses ~0.0009 alpha scale).
        self._tooltip_ms: dict[str, int] = {}
        self._mode_buttons: dict[str, UiButtonState] = {}

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        self._button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=self._button_sm, button_md=self._button_md)
        self._drop_on = cache.get_or_load("ui_dropOn", "ui/ui_dropDownOn.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._player_list_open = False
        self._dirty = False
        self._tooltip_ms.clear()
        self._mode_buttons.clear()

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)

        # Close transition (matches PanelMenuView).
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True

        entry = self._entry
        if entry is None:
            return

        enabled = self._entry_enabled(entry)
        hovered_back = enabled and self._hovered_entry(entry)
        self._hovered = hovered_back

        # ESC always goes back; Enter should not auto-back on this screen.
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered_back and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered_back:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

        if not enabled:
            return

        layout = self._content_layout()
        scale = layout["scale"]
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        drop_x = layout["drop_x"]
        drop_y = layout["drop_y"]

        consumed_click = self._update_player_count(Vec2(drop_x, drop_y), scale)
        if consumed_click:
            return

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
        button_enabled = not self._player_list_open

        y = base_y
        entries, y_step, y_start, y_end = self._mode_entries()
        y += y_start * scale
        for mode in entries:
            clicked, hovered = self._update_mode_button(
                mode,
                Vec2(base_x, y),
                scale,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
                enabled=button_enabled,
            )
            self._update_tooltip_timer(mode.key, hovered, dt_ms)
            if clicked:
                self._activate_mode(mode)
                return
            y += y_step * scale

        # Decay timers for modes that aren't visible right now.
        visible = {m.key for m in entries}
        for key in list(self._tooltip_ms):
            if key in visible:
                continue
            self._tooltip_ms[key] = max(0, self._tooltip_ms[key] - dt_ms * 2)

    def _begin_close_transition(self, action: str) -> None:
        if self._dirty:
            try:
                self._state.config.save()
            except Exception:
                pass
            self._dirty = False
        super()._begin_close_transition(action)

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
        origin_x = -(self._panel_offset_x * panel_scale)
        origin_y = -(self._panel_offset_y * panel_scale)
        panel_left = panel_x - origin_x
        panel_top = panel_y - origin_y

        # `sub_44ed80`:
        #   xy = panel_offset_x + panel_x + 330 - 64  (+ animated X offset)
        #   var_1c = panel_offset_y + panel_y + 50
        base_x = panel_left + 266.0 * panel_scale
        base_y = panel_top + 50.0 * panel_scale

        drop_x = base_x + 80.0 * panel_scale
        drop_y = base_y + 1.0 * panel_scale

        return {
            "panel_left": panel_left,
            "panel_top": panel_top,
            "scale": panel_scale,
            "base_x": base_x,
            "base_y": base_y,
            "drop_x": drop_x,
            "drop_y": drop_y,
        }

    def _quests_total_played(self) -> int:
        counts = self._state.status.data.get("quest_play_counts", [])
        if not isinstance(counts, list) or not counts:
            return 0
        # `sub_44ed80` sums 40 ints from game_status_blob+0x104..0x1a4.
        # Our `quest_play_counts` array starts at blob+0xd8, so this is indices 11..50.
        return int(sum(int(v) for v in counts[11:51]))

    def _mode_entries(self) -> tuple[list[_PlayGameModeEntry], float, float, float]:
        config = self._state.config
        status = self._state.status

        # Clamp to a valid range; older configs in the repo can contain 0 here,
        # which would incorrectly hide the Tutorial entry (it is gated on == 1).
        player_count = int(config.data.get("player_count", 1))
        if player_count < 1:
            player_count = 1
        if player_count > len(self._PLAYER_COUNT_LABELS):
            player_count = len(self._PLAYER_COUNT_LABELS)
        quest_unlock = int(status.quest_unlock_index)
        full_version = not self._state.demo_enabled

        quests_total = self._quests_total_played()
        rush_total = int(status.mode_play_count("rush"))
        survival_total = int(status.mode_play_count("survival"))
        # Matches the tutorial placement gating in `sub_44ed80` (excludes Typ-o).
        main_total = quests_total + rush_total + survival_total

        # `sub_44ed80` uses tighter spacing when quest_unlock>=40 and player_count==1.
        tight_spacing = not (quest_unlock < 0x28 or player_count > 1)
        y_step = 28.0 if tight_spacing else 32.0
        y_start = 26.0 if tight_spacing else 32.0

        has_typo = tight_spacing and full_version and player_count == 1
        show_tutorial = player_count == 1

        entries: list[_PlayGameModeEntry] = []
        if show_tutorial and main_total <= 0:
            entries.append(
                _PlayGameModeEntry(
                    key="tutorial",
                    label="Tutorial",
                    tooltip="Learn how to play Crimsonland.",
                    action="start_tutorial",
                    game_mode=8,
                )
            )

        entries.extend(
            [
                _PlayGameModeEntry(
                    key="quests",
                    label=" Quests ",
                    tooltip="Unlock new weapons and perks in Quest mode.",
                    action="open_quests",
                    show_count=True,
                ),
                _PlayGameModeEntry(
                    key="rush",
                    label="  Rush  ",
                    tooltip="Face a rush of aliens in Rush mode.",
                    action="start_rush",
                    game_mode=2,
                    show_count=True,
                ),
                _PlayGameModeEntry(
                    key="survival",
                    label="Survival",
                    tooltip="Gain perks and weapons and fight back.",
                    action="start_survival",
                    game_mode=1,
                    show_count=True,
                ),
            ]
        )

        if has_typo:
            entries.append(
                _PlayGameModeEntry(
                    key="typo",
                    label="Typ'o'Shooter",
                    tooltip="Use your typing skills as the weapon to lay\nthem down.",
                    action="start_typo",
                    game_mode=4,
                    show_count=True,
                )
            )

        if show_tutorial and main_total > 0:
            entries.append(
                _PlayGameModeEntry(
                    key="tutorial",
                    label="Tutorial",
                    tooltip="Learn how to play Crimsonland.",
                    action="start_tutorial",
                    game_mode=8,
                )
            )

        # The y after the last row is used as a tooltip anchor in `sub_44ed80`.
        y_end = y_start + y_step * float(len(entries))
        return entries, y_step, y_start, y_end

    def _mode_button_state(self, mode: _PlayGameModeEntry) -> UiButtonState:
        state = self._mode_buttons.get(mode.key)
        if state is None:
            state = UiButtonState(mode.label)
            self._mode_buttons[mode.key] = state
        else:
            state.label = mode.label
        return state

    def _update_mode_button(
        self,
        mode: _PlayGameModeEntry,
        pos: Vec2,
        scale: float,
        *,
        dt_ms: int,
        mouse: rl.Vector2,
        click: bool,
        enabled: bool,
    ) -> tuple[bool, bool]:
        state = self._mode_button_state(mode)
        state.enabled = bool(enabled)
        font = self._ensure_small_font()
        width = button_width(font, state.label, scale=scale, force_wide=state.force_wide)
        clicked = button_update(
            state, pos=Vec2(pos.x, pos.y), width=width, dt_ms=float(dt_ms), mouse=mouse, click=bool(click)
        )
        return clicked, state.hovered

    def _activate_mode(self, mode: _PlayGameModeEntry) -> None:
        if mode.game_mode is not None:
            self._state.config.data["game_mode"] = int(mode.game_mode)
            self._dirty = True
        self._begin_close_transition(mode.action)

    def _update_tooltip_timer(self, key: str, hovered: bool, dt_ms: int) -> None:
        value = int(self._tooltip_ms.get(key, 0))
        if hovered:
            value += dt_ms * 6
        else:
            value -= dt_ms * 2
        self._tooltip_ms[key] = max(0, min(1000, value))

    def _player_count_widget_layout(self, pos: Vec2, scale: float) -> dict[str, float]:
        """Return Play Game player-count dropdown metrics.

        `ui_list_widget_update` (0x43efc0):
          - width = max(label_w) + 0x30
          - header height = 16
          - open height = (count * 16) + 0x18
          - arrow icon = 16x16 at (x + width - 16 - 1, y)
          - selected label at (x + 4, y + 1)
          - list rows start at y + 17, step 16
        """
        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        x = pos.x
        y = pos.y
        max_label_w = 0.0
        for label in self._PLAYER_COUNT_LABELS:
            max_label_w = max(max_label_w, measure_small_text_width(font, label, text_scale))
        width = max_label_w + 48.0 * scale
        header_h = 16.0 * scale
        row_h = 16.0 * scale
        full_h = (float(len(self._PLAYER_COUNT_LABELS)) * 16.0 + 24.0) * scale
        arrow = 16.0 * scale
        return {
            "x": x,
            "y": y,
            "w": width,
            "header_h": header_h,
            "row_h": row_h,
            "rows_y0": y + 17.0 * scale,
            "full_h": full_h,
            "arrow_x": x + width - arrow - 1.0 * scale,
            "arrow_y": y,
            "arrow_w": arrow,
            "arrow_h": arrow,
            "text_x": x + 4.0 * scale,
            "text_y": y + 1.0 * scale,
            "text_scale": text_scale,
        }

    def _update_player_count(self, pos: Vec2, scale: float) -> bool:
        config = self._state.config
        layout = self._player_count_widget_layout(pos, scale)
        w = layout["w"]
        header_h = layout["header_h"]
        row_h = layout["row_h"]
        rows_y0 = layout["rows_y0"]
        full_h = layout["full_h"]
        x = pos.x
        y = pos.y

        mouse = rl.get_mouse_position()
        hovered_header = x <= mouse.x <= x + w and y <= mouse.y <= y + header_h
        if hovered_header and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._player_list_open = not self._player_list_open
            return True

        if not self._player_list_open:
            return False

        # Close if we click outside the dropdown + list.
        list_hovered = x <= mouse.x <= x + w and y <= mouse.y <= y + full_h
        if rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT) and not list_hovered:
            self._player_list_open = False
            return True

        for idx, label in enumerate(self._PLAYER_COUNT_LABELS):
            del label
            item_y = rows_y0 + row_h * float(idx)
            item_hovered = x <= mouse.x <= x + w and item_y <= mouse.y <= item_y + row_h
            if item_hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
                config.data["player_count"] = idx + 1
                self._dirty = True
                self._player_list_open = False
                return True
        return False

    def _draw_contents(self) -> None:
        assets = self._assets
        if assets is None:
            return
        labels_tex = assets.labels
        layout = self._content_layout()
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        drop_x = layout["drop_x"]
        drop_y = layout["drop_y"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        # `sub_44ed80`: title label at (xy - 64, var_1c - 8), size 128x32.
        title_w = 128.0
        title_h = MENU_LABEL_ROW_HEIGHT
        title_x = base_x - 64.0 * scale
        title_y = base_y - 8.0 * scale

        if labels_tex is not None:
            src = rl.Rectangle(
                0.0,
                float(MENU_LABEL_ROW_PLAY_GAME) * MENU_LABEL_ROW_HEIGHT,
                title_w,
                title_h,
            )
            dst = rl.Rectangle(
                title_x,
                title_y,
                title_w * scale,
                title_h * scale,
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
            rl.draw_text(self._title, int(title_x), int(title_y), int(24 * scale), rl.WHITE)

        entries, y_step, y_start, y_end = self._mode_entries()
        y = base_y + y_start * scale
        show_counts = debug_enabled() and rl.is_key_down(rl.KeyboardKey.KEY_F1)

        if show_counts:
            draw_small_text(
                font, "times played:", Vec2(base_x + 132.0 * scale, base_y + 16.0 * scale), text_scale, text_color
            )

        for mode in entries:
            self._draw_mode_button(mode, Vec2(base_x, y), scale)
            if show_counts and mode.show_count:
                self._draw_mode_count(mode.key, Vec2(base_x + 158.0 * scale, y + 8.0 * scale), text_scale, text_color)
            y += y_step * scale

        # `sub_44ed80`: the list widget is drawn before tooltips, so tooltips can overlay it.
        self._draw_player_count(Vec2(drop_x, drop_y), scale)
        self._draw_tooltips(entries, Vec2(base_x, base_y), y_end, scale)

    def _draw_player_count(self, pos: Vec2, scale: float) -> None:
        drop_on = self._drop_on
        drop_off = self._drop_off
        font = self._ensure_small_font()
        layout = self._player_count_widget_layout(pos, scale)
        w = layout["w"]
        header_h = layout["header_h"]
        row_h = layout["row_h"]
        rows_y0 = layout["rows_y0"]
        full_h = layout["full_h"]
        arrow_x = layout["arrow_x"]
        arrow_y = layout["arrow_y"]
        arrow_w = layout["arrow_w"]
        arrow_h = layout["arrow_h"]
        text_x = layout["text_x"]
        text_y = layout["text_y"]
        text_scale = layout["text_scale"]
        x = pos.x
        y = pos.y

        # `ui_list_widget_update` draws a single bordered black rect for the widget.
        widget_h = full_h if self._player_list_open else header_h
        rl.draw_rectangle(int(x), int(y), int(w), int(widget_h), rl.WHITE)
        inner_w = max(0, int(w) - 2)
        inner_h = max(0, int(widget_h) - 2)
        rl.draw_rectangle(int(x) + 1, int(y) + 1, inner_w, inner_h, rl.BLACK)

        # Arrow icon (the ui_drop* assets are 16x16 icons, not the background).
        mouse = rl.get_mouse_position()
        hovered_header = x <= mouse.x <= x + w and y <= mouse.y <= y + header_h
        arrow_tex = drop_on if (self._player_list_open or hovered_header) else drop_off
        if self._player_list_open or hovered_header:
            line_h = max(1, int(1.0 * scale))
            rl.draw_rectangle(int(x), int(y + 15.0 * scale), int(w), line_h, rl.Color(255, 255, 255, 128))
        if arrow_tex is not None:
            rl.draw_texture_pro(
                arrow_tex,
                rl.Rectangle(0.0, 0.0, float(arrow_tex.width), float(arrow_tex.height)),
                rl.Rectangle(arrow_x, arrow_y, arrow_w, arrow_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )

        player_count = int(self._state.config.data.get("player_count", 1))
        if player_count < 1:
            player_count = 1
        if player_count > len(self._PLAYER_COUNT_LABELS):
            player_count = len(self._PLAYER_COUNT_LABELS)
        label = self._PLAYER_COUNT_LABELS[player_count - 1]
        header_alpha = 242 if hovered_header else 191  # 0x3f733333 / 0x3f400000
        draw_small_text(font, label, Vec2(text_x, text_y), text_scale, rl.Color(255, 255, 255, header_alpha))

        if not self._player_list_open:
            return

        for idx, item in enumerate(self._PLAYER_COUNT_LABELS):
            item_y = rows_y0 + row_h * float(idx)
            hovered = x <= mouse.x <= x + w and item_y <= mouse.y <= item_y + row_h
            alpha = 153  # 0x3f19999a
            if hovered:
                alpha = 242  # 0x3f733333
            if idx == (player_count - 1):
                alpha = max(alpha, 245)  # 0x3f75c28f
            draw_small_text(font, item, Vec2(text_x, item_y), text_scale, rl.Color(255, 255, 255, alpha))

    def _draw_mode_button(self, mode: _PlayGameModeEntry, pos: Vec2, scale: float) -> None:
        textures = self._button_textures
        if textures is None:
            return
        if textures.button_sm is None and textures.button_md is None:
            return
        font = self._ensure_small_font()
        state = self._mode_button_state(mode)
        width = button_width(font, state.label, scale=scale, force_wide=state.force_wide)
        button_draw(textures, font, state, pos=Vec2(pos.x, pos.y), width=width, scale=scale)

    def _draw_mode_count(self, key: str, pos: Vec2, scale: float, color: rl.Color) -> None:
        status = self._state.status
        if key == "quests":
            count = self._quests_total_played()
        elif key == "rush":
            count = int(status.mode_play_count("rush"))
        elif key == "survival":
            count = int(status.mode_play_count("survival"))
        elif key == "typo":
            count = int(status.mode_play_count("typo"))
        else:
            return
        draw_small_text(self._ensure_small_font(), f"{count}", Vec2(pos.x, pos.y), scale, color)

    def _draw_tooltips(self, entries: list[_PlayGameModeEntry], base_pos: Vec2, y_end: float, scale: float) -> None:
        # `sub_44ed80` draws these below the mode list based on per-button hover timers.
        font = self._ensure_small_font()
        tooltip_x = base_pos.x - 55.0 * scale
        tooltip_y = base_pos.y + (y_end + 16.0) * scale

        offsets = {
            "quests": (-8.0, 0.0),
            "rush": (32.0, 0.0),
            "survival": (20.0, 0.0),
            "typo": (0.0, -12.0),
            "tutorial": (38.0, 0.0),
        }

        for mode in entries:
            ms = int(self._tooltip_ms.get(mode.key, 0))
            if ms <= 0:
                continue
            alpha_f = min(1.0, float(ms) * 0.0009)
            alpha = int(255 * alpha_f)
            off_x, off_y = offsets.get(mode.key, (0.0, 0.0))
            x = tooltip_x + off_x * scale
            y = tooltip_y + off_y * scale
            for line in mode.tooltip.splitlines():
                draw_small_text(font, line, Vec2(x, y), 1.0 * scale, rl.Color(255, 255, 255, alpha))
                y += font.cell_size * 1.0 * scale
