from __future__ import annotations

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.view import ViewContext

from ..gameplay import GameplayState, PlayerState, perk_selection_current_choices, perk_selection_pick, survival_check_level_up
from ..perks import PERK_BY_ID, PerkId
from .registry import register_view

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_PANEL_BG = rl.Color(20, 20, 24, 245)
UI_PANEL_BORDER = rl.Color(80, 80, 95, 255)
UI_PANEL_OVERLAY = rl.Color(0, 0, 0, 160)
UI_PANEL_HILITE = rl.Color(250, 210, 120, 255)
UI_PANEL_ITEM_BG = rl.Color(60, 60, 70, 255)
UI_PANEL_ITEM_HOVER = rl.Color(90, 90, 110, 255)
UI_PROMPT_BG = rl.Color(40, 40, 55, 200)
UI_PROMPT_HOVER = rl.Color(70, 70, 90, 230)

GAME_MODE_SURVIVAL = 3


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


class PerkSelectionView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self.close_requested = False

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
        self._game_mode = GAME_MODE_SURVIVAL
        self._player_count = 1

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_menu_open = False
        self._perk_menu_selected = 0

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _ui_text_width(self, text: str, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(measure_small_text_width(self._small, text, scale))
        return int(rl.measure_text(text, int(20 * scale)))

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

    def _wrap_ui_text(self, text: str, *, max_width: float, scale: float = UI_TEXT_SCALE) -> list[str]:
        lines: list[str] = []
        for raw in text.splitlines() or [""]:
            para = raw.strip()
            if not para:
                lines.append("")
                continue
            current = ""
            for word in para.split():
                candidate = word if not current else f"{current} {word}"
                if current and self._ui_text_width(candidate, scale) > max_width:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
        return lines

    def _reset(self) -> None:
        self._state = GameplayState()
        self._state.rng.srand(0xBEEF)
        self._player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
        self._game_mode = GAME_MODE_SURVIVAL
        self._player_count = 1
        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_menu_open = False
        self._perk_menu_selected = 0

    def open(self) -> None:
        self.close_requested = False
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None
        self._reset()

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _perk_prompt_label(self) -> str:
        pending = int(self._state.perk_selection.pending_count)
        if pending <= 0:
            return ""
        suffix = f" ({pending})" if pending > 1 else ""
        return f"Press P to pick a perk{suffix}"

    def _perk_prompt_rect(self, label: str, *, scale: float = UI_TEXT_SCALE) -> rl.Rectangle:
        margin = 18.0
        pad_x = 12.0
        pad_y = 8.0
        line_h = float(self._ui_line_height(scale))
        text_w = float(self._ui_text_width(label, scale))
        w = text_w + pad_x * 2.0
        h = line_h + pad_y * 2.0
        x = float(rl.get_screen_width()) - margin - w
        y = margin
        return rl.Rectangle(x, y, w, h)

    def _open_perk_menu(self) -> None:
        perk_state = self._state.perk_selection
        if int(perk_state.pending_count) <= 0:
            perk_state.pending_count = 1
            perk_state.choices_dirty = True
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=self._game_mode,
            player_count=self._player_count,
        )
        if not choices:
            return
        self._perk_menu_open = True
        self._perk_menu_selected = 0

    def _perk_menu_layout(self, *, choice_count: int) -> tuple[rl.Rectangle, list[rl.Rectangle], rl.Rectangle, rl.Rectangle, rl.Rectangle]:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        margin = 36.0
        line_h = float(self._ui_line_height())

        header_h = line_h + 30.0
        footer_h = line_h + 34.0
        item_h = line_h + 10.0
        content_h = max(200.0, float(choice_count) * item_h + 8.0)
        panel_w = min(860.0, screen_w - margin * 2.0)
        panel_h = min(header_h + content_h + footer_h, screen_h - margin * 2.0)
        panel_x = (screen_w - panel_w) * 0.5
        panel_y = (screen_h - panel_h) * 0.5
        panel = rl.Rectangle(panel_x, panel_y, panel_w, panel_h)

        padding = 18.0
        gutter = 18.0
        list_w = panel_w * 0.42
        list_x = panel_x + padding
        list_y = panel_y + header_h
        list_rects: list[rl.Rectangle] = [
            rl.Rectangle(list_x, list_y + float(idx) * item_h, list_w, item_h - 2.0)
            for idx in range(choice_count)
        ]
        desc_x = list_x + list_w + gutter
        desc_y = list_y
        desc_w = panel_x + panel_w - desc_x - padding
        desc_h = panel_h - header_h - footer_h
        desc_rect = rl.Rectangle(desc_x, desc_y, desc_w, desc_h)

        button_w = 128.0
        button_h = line_h + 14.0
        button_y = panel_y + panel_h - footer_h + (footer_h - button_h) * 0.5
        select_rect = rl.Rectangle(panel_x + panel_w - padding - button_w, button_y, button_w, button_h)
        cancel_rect = rl.Rectangle(select_rect.x - 12.0 - button_w, button_y, button_w, button_h)
        return panel, list_rects, desc_rect, cancel_rect, select_rect

    def _perk_menu_handle_input(self) -> None:
        perk_state = self._state.perk_selection
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=self._game_mode,
            player_count=self._player_count,
        )
        if not choices:
            self._perk_menu_open = False
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._perk_menu_selected = (self._perk_menu_selected + 1) % len(choices)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._perk_menu_selected = (self._perk_menu_selected - 1) % len(choices)

        mouse = rl.get_mouse_position()
        _, item_rects, _desc_rect, cancel_rect, select_rect = self._perk_menu_layout(choice_count=len(choices))
        for idx, rect in enumerate(item_rects):
            if rl.check_collision_point_rec(mouse, rect):
                self._perk_menu_selected = idx
                if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                    perk_selection_pick(
                        self._state,
                        [self._player],
                        perk_state,
                        idx,
                        game_mode=self._game_mode,
                        player_count=self._player_count,
                    )
                    self._perk_menu_open = False
                    return
                break

        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            if rl.check_collision_point_rec(mouse, cancel_rect):
                self._perk_menu_open = False
                return
            if rl.check_collision_point_rec(mouse, select_rect):
                perk_selection_pick(
                    self._state,
                    [self._player],
                    perk_state,
                    self._perk_menu_selected,
                    game_mode=self._game_mode,
                    player_count=self._player_count,
                )
                self._perk_menu_open = False
                return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            perk_selection_pick(
                self._state,
                [self._player],
                perk_state,
                self._perk_menu_selected,
                game_mode=self._game_mode,
                player_count=self._player_count,
            )
            self._perk_menu_open = False

    def _toggle_perk(self, perk_id: PerkId) -> None:
        idx = int(perk_id)
        value = int(self._player.perk_counts[idx])
        self._player.perk_counts[idx] = 0 if value > 0 else 1
        self._state.perk_selection.choices_dirty = True

    def update(self, dt: float) -> None:
        if self._perk_menu_open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._perk_menu_open = False
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._reset()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._player_count = 1
            self._state.perk_selection.choices_dirty = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._player_count = 2
            self._state.perk_selection.choices_dirty = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_G):
            self._game_mode = GAME_MODE_SURVIVAL if self._game_mode != GAME_MODE_SURVIVAL else 1
            self._state.perk_selection.choices_dirty = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._state.perk_selection.pending_count = max(0, int(self._state.perk_selection.pending_count) - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._state.perk_selection.pending_count += 1

        if rl.is_key_pressed(rl.KeyboardKey.KEY_C):
            self._state.perk_selection.choices_dirty = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_E):
            self._toggle_perk(PerkId.PERK_EXPERT)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
            if self._player.perk_counts[int(PerkId.PERK_MASTER)] > 0:
                self._player.perk_counts[int(PerkId.PERK_MASTER)] = 0
            else:
                self._player.perk_counts[int(PerkId.PERK_EXPERT)] = max(1, int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]))
                self._player.perk_counts[int(PerkId.PERK_MASTER)] = 1
            self._state.perk_selection.choices_dirty = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_X):
            self._player.experience += 5000
            survival_check_level_up(self._player, self._state.perk_selection)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._player.health = 100.0

        perk_pending = int(self._state.perk_selection.pending_count) > 0
        if self._perk_menu_open:
            self._perk_menu_handle_input()
            dt = 0.0

        if (not self._perk_menu_open) and perk_pending:
            label = self._perk_prompt_label()
            if label:
                rect = self._perk_prompt_rect(label)
                mouse = rl.get_mouse_position()
                self._perk_prompt_hover = rl.check_collision_point_rec(mouse, rect)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_P) or (
                self._perk_prompt_hover and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            ):
                self._open_perk_menu()
                dt = 0.0
        else:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
                self._open_perk_menu()

        dt_ms = dt * 1000.0
        if perk_pending and not self._perk_menu_open:
            self._perk_prompt_timer_ms = _clamp(self._perk_prompt_timer_ms + dt_ms, 0.0, 200.0)
        else:
            self._perk_prompt_timer_ms = _clamp(self._perk_prompt_timer_ms - dt_ms, 0.0, 200.0)

    def _draw_perk_prompt(self) -> None:
        if self._perk_menu_open:
            return
        pending = int(self._state.perk_selection.pending_count)
        if pending <= 0:
            return
        label = self._perk_prompt_label()
        if not label:
            return

        alpha = float(self._perk_prompt_timer_ms) / 200.0
        if alpha <= 1e-3:
            return

        scale = 0.95
        rect = self._perk_prompt_rect(label, scale=scale)
        bg = UI_PROMPT_HOVER if self._perk_prompt_hover else UI_PROMPT_BG
        rl.draw_rectangle_rounded(rect, 0.2, 6, rl.Color(bg.r, bg.g, bg.b, int(bg.a * alpha)))
        rl.draw_rectangle_rounded_lines_ex(
            rect,
            0.2,
            6,
            1.2,
            rl.Color(UI_PANEL_BORDER.r, UI_PANEL_BORDER.g, UI_PANEL_BORDER.b, int(255 * alpha)),
        )
        pad_x = 12.0
        pad_y = 8.0
        self._draw_ui_text(
            label,
            rect.x + pad_x,
            rect.y + pad_y,
            rl.Color(UI_TEXT_COLOR.r, UI_TEXT_COLOR.g, UI_TEXT_COLOR.b, int(255 * alpha)),
            scale=scale,
        )

    def _draw_perk_menu(self) -> None:
        if not self._perk_menu_open:
            return

        perk_state = self._state.perk_selection
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=self._game_mode,
            player_count=self._player_count,
        )
        if not choices:
            self._perk_menu_open = False
            return

        screen_w = rl.get_screen_width()
        screen_h = rl.get_screen_height()
        rl.draw_rectangle(0, 0, screen_w, screen_h, UI_PANEL_OVERLAY)

        panel, item_rects, desc_rect, cancel_rect, select_rect = self._perk_menu_layout(choice_count=len(choices))
        rl.draw_rectangle_rounded(panel, 0.06, 8, UI_PANEL_BG)
        rl.draw_rectangle_rounded_lines_ex(panel, 0.06, 8, 2.0, UI_PANEL_BORDER)

        header_x = panel.x + 18.0
        header_y = panel.y + 14.0
        self._draw_ui_text("PICK A PERK", header_x, header_y, UI_PANEL_HILITE, scale=1.2)

        pending = int(perk_state.pending_count)
        hint = f"pending: {pending}" if pending != 1 else "pending: 1"
        hint_w = float(self._ui_text_width(hint, 0.9))
        self._draw_ui_text(hint, panel.x + panel.width - 18.0 - hint_w, header_y + 4.0, UI_HINT_COLOR, scale=0.9)

        mouse = rl.get_mouse_position()
        hover_index: int | None = None
        for idx, perk_id in enumerate(choices):
            rect = item_rects[idx]
            is_hover = rl.check_collision_point_rec(mouse, rect)
            if is_hover:
                hover_index = idx
            is_selected = idx == self._perk_menu_selected
            bg = UI_PANEL_ITEM_HOVER if is_hover or is_selected else UI_PANEL_ITEM_BG
            rl.draw_rectangle_rounded(rect, 0.2, 6, bg)
            if is_selected:
                rl.draw_rectangle_rounded_lines_ex(rect, 0.2, 6, 1.5, UI_PANEL_HILITE)
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            self._draw_ui_text(label, rect.x + 10.0, rect.y + 6.0, UI_TEXT_COLOR)

        if hover_index is not None:
            self._perk_menu_selected = hover_index

        selected = choices[self._perk_menu_selected]
        meta = PERK_BY_ID.get(int(selected))
        desc = meta.description if meta is not None else "Unknown perk."
        desc_lines = self._wrap_ui_text(desc, max_width=desc_rect.width - 12.0, scale=0.9)
        desc_y = desc_rect.y + 6.0
        line_h = float(self._ui_line_height(0.9))
        for line in desc_lines:
            if desc_y + line_h > desc_rect.y + desc_rect.height:
                break
            self._draw_ui_text(line, desc_rect.x + 6.0, desc_y, UI_TEXT_COLOR, scale=0.9)
            desc_y += line_h

        button_scale = 0.95
        cancel_hover = rl.check_collision_point_rec(mouse, cancel_rect)
        select_hover = rl.check_collision_point_rec(mouse, select_rect)
        for rect, label, hover in (
            (cancel_rect, "Cancel", cancel_hover),
            (select_rect, "Select", select_hover),
        ):
            bg = UI_PANEL_ITEM_HOVER if hover else UI_PANEL_ITEM_BG
            rl.draw_rectangle_rounded(rect, 0.2, 6, bg)
            rl.draw_rectangle_rounded_lines_ex(rect, 0.2, 6, 1.5, UI_PANEL_BORDER)
            text_w = float(self._ui_text_width(label, button_scale))
            text_x = rect.x + (rect.width - text_w) * 0.5
            text_y = rect.y + (rect.height - float(self._ui_line_height(button_scale))) * 0.5
            self._draw_ui_text(label, text_x, text_y, UI_TEXT_COLOR, scale=button_scale)

        footer = "Enter/Click: select   Esc: cancel   Up/Down: navigate"
        footer_w = float(self._ui_text_width(footer, 0.85))
        footer_x = panel.x + (panel.width - footer_w) * 0.5
        footer_y = panel.y + panel.height - float(self._ui_line_height(0.85)) - 8.0
        self._draw_ui_text(footer, footer_x, footer_y, UI_HINT_COLOR, scale=0.85)

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))

        x = 24.0
        y = 24.0
        line = float(self._ui_line_height())
        self._draw_ui_text("Perk selection (debug)", x, y, UI_TEXT_COLOR, scale=1.2)
        y += line * 1.4

        if self._missing_assets:
            self._draw_ui_text("Missing assets: " + ", ".join(self._missing_assets), x, y, UI_ERROR_COLOR)
            y += line

        perk_state = self._state.perk_selection
        self._draw_ui_text(
            f"mode={self._game_mode}  players={self._player_count}  pending={int(perk_state.pending_count)}  level={self._player.level}  xp={self._player.experience}  hp={self._player.health:.1f}",
            x,
            y,
            UI_HINT_COLOR,
        )
        y += line
        self._draw_ui_text(
            "P: open   [/]: pending -/+   C: reroll choices   X: +5000xp   E: toggle Perk Expert   M: toggle Perk Master   1/2: player count   G: toggle mode   R: reset   Esc: quit",
            x,
            y,
            UI_HINT_COLOR,
            scale=0.85,
        )
        y += line * 1.2

        owned = [
            (meta.name, int(self._player.perk_counts[int(meta.perk_id)]))
            for meta in PERK_BY_ID.values()
            if int(self._player.perk_counts[int(meta.perk_id)]) > 0 and meta.perk_id != PerkId.ANTIPERK
        ]
        if owned:
            self._draw_ui_text("Owned perks:", x, y, UI_PANEL_HILITE)
            y += line
            for name, count in owned[:18]:
                self._draw_ui_text(f"- {name} x{count}", x, y, UI_TEXT_COLOR, scale=0.95)
                y += line * 0.95
        else:
            self._draw_ui_text("Owned perks: none", x, y, UI_HINT_COLOR)

        self._draw_perk_prompt()
        self._draw_perk_menu()


@register_view("perks", "Perk selection (debug)")
def _create_perk_selection_view(*, ctx: ViewContext) -> PerkSelectionView:
    return PerkSelectionView(ctx)
