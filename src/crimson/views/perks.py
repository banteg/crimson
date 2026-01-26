from __future__ import annotations

import pyray as rl

from grim.fonts.small import SmallFontData, load_small_font, measure_small_text_width
from grim.view import ViewContext

from ..gameplay import GameplayState, PlayerState, perk_selection_current_choices, perk_selection_pick, survival_check_level_up
from ..perks import PERK_BY_ID, PerkId
from ..ui.perk_menu import (
    PerkMenuLayout,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    cursor_draw,
    draw_menu_item,
    draw_ui_text,
    load_perk_menu_assets,
    menu_item_hit_rect,
    ui_origin,
    ui_scale,
    wrap_ui_text,
)
from .registry import register_view

GAME_MODE_SURVIVAL = 3

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))


class PerkSelectionView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._small: SmallFontData | None = None
        self._missing_assets: list[str] = []
        self._ui_assets = None
        self._layout = PerkMenuLayout()

        self.close_requested = False
        self._debug_overlay = False

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
        self._game_mode = GAME_MODE_SURVIVAL
        self._player_count = 1

        self._perk_menu_open = False
        self._perk_menu_selected = 0

        self._cancel_button = UiButtonState("Cancel")

    def _ui_text_width(self, text: str, scale: float) -> float:
        if self._small is not None:
            return float(measure_small_text_width(self._small, text, scale))
        return float(rl.measure_text(text, int(20 * scale)))

    def _reset(self) -> None:
        self._state = GameplayState()
        self._state.rng.srand(0xBEEF)
        self._player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
        self._game_mode = GAME_MODE_SURVIVAL
        self._player_count = 1

        self._state.perk_selection.pending_count = 1
        self._state.perk_selection.choices_dirty = True

        self._perk_menu_open = True
        self._perk_menu_selected = 0
        self._cancel_button = UiButtonState("Cancel")

    def open(self) -> None:
        self.close_requested = False
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None
        self._ui_assets = load_perk_menu_assets(self._assets_root)
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)
        rl.hide_cursor()
        self._reset()

    def close(self) -> None:
        rl.show_cursor()
        if self._ui_assets is not None:
            self._ui_assets.unload()
            self._ui_assets = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _toggle_perk(self, perk_id: PerkId) -> None:
        idx = int(perk_id)
        value = int(self._player.perk_counts[idx])
        self._player.perk_counts[idx] = 0 if value > 0 else 1
        self._state.perk_selection.choices_dirty = True

    def update(self, dt: float) -> None:
        dt_ms = float(min(dt, 0.1) * 1000.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_F1):
            self._debug_overlay = not self._debug_overlay

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            if self._perk_menu_open:
                self._perk_menu_open = False
            else:
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

        if not self._perk_menu_open:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_P) and int(self._state.perk_selection.pending_count) > 0:
                self._perk_menu_open = True
                self._perk_menu_selected = 0
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

        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._perk_menu_selected = (self._perk_menu_selected + 1) % len(choices)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._perk_menu_selected = (self._perk_menu_selected - 1) % len(choices)

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        list_y = self._layout.list_y - (10.0 if expert_owned else 0.0)
        list_step = 18.0 if expert_owned else self._layout.list_step_y

        for idx, perk_id in enumerate(choices):
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            item_x = origin_x + self._layout.list_x * scale
            item_y = origin_y + (list_y + float(idx) * list_step) * scale
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            if rl.check_collision_point_rec(mouse, rect):
                self._perk_menu_selected = idx
                if click:
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

        cancel_w = button_width(self._small, self._cancel_button.label, scale=scale, force_wide=self._cancel_button.force_wide)
        cancel_x = origin_x + self._layout.cancel_x * scale
        button_y = origin_y + self._layout.button_y * scale

        cancel_clicked = button_update(
            self._cancel_button,
            x=cancel_x,
            y=button_y,
            width=cancel_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        )
        if cancel_clicked:
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

    def draw(self) -> None:
        rl.clear_background(rl.Color(0, 0, 0, 255))

        if self._missing_assets and self._debug_overlay:
            draw_ui_text(
                self._small,
                "Missing assets: " + ", ".join(self._missing_assets),
                24.0,
                24.0,
                scale=1.0,
                color=UI_ERROR_COLOR,
            )

        if self._perk_menu_open:
            self._draw_perk_menu()
        if self._debug_overlay:
            self._draw_debug_overlay()

    def _draw_perk_menu(self) -> None:
        if self._ui_assets is None:
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
            return

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)

        panel_tex = self._ui_assets.menu_panel
        if panel_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(panel_tex.width), float(panel_tex.height))
            dst = rl.Rectangle(
                origin_x + self._layout.panel_x * scale,
                origin_y + self._layout.panel_y * scale,
                self._layout.panel_w * scale,
                self._layout.panel_h * scale,
            )
            rl.draw_texture_pro(panel_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        title_tex = self._ui_assets.title_pick_perk
        if title_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(title_tex.width), float(title_tex.height))
            dst = rl.Rectangle(
                origin_x + self._layout.title_x * scale,
                origin_y + self._layout.title_y * scale,
                self._layout.title_w * scale,
                self._layout.title_h * scale,
            )
            rl.draw_texture_pro(title_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        master_owned = int(self._player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        sponsor = None
        if master_owned:
            sponsor = "extra perks sponsored by the Perk Master"
        elif expert_owned:
            sponsor = "extra perk sponsored by the Perk Expert"
        if sponsor:
            draw_ui_text(
                self._small,
                sponsor,
                origin_x + (self._layout.title_x - 28.0) * scale,
                origin_y + (self._layout.title_y - 8.0) * scale,
                scale=scale,
                color=UI_SPONSOR_COLOR,
            )

        list_y = self._layout.list_y - (10.0 if expert_owned else 0.0)
        list_step = 18.0 if expert_owned else self._layout.list_step_y

        mouse = rl.get_mouse_position()
        for idx, perk_id in enumerate(choices):
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            item_x = origin_x + self._layout.list_x * scale
            item_y = origin_y + (list_y + float(idx) * list_step) * scale
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            hovered = rl.check_collision_point_rec(mouse, rect) or (idx == self._perk_menu_selected)
            draw_menu_item(self._small, label, x=item_x, y=item_y, scale=scale, hovered=hovered)

        selected = choices[self._perk_menu_selected]
        meta = PERK_BY_ID.get(int(selected))
        desc = meta.description if meta is not None else "Unknown perk."
        desc_x = origin_x + self._layout.desc_x * scale
        desc_y = origin_y + self._layout.desc_y * scale
        desc_w = self._layout.desc_w * scale
        desc_h = self._layout.desc_h * scale
        desc_scale = scale * 0.85
        desc_lines = wrap_ui_text(self._small, desc, max_width=desc_w, scale=desc_scale)
        line_h = float(self._small.cell_size * desc_scale) if self._small is not None else float(20 * desc_scale)
        y = desc_y
        for line in desc_lines:
            if y + line_h > desc_y + desc_h:
                break
            draw_ui_text(self._small, line, desc_x, y, scale=desc_scale, color=UI_TEXT_COLOR)
            y += line_h

        cancel_w = button_width(self._small, self._cancel_button.label, scale=scale, force_wide=self._cancel_button.force_wide)
        cancel_x = origin_x + self._layout.cancel_x * scale
        button_y = origin_y + self._layout.button_y * scale
        button_draw(self._ui_assets, self._small, self._cancel_button, x=cancel_x, y=button_y, width=cancel_w, scale=scale)

        cursor_draw(self._ui_assets, mouse=mouse, scale=scale)

    def _draw_debug_overlay(self) -> None:
        x = 24.0
        y = 24.0
        scale = 0.9
        line_h = float(self._small.cell_size * scale) if self._small is not None else float(20 * scale)
        perk_state = self._state.perk_selection
        draw_ui_text(self._small, "Perk selection (debug overlay, F1)", x, y, scale=scale, color=UI_TEXT_COLOR)
        y += line_h
        draw_ui_text(
            self._small,
            f"mode={self._game_mode} players={self._player_count} pending={int(perk_state.pending_count)} level={self._player.level} xp={self._player.experience}",
            x,
            y,
            scale=scale,
            color=UI_HINT_COLOR,
        )
        y += line_h
        draw_ui_text(
            self._small,
            "Keys: C reroll  X +5000xp  E/M toggle Expert/Master  1/2 players  G mode  R reset  P reopen  Esc close",
            x,
            y,
            scale=scale,
            color=UI_HINT_COLOR,
        )
        y += line_h
        owned = [
            (meta.name, int(self._player.perk_counts[int(meta.perk_id)]))
            for meta in PERK_BY_ID.values()
            if int(self._player.perk_counts[int(meta.perk_id)]) > 0 and meta.perk_id != PerkId.ANTIPERK
        ]
        if owned:
            draw_ui_text(self._small, "Owned:", x, y, scale=scale, color=UI_HINT_COLOR)
            y += line_h
            for name, count in owned[:8]:
                draw_ui_text(self._small, f"- {name} x{count}", x, y, scale=scale, color=UI_HINT_COLOR)
                y += line_h


@register_view("perks", "Perk selection (debug)")
def _create_perk_selection_view(*, ctx: ViewContext) -> PerkSelectionView:
    return PerkSelectionView(ctx)
