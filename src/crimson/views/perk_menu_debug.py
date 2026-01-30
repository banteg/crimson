from __future__ import annotations

import pyray as rl

from grim.fonts.small import SmallFontData, load_small_font, measure_small_text_width
from grim.view import View, ViewContext

from ..perks import PERK_BY_ID, PerkId, perk_display_description, perk_display_name
from ..ui.perk_menu import (
    PerkMenuAssets,
    PerkMenuLayout,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    cursor_draw,
    draw_menu_panel,
    draw_menu_item,
    draw_ui_text,
    load_perk_menu_assets,
    menu_item_hit_rect,
    perk_menu_compute_layout,
    ui_origin,
    ui_scale,
    wrap_ui_text,
)
from .registry import register_view


UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))

PERK_PROMPT_OUTSET_X = 50.0
PERK_PROMPT_BAR_SCALE = 0.75
PERK_PROMPT_BAR_BASE_OFFSET_X = -72.0
PERK_PROMPT_BAR_BASE_OFFSET_Y = -60.0
PERK_PROMPT_BAR_SHIFT_X = -300.0

PERK_PROMPT_LEVEL_UP_SCALE = 0.85
PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X = -230.0
PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y = -27.0
PERK_PROMPT_LEVEL_UP_BASE_W = 75.0
PERK_PROMPT_LEVEL_UP_BASE_H = 25.0
PERK_PROMPT_LEVEL_UP_SHIFT_X = -46.0
PERK_PROMPT_LEVEL_UP_SHIFT_Y = -4.0

PERK_PROMPT_TEXT_MARGIN_X = 16.0
PERK_PROMPT_TEXT_OFFSET_Y = 8.0


class PerkMenuDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._assets: PerkMenuAssets | None = None
        self._layout = PerkMenuLayout()

        self._perk_ids = [
            perk_id for perk_id in sorted(PERK_BY_ID.keys()) if perk_id != int(PerkId.ANTIPERK)
        ]
        self._choice_count = 6
        self._selected = 0
        self._expert_owned = False
        self._master_owned = False
        self._show_menu = True
        self._show_prompt = True
        self._panel_slide_x = 0.0
        self._prompt_alpha = 1.0
        self._prompt_pulse = 0.0
        self._prompt_hover = False
        self._prompt_rect: rl.Rectangle | None = None
        self._cancel_button = UiButtonState("Cancel")
        self._debug_overlay = True
        self._show_prompt_rect = False

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None
        self._assets = load_perk_menu_assets(self._assets_root)
        if self._assets.missing:
            self._missing_assets.extend(self._assets.missing)
        rl.hide_cursor()

    def close(self) -> None:
        rl.show_cursor()
        if self._assets is not None:
            self._assets.unload()
            self._assets = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _choices(self) -> list[int]:
        if not self._perk_ids:
            return []
        count = max(1, min(self._choice_count, len(self._perk_ids)))
        return self._perk_ids[:count]

    def _prompt_label(self) -> str:
        pending = max(1, int(self._choice_count))
        suffix = f" ({pending})" if pending > 1 else ""
        return f"Press Mouse2 to pick a perk{suffix}"

    @staticmethod
    def _perk_prompt_hinge() -> tuple[float, float]:
        screen_w = float(rl.get_screen_width())
        hinge_x = screen_w + PERK_PROMPT_OUTSET_X
        hinge_y = 80.0 if int(screen_w) == 640 else 40.0
        return hinge_x, hinge_y

    def _perk_prompt_rect(self, label: str) -> rl.Rectangle:
        hinge_x, hinge_y = self._perk_prompt_hinge()
        if self._assets is not None and self._assets.menu_item is not None:
            tex = self._assets.menu_item
            bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
            bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
            local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
            local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
            return rl.Rectangle(
                float(hinge_x + local_x),
                float(hinge_y + local_y),
                float(bar_w),
                float(bar_h),
            )

        text_w = float(_ui_text_width(self._small, label, 1.0))
        text_h = 20.0
        x = float(rl.get_screen_width()) - PERK_PROMPT_TEXT_MARGIN_X - text_w
        y = hinge_y + PERK_PROMPT_TEXT_OFFSET_Y
        return rl.Rectangle(x, y, text_w, text_h)

    def _draw_perk_prompt(self) -> None:
        if not self._show_prompt:
            return
        if self._assets is None:
            return
        label = self._prompt_label()
        if not label:
            return
        alpha = max(0.0, min(self._prompt_alpha, 1.0))
        if alpha <= 1e-3:
            return

        hinge_x, hinge_y = self._perk_prompt_hinge()
        rot_deg = (1.0 - alpha) * 90.0
        tint = rl.Color(255, 255, 255, int(255 * alpha))

        text_w = float(_ui_text_width(self._small, label, 1.0))
        x = float(rl.get_screen_width()) - PERK_PROMPT_TEXT_MARGIN_X - text_w
        y = hinge_y + PERK_PROMPT_TEXT_OFFSET_Y
        color = rl.Color(UI_TEXT_COLOR.r, UI_TEXT_COLOR.g, UI_TEXT_COLOR.b, int(255 * alpha))
        draw_ui_text(self._small, label, x, y, scale=1.0, color=color)

        if self._assets.menu_item is not None:
            tex = self._assets.menu_item
            bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
            bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
            local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
            local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
            src = rl.Rectangle(float(tex.width), 0.0, -float(tex.width), float(tex.height))
            dst = rl.Rectangle(float(hinge_x), float(hinge_y), float(bar_w), float(bar_h))
            origin = rl.Vector2(float(-local_x), float(-local_y))
            rl.draw_texture_pro(tex, src, dst, origin, rot_deg, tint)

        if self._assets.title_level_up is not None:
            tex = self._assets.title_level_up
            local_x = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_X
            local_y = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_Y
            w = PERK_PROMPT_LEVEL_UP_BASE_W * PERK_PROMPT_LEVEL_UP_SCALE
            h = PERK_PROMPT_LEVEL_UP_BASE_H * PERK_PROMPT_LEVEL_UP_SCALE
            pulse_alpha = (100.0 + float(int(self._prompt_pulse * 155.0 / 1000.0))) / 255.0
            pulse_alpha = max(0.0, min(1.0, pulse_alpha))
            label_alpha = max(0.0, min(1.0, alpha * pulse_alpha))
            pulse_tint = rl.Color(255, 255, 255, int(255 * label_alpha))
            src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
            dst = rl.Rectangle(float(hinge_x), float(hinge_y), float(w), float(h))
            origin = rl.Vector2(float(-local_x), float(-local_y))
            rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
            if label_alpha > 0.0:
                rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
                rl.end_blend_mode()

    def update(self, dt: float) -> None:
        dt_ms = float(min(dt, 0.1) * 1000.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_F1):
            self._debug_overlay = not self._debug_overlay
        if rl.is_key_pressed(rl.KeyboardKey.KEY_E):
            self._expert_owned = not self._expert_owned
            if not self._expert_owned:
                self._master_owned = False
        if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
            self._master_owned = not self._master_owned
            if self._master_owned:
                self._expert_owned = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_O):
            self._show_menu = not self._show_menu
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._show_prompt = not self._show_prompt
        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._show_prompt_rect = not self._show_prompt_rect
        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._panel_slide_x = 0.0
            self._choice_count = 6
            self._selected = 0
            self._expert_owned = False
            self._master_owned = False
            self._show_menu = True
            self._show_prompt = True
            self._prompt_pulse = 0.0
            self._prompt_hover = False

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._choice_count = max(1, self._choice_count - 1)
            self._selected = min(self._selected, self._choice_count - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._choice_count = min(len(self._perk_ids), self._choice_count + 1)

        if self._show_menu and self._choice_count > 0:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
                self._selected = (self._selected + 1) % self._choice_count
            if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
                self._selected = (self._selected - 1) % self._choice_count

        step = 10.0
        if rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT):
            step = 40.0
        if rl.is_key_down(rl.KeyboardKey.KEY_LEFT):
            self._panel_slide_x -= step
        if rl.is_key_down(rl.KeyboardKey.KEY_RIGHT):
            self._panel_slide_x += step

        self._panel_slide_x = _clamp(self._panel_slide_x, -self._layout.panel_w, 0.0)

        self._prompt_hover = False
        self._prompt_rect = None
        if self._show_prompt:
            label = self._prompt_label()
            if label:
                rect = self._perk_prompt_rect(label)
                self._prompt_rect = rect
                mouse = rl.get_mouse_position()
                self._prompt_hover = rl.check_collision_point_rec(mouse, rect)

        pulse_delta = dt_ms * (6.0 if self._prompt_hover else -2.0)
        self._prompt_pulse = _clamp(self._prompt_pulse + pulse_delta, 0.0, 1000.0)

        if not self._show_menu or self._assets is None:
            return

        choices = self._choices()
        if not choices:
            return
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            origin_x=origin_x,
            origin_y=origin_y,
            scale=scale,
            choice_count=len(choices),
            expert_owned=self._expert_owned,
            master_owned=self._master_owned,
            panel_slide_x=self._panel_slide_x,
        )

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        for idx, perk_id in enumerate(choices):
            label = perk_display_name(int(perk_id))
            item_x = computed.list_x
            item_y = computed.list_y + float(idx) * computed.list_step_y
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            if rl.check_collision_point_rec(mouse, rect):
                self._selected = idx
                break

        cancel_w = button_width(self._small, self._cancel_button.label, scale=scale, force_wide=self._cancel_button.force_wide)
        cancel_x = computed.cancel_x
        button_y = computed.cancel_y
        if button_update(
            self._cancel_button,
            x=cancel_x,
            y=button_y,
            width=cancel_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._show_menu = False

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
            return

        self._draw_perk_prompt()
        if self._show_prompt_rect and self._prompt_rect is not None:
            rl.draw_rectangle_lines_ex(self._prompt_rect, 1.0, rl.Color(255, 0, 255, 255))

        if self._show_menu and self._assets is not None:
            choices = self._choices()
            if choices:
                screen_w = float(rl.get_screen_width())
                screen_h = float(rl.get_screen_height())
                scale = ui_scale(screen_w, screen_h)
                origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
                computed = perk_menu_compute_layout(
                    self._layout,
                    screen_w=screen_w,
                    origin_x=origin_x,
                    origin_y=origin_y,
                    scale=scale,
                    choice_count=len(choices),
                    expert_owned=self._expert_owned,
                    master_owned=self._master_owned,
                    panel_slide_x=self._panel_slide_x,
                )

                if self._assets.menu_panel is not None:
                    draw_menu_panel(self._assets.menu_panel, dst=computed.panel)

                if self._assets.title_pick_perk is not None:
                    tex = self._assets.title_pick_perk
                    src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
                    rl.draw_texture_pro(tex, src, computed.title, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

                sponsor = None
                if self._master_owned:
                    sponsor = "extra perks sponsored by the Perk Master"
                elif self._expert_owned:
                    sponsor = "extra perk sponsored by the Perk Expert"
                if sponsor:
                    draw_ui_text(
                        self._small,
                        sponsor,
                        computed.sponsor_x,
                        computed.sponsor_y,
                        scale=scale,
                        color=UI_SPONSOR_COLOR,
                    )

                mouse = rl.get_mouse_position()
                for idx, perk_id in enumerate(choices):
                    label = perk_display_name(int(perk_id))
                    item_x = computed.list_x
                    item_y = computed.list_y + float(idx) * computed.list_step_y
                    rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
                    hovered = rl.check_collision_point_rec(mouse, rect) or (idx == self._selected)
                    draw_menu_item(self._small, label, x=item_x, y=item_y, scale=scale, hovered=hovered)

                selected_id = choices[self._selected]
                desc = perk_display_description(int(selected_id))
                desc_x = float(computed.desc.x)
                desc_y = float(computed.desc.y)
                desc_w = float(computed.desc.width)
                desc_h = float(computed.desc.height)
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
                button_draw(self._assets, self._small, self._cancel_button, x=computed.cancel_x, y=computed.cancel_y, width=cancel_w, scale=scale)

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        if self._assets is not None:
            cursor_draw(self._assets, mouse=rl.get_mouse_position(), scale=scale)

        if self._debug_overlay:
            self._draw_overlay()

    def _draw_overlay(self) -> None:
        x = 24.0
        y = 24.0
        scale = 0.9
        line_h = float(self._small.cell_size * scale) if self._small is not None else float(20 * scale)
        lines = [
            "Perk menu render debug (F1 hide)",
            "O toggle menu  P toggle prompt  H hover rect  E/M toggle Expert/Master",
            "Left/Right slide_x (hold Shift for bigger)  [/] choices  Up/Down selection  R reset",
            f"slide_x={self._panel_slide_x:.1f} choices={self._choice_count} selected={self._selected}",
        ]
        for line in lines:
            draw_ui_text(self._small, line, x, y, scale=scale, color=UI_HINT_COLOR)
            y += line_h


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _ui_text_width(font: SmallFontData | None, text: str, scale: float) -> float:
    if font is None:
        return float(rl.measure_text(text, int(20 * scale)))
    return float(measure_small_text_width(font, text, scale))


@register_view("perk-menu-debug", "Perk menu render debug")
def _create_perk_menu_debug_view(*, ctx: ViewContext) -> View:
    return PerkMenuDebugView(ctx)
