from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pyray as rl

from grim.audio import set_music_volume, set_sfx_volume
from grim.config import apply_detail_preset
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_WIDTH,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuView,
    _draw_menu_cursor,
)
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView

if TYPE_CHECKING:
    from ...game import GameState


@dataclass(slots=True)
class SliderState:
    value: int
    min_value: int
    max_value: int


class OptionsMenuView(PanelMenuView):
    _LABELS = (
        "Sound volume:",
        "Music volume:",
        "Graphics detail:",
        "Mouse sensitivity:",
    )

    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Options")
        self._small_font: SmallFontData | None = None
        self._rect_on: rl.Texture2D | None = None
        self._rect_off: rl.Texture2D | None = None
        self._check_on: rl.Texture2D | None = None
        self._check_off: rl.Texture2D | None = None
        self._button_tex: rl.Texture2D | None = None
        self._slider_sfx = SliderState(10, 0, 10)
        self._slider_music = SliderState(10, 0, 10)
        self._slider_detail = SliderState(5, 1, 5)
        self._slider_mouse = SliderState(10, 1, 10)
        self._ui_info_texts = True
        self._active_slider: str | None = None
        self._dirty = False

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        self._rect_on = cache.get_or_load("ui_rectOn", "ui/ui_rectOn.jaz").texture
        self._rect_off = cache.get_or_load("ui_rectOff", "ui/ui_rectOff.jaz").texture
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._check_off = cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture
        self._button_tex = cache.get_or_load("ui_button_md", "ui/ui_button_145x32.jaz").texture
        self._active_slider = None
        self._dirty = False
        self._sync_from_config()

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return
        entry = self._entry
        if entry is None or not self._entry_enabled(entry):
            return

        config = self._state.config
        layout = self._content_layout()
        label_x = layout["label_x"]
        base_y = layout["base_y"]
        scale = layout["scale"]
        slider_x = layout["slider_x"]

        rect_on = self._rect_on
        rect_off = self._rect_off
        if rect_on is None or rect_off is None:
            return

        if self._update_slider("sfx", self._slider_sfx, slider_x, base_y + 47.0 * scale, rect_on, rect_off, scale):
            config.data["sfx_volume"] = float(self._slider_sfx.value) * 0.1
            set_sfx_volume(self._state.audio, float(config.data["sfx_volume"]))
            self._dirty = True

        if self._update_slider("music", self._slider_music, slider_x, base_y + 67.0 * scale, rect_on, rect_off, scale):
            config.data["music_volume"] = float(self._slider_music.value) * 0.1
            set_music_volume(self._state.audio, float(config.data["music_volume"]))
            self._dirty = True

        if self._update_slider("detail", self._slider_detail, slider_x, base_y + 87.0 * scale, rect_on, rect_off, scale):
            preset = apply_detail_preset(config, self._slider_detail.value)
            self._slider_detail.value = preset
            self._dirty = True

        if self._update_slider("mouse", self._slider_mouse, slider_x, base_y + 107.0 * scale, rect_on, rect_off, scale):
            sensitivity = float(self._slider_mouse.value) * 0.1
            if sensitivity < 0.1:
                sensitivity = 0.1
            if sensitivity > 1.0:
                sensitivity = 1.0
            config.data["mouse_sensitivity"] = sensitivity
            self._dirty = True

        if self._update_checkbox(label_x, base_y + 135.0 * scale, scale):
            value = 1 if self._ui_info_texts else 0
            config.data["ui_info_texts"] = value
            self._dirty = True

        if self._update_controls_button(label_x - 8.0 * scale, base_y + 155.0 * scale, scale):
            self._begin_close_transition("open_controls")

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
        self._draw_options_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

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

    def _sync_from_config(self) -> None:
        config = self._state.config
        self._ui_info_texts = bool(int(config.data.get("ui_info_texts", 1) or 0))

        sfx_volume = float(config.data.get("sfx_volume", 1.0))
        music_volume = float(config.data.get("music_volume", 1.0))
        detail_preset = int(config.data.get("detail_preset", 5))
        mouse_sensitivity = float(config.data.get("mouse_sensitivity", 1.0))

        self._slider_sfx.value = max(self._slider_sfx.min_value, min(self._slider_sfx.max_value, int(sfx_volume * 10.0)))
        self._slider_music.value = max(
            self._slider_music.min_value, min(self._slider_music.max_value, int(music_volume * 10.0))
        )
        if detail_preset < self._slider_detail.min_value:
            detail_preset = self._slider_detail.min_value
        if detail_preset > self._slider_detail.max_value:
            detail_preset = self._slider_detail.max_value
        self._slider_detail.value = detail_preset
        self._slider_mouse.value = max(
            self._slider_mouse.min_value,
            min(self._slider_mouse.max_value, int(mouse_sensitivity * 10.0 + 0.5)),
        )

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
        slider_x = label_x + 130.0 * panel_scale
        return {
            "panel_left": panel_left,
            "panel_top": panel_top,
            "base_x": base_x,
            "base_y": base_y,
            "label_x": label_x,
            "slider_x": slider_x,
            "scale": panel_scale,
        }

    def _update_slider(
        self,
        slider_id: str,
        slider: SliderState,
        x: float,
        y: float,
        rect_on: rl.Texture2D,
        rect_off: rl.Texture2D,
        scale: float,
    ) -> bool:
        rect_w = float(rect_on.width) * scale
        rect_h = float(rect_on.height) * scale
        if rect_w <= 0.0 or rect_h <= 0.0:
            return False
        bar_w = rect_w * float(slider.max_value)
        bar_h = rect_h
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + bar_w and y <= mouse.y <= y + bar_h

        changed = False
        if hovered:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
                slider.value = max(slider.min_value, slider.value - 1)
                changed = True
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
                slider.value = min(slider.max_value, slider.value + 1)
                changed = True

        mouse_down = rl.is_mouse_button_down(rl.MOUSE_BUTTON_LEFT)
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._active_slider = slider_id
        if self._active_slider == slider_id and mouse_down:
            relative = float(mouse.x) - x
            idx = int(relative // rect_w) + 1
            if idx < slider.min_value:
                idx = slider.min_value
            if idx > slider.max_value:
                idx = slider.max_value
            if slider.value != idx:
                slider.value = idx
                changed = True
        if self._active_slider == slider_id and not mouse_down:
            self._active_slider = None

        return changed

    def _update_checkbox(self, x: float, y: float, scale: float) -> bool:
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False
        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        label = "UI Info texts"
        label_w = measure_small_text_width(font, label, text_scale)
        rect_w = float(check_on.width) * scale + 6.0 * scale + label_w
        rect_h = max(float(check_on.height) * scale, font.cell_size * text_scale)
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + rect_w and y <= mouse.y <= y + rect_h
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._ui_info_texts = not self._ui_info_texts
            return True
        return False

    def _update_controls_button(self, x: float, y: float, scale: float) -> bool:
        tex = self._button_tex
        if tex is None:
            return False
        w = float(tex.width) * scale
        h = float(tex.height) * scale
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + w and y <= mouse.y <= y + h
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            return True
        return False

    def _draw_options_contents(self) -> None:
        assets = self._assets
        if assets is None:
            return
        labels_tex = assets.labels
        layout = self._content_layout()
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        label_x = layout["label_x"]
        slider_x = layout["slider_x"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        if labels_tex is not None:
            src = rl.Rectangle(
                0.0,
                float(MENU_LABEL_ROW_OPTIONS) * MENU_LABEL_ROW_HEIGHT,
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

        y_offsets = (47.0, 67.0, 87.0, 107.0)
        for label, offset in zip(self._LABELS, y_offsets, strict=False):
            draw_small_text(font, label, label_x, base_y + offset * scale, text_scale, text_color)

        rect_on = self._rect_on
        rect_off = self._rect_off
        if rect_on is None or rect_off is None:
            return
        rect_w = float(rect_on.width) * scale
        rect_h = float(rect_on.height) * scale

        self._draw_slider(self._slider_sfx, slider_x, base_y + 47.0 * scale, rect_on, rect_off, rect_w, rect_h)
        self._draw_slider(self._slider_music, slider_x, base_y + 67.0 * scale, rect_on, rect_off, rect_w, rect_h)
        self._draw_slider(self._slider_detail, slider_x, base_y + 87.0 * scale, rect_on, rect_off, rect_w, rect_h)
        self._draw_slider(self._slider_mouse, slider_x, base_y + 107.0 * scale, rect_on, rect_off, rect_w, rect_h)

        check_on = self._check_on
        check_off = self._check_off
        if check_on is not None and check_off is not None:
            check_tex = check_on if self._ui_info_texts else check_off
            check_w = float(check_tex.width) * scale
            check_h = float(check_tex.height) * scale
            check_x = label_x
            check_y = base_y + 135.0 * scale
            rl.draw_texture_pro(
                check_tex,
                rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
                rl.Rectangle(check_x, check_y, check_w, check_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
            draw_small_text(
                font,
                "UI Info texts",
                check_x + check_w + 6.0 * scale,
                check_y + 1.0 * scale,
                text_scale,
                text_color,
            )

        button = self._button_tex
        if button is not None:
            button_x = label_x - 8.0 * scale
            button_y = base_y + 155.0 * scale
            button_w = float(button.width) * scale
            button_h = float(button.height) * scale
            mouse = rl.get_mouse_position()
            hovered = button_x <= mouse.x <= button_x + button_w and button_y <= mouse.y <= button_y + button_h
            alpha = 255 if hovered else 220
            rl.draw_texture_pro(
                button,
                rl.Rectangle(0.0, 0.0, float(button.width), float(button.height)),
                rl.Rectangle(button_x, button_y, button_w, button_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, alpha),
            )
            label = "Controls"
            label_w = measure_small_text_width(font, label, text_scale)
            text_x = button_x + (button_w - label_w) * 0.5
            text_y = button_y + (button_h - font.cell_size * text_scale) * 0.5
            draw_small_text(font, label, text_x, text_y, text_scale, rl.Color(20, 20, 20, 255))

    def _draw_slider(
        self,
        slider: SliderState,
        x: float,
        y: float,
        rect_on: rl.Texture2D,
        rect_off: rl.Texture2D,
        rect_w: float,
        rect_h: float,
    ) -> None:
        for idx in range(slider.max_value):
            tex = rect_on if idx < slider.value else rect_off
            dst = rl.Rectangle(x + float(idx) * rect_w, y, rect_w, rect_h)
            tint = rl.WHITE if idx < slider.value else rl.Color(255, 255, 255, int(255 * 0.5))
            rl.draw_texture_pro(
                tex,
                rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height)),
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                tint,
            )
