from __future__ import annotations

import msgspec

from crimson.screens.actions import Route, ScreenAction
from grim.assets import TextureId
from grim.audio import set_music_volume, set_sfx_volume
from grim.config import apply_detail_preset
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_OPTIONS,
    MENU_PANEL_WIDTH,
    MenuView,
    _draw_menu_cursor,
)
from ..transitions import _draw_screen_fade
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from .hit_test import mouse_inside_rect_with_padding


class SliderState(msgspec.Struct):
    value: int
    min_value: int
    max_value: int


class _OptionsContentLayout(msgspec.Struct, frozen=True):
    scale: float
    base_pos: Vec2
    label_pos: Vec2
    slider_pos: Vec2


class OptionsMenuView(PanelMenuView):
    _LABELS = (
        "Sound volume:",
        "Music volume:",
        "Graphics detail:",
        "Mouse sensitivity:",
    )

    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Options", back_action=Route.BACK)
        self._controls_button: UiButtonState = UiButtonState("Controls", force_wide=True)
        self._slider_sfx = SliderState(10, 0, 10)
        self._slider_music = SliderState(10, 0, 10)
        self._slider_detail = SliderState(5, 1, 5)
        self._slider_mouse = SliderState(10, 1, 10)
        self._ui_info_texts = True
        self._active_slider: str | None = None
        self._dirty = False

    def open(self) -> None:
        super().open()
        self._controls_button = UiButtonState("Controls", force_wide=True)
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

        config = self.state.config
        layout = self._content_layout()
        base_pos = layout.base_pos
        label_pos = layout.label_pos
        slider_pos = layout.slider_pos
        scale = layout.scale

        resources = require_runtime_resources(self.state)
        rect_on = resources.texture(TextureId.UI_RECT_ON)
        rect_off = resources.texture(TextureId.UI_RECT_OFF)

        if self._update_slider("sfx", self._slider_sfx, slider_pos.offset(dy=47.0 * scale), rect_on, rect_off, scale):
            config.audio.sfx_volume = float(self._slider_sfx.value) * 0.1
            set_sfx_volume(self.state.audio, config.audio.sfx_volume)
            self._dirty = True

        if self._update_slider(
            "music",
            self._slider_music,
            slider_pos.offset(dy=67.0 * scale),
            rect_on,
            rect_off,
            scale,
        ):
            config.audio.music_volume = float(self._slider_music.value) * 0.1
            set_music_volume(self.state.audio, config.audio.music_volume)
            self._dirty = True

        if self._update_slider(
            "detail",
            self._slider_detail,
            slider_pos.offset(dy=87.0 * scale),
            rect_on,
            rect_off,
            scale,
        ):
            preset = apply_detail_preset(config, self._slider_detail.value)
            self._slider_detail.value = preset
            self._dirty = True

        if self._update_slider(
            "mouse",
            self._slider_mouse,
            slider_pos.offset(dy=107.0 * scale),
            rect_on,
            rect_off,
            scale,
        ):
            sensitivity = float(self._slider_mouse.value) * 0.1
            if sensitivity < 0.1:
                sensitivity = 0.1
            if sensitivity > 1.0:
                sensitivity = 1.0
            config.display.mouse_sensitivity = sensitivity
            self._dirty = True

        if self._update_checkbox(label_pos.offset(dy=135.0 * scale), scale):
            config.gameplay.show_info_texts = self._ui_info_texts
            self._dirty = True

        # `options_menu_update`: controls button is aligned with the panel content base.
        controls_pos = base_pos.offset(dy=155.0 * scale)
        dt_ms = min(float(dt), 0.1) * 1000.0
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        resources = require_runtime_resources(self.state)
        width = button_width(
            resources,
            self._controls_button.label,
            scale=scale,
            force_wide=self._controls_button.force_wide,
        )
        if button_update(
            self._controls_button,
            pos=controls_pos,
            width=width,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._begin_close_transition(Route.CONTROLS)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        _draw_screen_fade(self.state)
        entry = self._entry
        assert entry is not None, "OptionsMenuView entry must be initialized before draw()"
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_options_contents()
        _draw_menu_cursor(
            self.state,
            resources=require_runtime_resources(self.state),
            pulse_time=self._cursor_pulse_time,
        )

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self._dirty:
            try:
                self.state.config.save()
            except (OSError, ValueError) as exc:
                self.state.console.log.log(f"config: save failed: {exc}")
            else:
                self._dirty = False
        super()._begin_close_transition(action)

    def _sync_from_config(self) -> None:
        config = self.state.config
        self._ui_info_texts = config.gameplay.show_info_texts

        sfx_volume = config.audio.sfx_volume
        music_volume = config.audio.music_volume
        detail_preset = config.display.detail_preset
        mouse_sensitivity = config.display.mouse_sensitivity

        self._slider_sfx.value = max(
            self._slider_sfx.min_value,
            min(self._slider_sfx.max_value, int(sfx_volume * 10.0)),
        )
        self._slider_music.value = max(
            self._slider_music.min_value,
            min(self._slider_music.max_value, int(music_volume * 10.0)),
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

    def _content_layout(self) -> _OptionsContentLayout:
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
        base_pos = panel_top_left + Vec2(212.0 * panel_scale, 40.0 * panel_scale)
        # `options_menu_update`: title label is anchored at panel_top + 40.
        label_pos = base_pos.offset(dx=8.0 * panel_scale)
        slider_pos = label_pos.offset(dx=130.0 * panel_scale)
        return _OptionsContentLayout(
            base_pos=base_pos,
            label_pos=label_pos,
            slider_pos=slider_pos,
            scale=panel_scale,
        )

    def _update_slider(
        self,
        slider_id: str,
        slider: SliderState,
        pos: Vec2,
        rect_on: rl.Texture,
        rect_off: rl.Texture,
        scale: float,
    ) -> bool:
        rect_w = float(rect_on.width) * scale
        rect_h = float(rect_on.height) * scale
        if rect_w <= 0.0 or rect_h <= 0.0:
            return False
        bar_w = rect_w * float(slider.max_value)
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        hovered = mouse_inside_rect_with_padding(
            mouse_pos,
            pos=pos,
            width=bar_w,
            height=18.0 * scale,
            left_pad=3.0 * scale,
            top_pad=1.0 * scale,
        )

        changed = False
        if hovered:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
                slider.value = max(slider.min_value, slider.value - 1)
                changed = True
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
                slider.value = min(slider.max_value, slider.value + 1)
                changed = True
        mouse_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._active_slider = slider_id
        if self._active_slider == slider_id and mouse_down:
            relative = mouse_pos.x - pos.x
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

    def _update_checkbox(self, pos: Vec2, scale: float) -> bool:
        resources = require_runtime_resources(self.state)
        check_on = resources.texture(TextureId.UI_CHECK_ON)
        font = resources.small_font
        text_scale = 1.0 * scale
        label = "UI Info texts"
        label_w = measure_small_text_width(font, label)
        rect_w = float(check_on.width) * scale + 6.0 * scale + label_w
        rect_h = max(float(check_on.height) * scale, font.cell_size * text_scale)
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        hovered = Rect.from_top_left(pos, rect_w, rect_h).contains(mouse_pos)
        if hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._ui_info_texts = not self._ui_info_texts
            return True
        return False

    def _draw_options_contents(self) -> None:
        resources = require_runtime_resources(self.state)
        labels_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        layout = self._content_layout()
        base_pos = layout.base_pos
        label_pos = layout.label_pos
        slider_pos = layout.slider_pos
        scale = layout.scale

        font = resources.small_font
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        title_w = 128.0
        src = rl.Rectangle(
            0.0,
            float(MENU_LABEL_ROW_OPTIONS) * MENU_LABEL_ROW_HEIGHT,
            title_w,
            MENU_LABEL_ROW_HEIGHT,
        )
        dst = rl.Rectangle(
            base_pos.x,
            base_pos.y,
            title_w * scale,
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

        y_offsets = (47.0, 67.0, 87.0, 107.0)
        for label, offset in zip(self._LABELS, y_offsets, strict=False):
            draw_small_text(font, label, label_pos.offset(dy=offset * scale), text_color)

        rect_on = resources.texture(TextureId.UI_RECT_ON)
        rect_off = resources.texture(TextureId.UI_RECT_OFF)
        rect_w = float(rect_on.width) * scale
        rect_h = float(rect_on.height) * scale

        self._draw_slider(
            self._slider_sfx,
            slider_pos.offset(dy=47.0 * scale),
            rect_on,
            rect_off,
            rect_w,
            rect_h,
        )
        self._draw_slider(
            self._slider_music,
            slider_pos.offset(dy=67.0 * scale),
            rect_on,
            rect_off,
            rect_w,
            rect_h,
        )
        self._draw_slider(
            self._slider_detail,
            slider_pos.offset(dy=87.0 * scale),
            rect_on,
            rect_off,
            rect_w,
            rect_h,
        )
        self._draw_slider(
            self._slider_mouse,
            slider_pos.offset(dy=107.0 * scale),
            rect_on,
            rect_off,
            rect_w,
            rect_h,
        )

        check_tex = (
            resources.texture(TextureId.UI_CHECK_ON)
            if self._ui_info_texts
            else resources.texture(TextureId.UI_CHECK_OFF)
        )
        check_w = float(check_tex.width) * scale
        check_h = float(check_tex.height) * scale
        check_pos = label_pos.offset(dy=135.0 * scale)
        rl.draw_texture_pro(
            check_tex,
            rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
            rl.Rectangle(check_pos.x, check_pos.y, check_w, check_h),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )
        draw_small_text(font, "UI Info texts", check_pos + Vec2(check_w + 6.0 * scale, 1.0 * scale), text_color)

        button_pos = base_pos.offset(dy=155.0 * scale)
        button_w = button_width(
            resources,
            self._controls_button.label,
            scale=scale,
            force_wide=self._controls_button.force_wide,
        )
        button_draw(
            resources,
            self._controls_button,
            pos=button_pos,
            width=button_w,
            scale=scale,
        )

    def _draw_slider(
        self,
        slider: SliderState,
        pos: Vec2,
        rect_on: rl.Texture,
        rect_off: rl.Texture,
        rect_w: float,
        rect_h: float,
    ) -> None:
        for idx in range(slider.max_value):
            tex = rect_on if idx < slider.value else rect_off
            dst = rl.Rectangle(pos.x + float(idx) * rect_w, pos.y, rect_w, rect_h)
            tint = rl.WHITE if idx < slider.value else rl.Color(255, 255, 255, int(255 * 0.5))
            rl.draw_texture_pro(
                tex,
                rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height)),
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                tint,
            )
