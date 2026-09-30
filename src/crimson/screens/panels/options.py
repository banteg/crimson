from __future__ import annotations

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.actions import Route
from crimson.ui.menu_chrome import draw_ui_quad
from crimson.ui.menu_layout import MENU_LABEL_ROW_HEIGHT, MENU_LABEL_ROW_OPTIONS
from grim import canvas
from grim.assets import TextureId
from grim.config import apply_detail_preset
from grim.fonts.small import draw_small_text
from grim.geom import Vec2
from grim.music import set_music_volume
from grim.raylib_api import rl
from grim.sfx import set_sfx_volume

from ...game.types import GameState
from ...ui.button import UiButtonState, button_draw, button_update
from ...ui.checkbox import UiCheckbox, ui_checkbox_draw, ui_checkbox_update
from ...ui.slider import UiSegmentedSlider, ui_segmented_slider_draw, ui_segmented_slider_update
from ..assets import require_runtime_resources
from .base import PanelMenuView


class _OptionsContentLayout(msgspec.Struct, frozen=True):
    base_pos: Vec2
    label_pos: Vec2
    slider_pos: Vec2


class OptionsMenuView(PanelMenuView):
    # Native also has a "Mouse sensitivity:" slider at +107 for its software cursor; the port uses the OS cursor,
    # so the row is left empty and crimson.cfg keeps the value.
    _LABELS = (
        "Sound volume:",
        "Music volume:",
        "Graphics detail:",
    )

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state, game_state=GameStateId.OPTIONS_MENU, panel_element=31, back_element=32, title="Options", back_action=Route.BACK,
        )
        self._controls_button: UiButtonState = UiButtonState("Controls", force_wide=True)
        self._slider_sfx = UiSegmentedSlider(value=10)
        self._slider_music = UiSegmentedSlider(value=10)
        self._slider_detail = UiSegmentedSlider(value=5, max=5, min=1)
        self._info_checkbox = UiCheckbox("UI Info texts")

    def open(self) -> None:
        super().open()
        self._controls_button = UiButtonState("Controls", force_wide=True)
        self._dirty = False
        self._sync_from_config()

    def update(self, dt: float) -> None:
        super().update(dt)
        if self.state.ui.closing:
            return
        entry = self._entry
        if entry is None or not self._entry_enabled():
            return

        config = self.state.config
        layout = self._content_layout()
        base_pos = layout.base_pos
        label_pos = layout.label_pos
        slider_pos = layout.slider_pos

        resources = require_runtime_resources(self.state)
        focus = self.state.focus
        mouse = Vec2.from_xy(canvas.mouse_position())

        # `options_menu_update` updates the checkbox, the sliders, then the Controls button: their focus order.
        if ui_checkbox_update(
            resources,
            self._info_checkbox,
            label_pos.offset(dy=135.0),
            focus=focus,
            mouse=mouse,
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
        ):
            config.gameplay.show_info_texts = self._info_checkbox.checked
            self._dirty = True

        down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        sfx_value = self._slider_sfx.value
        ui_segmented_slider_update(focus, self._slider_sfx, slider_pos.offset(dy=47.0), mouse=mouse, down=down)
        if self._slider_sfx.value != sfx_value:
            config.audio.sfx_volume = float(self._slider_sfx.value) * 0.1
            if self.state.audio is not None:
                set_sfx_volume(self.state.audio.sfx, config.audio.sfx_volume)
            self._dirty = True

        music_value = self._slider_music.value
        ui_segmented_slider_update(focus, self._slider_music, slider_pos.offset(dy=67.0), mouse=mouse, down=down)
        if self._slider_music.value != music_value:
            config.audio.music_volume = float(self._slider_music.value) * 0.1
            if self.state.audio is not None:
                set_music_volume(self.state.audio.music, config.audio.music_volume)
            self._dirty = True

        detail_value = self._slider_detail.value
        ui_segmented_slider_update(focus, self._slider_detail, slider_pos.offset(dy=87.0), mouse=mouse, down=down)
        if self._slider_detail.value != detail_value:
            # The keys step the slider down to 0; the preset stays within 1..5.
            self._slider_detail.value = apply_detail_preset(config, max(1, self._slider_detail.value))
            self._dirty = True

        # `options_menu_update`: controls button is aligned with the panel content base.
        controls_pos = base_pos.offset(dy=155.0)
        dt_ms = min(float(dt), 0.1) * 1000.0
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if button_update(
            resources,
            self._controls_button,
            focus=focus,
            pos=controls_pos,
            dt_ms=dt_ms,
            mouse=canvas.mouse_position(),
            click=click,
        ):
            self._begin_close_transition(Route.CONTROLS)

    def _sync_from_config(self) -> None:
        config = self.state.config
        self._info_checkbox.checked = config.gameplay.show_info_texts

        sfx_volume = config.audio.sfx_volume
        music_volume = config.audio.music_volume
        detail_preset = config.display.detail_preset

        self._slider_sfx.value = max(self._slider_sfx.min, min(self._slider_sfx.max, int(sfx_volume * 10.0)))
        self._slider_music.value = max(self._slider_music.min, min(self._slider_music.max, int(music_volume * 10.0)))
        self._slider_detail.value = max(self._slider_detail.min, min(self._slider_detail.max, detail_preset))

    def _content_layout(self) -> _OptionsContentLayout:
        panel_top_left = self._panel_rect(self._panel_element).top_left
        base_pos = panel_top_left + Vec2(212.0, 40.0)
        # `options_menu_update`: title label is anchored at panel_top + 40.
        label_pos = base_pos.offset(dx=8.0)
        slider_pos = label_pos.offset(dx=130.0)
        return _OptionsContentLayout(
            base_pos=base_pos,
            label_pos=label_pos,
            slider_pos=slider_pos,
        )

    def _draw_contents(self) -> None:
        resources = require_runtime_resources(self.state)
        labels_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        layout = self._content_layout()
        base_pos = layout.base_pos
        label_pos = layout.label_pos
        slider_pos = layout.slider_pos

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
            title_w,
            MENU_LABEL_ROW_HEIGHT,
        )
        draw_ui_quad(
            texture=labels_tex,
            src=src,
            dst=dst,
            origin=rl.Vector2(0.0, 0.0),
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

        y_offsets = (47.0, 67.0, 87.0)
        for label, offset in zip(self._LABELS, y_offsets, strict=False):
            draw_small_text(font, label, label_pos.offset(dy=offset), text_color)

        focus = self.state.focus
        ui_segmented_slider_draw(resources, focus, self._slider_sfx, slider_pos.offset(dy=47.0))
        ui_segmented_slider_draw(resources, focus, self._slider_music, slider_pos.offset(dy=67.0))
        ui_segmented_slider_draw(resources, focus, self._slider_detail, slider_pos.offset(dy=87.0))

        ui_checkbox_draw(resources, self._info_checkbox, label_pos.offset(dy=135.0), focus=self.state.focus)

        button_pos = base_pos.offset(dy=155.0)
        button_draw(
            resources,
            self._controls_button,
            focus=self.state.focus,
            pos=button_pos,
        )
