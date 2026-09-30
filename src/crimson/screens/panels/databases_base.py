from __future__ import annotations

from crimson.screens.actions import Route
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.menu_chrome import draw_menu_sign
from grim import canvas
from grim.audio import play_sfx
from grim.fonts.small import SmallFontData
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game.types import GameState
from ...ui.button import UiButtonState, button_draw, button_update
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.scrollbar import UiScrollbar
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen


class _DatabaseBaseView(MenuScreen):
    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._back_button = UiButtonState("Back", force_wide=False)
        # The database list's `ui_scrollbar_t`: ten rows.
        self.list_scroll = UiScrollbar(visible_rows=10)

    def open(self) -> None:
        super().open()
        self._back_button = UiButtonState("Back", force_wide=False)
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)

    def _panel_rect(self, index: int) -> Rect:
        """The databases lay out on `ui_element_slot_09` (the list) and slot 33 (the details)."""
        return ui_panel_rect(index, self.state.ui.timeline_ms, self.state.config.display.width)

    def update(self, dt: float) -> None:
        if not self._advance(dt):
            return
        dt_ms = int(min(float(dt), 0.1) * 1000.0)

        enabled = self.state.ui.opened
        if self.state.focus.escape and enabled:
            self._begin_close_transition(Route.BACK)
            return

        if not enabled:
            return

        left_top_left = self._panel_rect(9).top_left
        resources = require_runtime_resources(self.state)

        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_content_interaction(left_top_left=left_top_left, mouse=mouse)

        # The database's list registers for focus before its Back button.
        back_pos = self._back_button_pos()
        if button_update(
            resources,
            self._back_button,
            focus=self.state.focus,
            pos=left_top_left + back_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._begin_close_transition(Route.BACK)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()

        resources = require_runtime_resources(self.state)
        shadows_enabled = self.state.config.display.shadows_enabled
        left_panel = self._panel_rect(9)
        right_panel = self._panel_rect(33)
        draw_ui_panel(resources, 9, left_panel, shadow=shadows_enabled)
        draw_ui_panel(resources, 33, right_panel, shadow=shadows_enabled)
        left_panel_top_left = left_panel.top_left
        right_panel_top_left = right_panel.top_left

        font = resources.small_font
        self._draw_contents(left_panel_top_left, right_panel_top_left, font=font)

        back_pos = self._back_button_pos()
        button_draw(
            resources,
            self._back_button,
            focus=self.state.focus,
            pos=left_panel_top_left + back_pos,
        )

        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=True,
            timeline_ms=self.state.ui.timeline_ms,
        )
        ui_cursor_render(resources, dt=self.state.frame_dt)

    def _back_button_pos(self) -> Vec2:
        raise NotImplementedError

    def _draw_contents(
        self,
        left_top_left: Vec2,
        right_top_left: Vec2,
        *,
        font: SmallFontData,
    ) -> None:
        raise NotImplementedError

    def _update_content_interaction(self, *, left_top_left: Vec2, mouse: rl.Vector2) -> None:
        pass
