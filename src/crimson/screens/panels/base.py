from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.screens.actions import Route, ScreenAction
from crimson.ui.animation import ui_element_anim, ui_element_timeline_window
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.menu_chrome import draw_menu_item, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_LABEL_ROW_BACK,
    MenuEntry,
    back_button_scale,
    label_alpha,
    menu_item_bounds,
    ui_element_pos,
)
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen


class PanelMenuView(MenuScreen):
    def __init__(
        self,
        state: GameState,
        *,
        game_state: GameStateId,
        panel_element: int,
        back_element: int,
        title: str,
        body: str | None = None,
        back_action: ScreenAction = Route.MENU,
    ) -> None:
        super().__init__(state)
        self.game_state = game_state
        self._panel_element = panel_element
        self._back_element = back_element
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._back_action = back_action
        self._entry: MenuEntry | None = None
        self._hovered = False
        self._menu_screen_width = 0

    def open(self) -> None:
        self._menu_screen_width = int(self.state.config.display.width)
        back_y = ui_element_pos(self._back_element, self._menu_screen_width).y
        self._entry = MenuEntry(slot=0, row=MENU_LABEL_ROW_BACK, y=back_y)
        super().open()

    def _enter(self) -> None:
        super()._enter()
        self._hovered = False

    def update(self, dt: float) -> None:
        if self._update_panel(dt):
            self._update_back_button(dt)

    def _update_panel(self, dt: float, *, play_open_sfx: bool = True) -> bool:
        """Advance presentation without consuming widget or navigation input."""
        if not self._advance(dt):
            return False
        self._lock_sign(dt, click=play_open_sfx)

        # The back element sits later in the element table than the panel, so native's backwards walk registers
        # it for focus before the panel's own widgets.
        entry = self._entry
        if entry is not None:
            entry.focused = self.state.focus.update(entry)
        return True

    def _update_back_button(self, dt: float, *, enabled: bool = True) -> None:
        dt_ms = int(min(dt, 0.1) * 1000.0)
        entry = self._entry
        if entry is None:
            return

        focus = self.state.focus
        enabled = enabled and self._entry_enabled()
        hovered = enabled and self._hovered_entry(entry)
        self._hovered = hovered

        if focus.escape and enabled:
            self._begin_close_transition(self._back_action)
        if entry.focused and focus.enter and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))
        if entry.focused and focus.timer_ms > 0:
            entry.hover_amount = focus.timer_ms

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        entry = self._entry
        assert entry is not None, "PanelMenuView entry must be initialized before draw()"
        self._draw_panel()
        self._draw_entry(entry)
        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=True,
            timeline_ms=self.state.ui.timeline_ms,
        )
        self._draw_contents()
        ui_cursor_render(require_runtime_resources(self.state), dt=self.state.frame_dt)

    def _draw_contents(self) -> None:
        self._draw_title_text()

    def _draw_title_text(self) -> None:
        x = 32
        y = 140
        rl.draw_text(self._title, x, y, 28, rl.Color(235, 235, 235, 255))
        y += 34
        for line in self._body_lines:
            rl.draw_text(line, x, y, 18, rl.Color(190, 190, 200, 255))
            y += 22

    def _panel_rect(self, index: int) -> Rect:
        return ui_panel_rect(index, self.state.ui.timeline_ms, self._menu_screen_width)

    def _draw_panel(self) -> None:
        index = self._panel_element
        draw_ui_panel(
            require_runtime_resources(self.state), index, self._panel_rect(index),
            shadow=self.state.config.display.shadows_enabled,
        )

    def _draw_entry(self, entry: MenuEntry) -> None:
        resources = require_runtime_resources(self.state)
        item_scale, local_y_shift = back_button_scale(self._menu_screen_width)
        alpha = label_alpha(entry.hover_amount)
        draw_menu_item(
            resources,
            pos=self._back_button_pos(entry, resources),
            row=entry.row,
            item_scale=item_scale,
            local_y_shift=local_y_shift,
            rotation_deg=0.0,
            alpha=alpha,
            glow_alpha=alpha if self._entry_enabled() else None,
            shadows=self.state.config.display.shadows_enabled,
        )

    def _back_button_pos(self, entry: MenuEntry, resources: RuntimeResources) -> Vec2:
        item_w = float(resources.texture(TextureId.UI_MENU_ITEM).width)
        _angle_rad, slide_x = ui_element_anim(
            self.state.ui.timeline_ms,
            index=self._back_element,
            width=item_w * back_button_scale(self._menu_screen_width)[0],
        )
        return Vec2(ui_element_pos(self._back_element, self._menu_screen_width).x + slide_x, entry.y)

    def _entry_enabled(self) -> bool:
        return self.state.ui.timeline_ms >= ui_element_timeline_window(self._back_element)[1]

    def _hovered_entry(self, entry: MenuEntry) -> bool:
        mouse = canvas.mouse_position()
        mouse_pos = Vec2.from_xy(mouse)
        return self._menu_item_bounds(entry).contains(mouse_pos)

    def _menu_item_bounds(self, entry: MenuEntry) -> Rect:
        resources = require_runtime_resources(self.state)
        item = resources.texture(TextureId.UI_MENU_ITEM)
        item_scale, local_y_shift = back_button_scale(self._menu_screen_width)
        return menu_item_bounds(
            self._back_button_pos(entry, resources),
            Vec2(float(item.width), float(item.height)),
            item_scale,
            local_y_shift,
        )
