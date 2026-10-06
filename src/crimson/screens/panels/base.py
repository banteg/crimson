from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.screens.actions import Route, ScreenAction
from crimson.ui.animation import ui_element_timeline_window
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.menu_chrome import draw_menu_entry, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_ROW_BACK,
    MenuEntry,
    back_button_scale,
    menu_entry_activated,
    menu_entry_enabled,
    menu_entry_update,
    ui_element_pos,
)
from grim import canvas
from grim.assets import TextureId
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
        panel_grow: float = 0.0,
    ) -> None:
        super().__init__(state)
        self.game_state = game_state
        self._panel_element = panel_element
        self._back_element = back_element
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._back_action = back_action
        # Port rows below the native panel: its 3-slice middle stretches and the Back item moves down with it.
        self._panel_grow = panel_grow
        self._panel_lift = 0.0
        self._entry: MenuEntry | None = None
        self._menu_screen_width = 0

    def open(self) -> None:
        width = int(self.state.config.display.width)
        self._menu_screen_width = width
        scale, rise = back_button_scale(width)
        back_pos = ui_element_pos(self._back_element, width).offset(dy=self._panel_grow)
        # Where the grown panel would push Back out of the window (640x480), the panel and Back rise instead, by at
        # most the growth, so a native layout never moves.
        item_h = float(require_runtime_resources(self.state).texture(TextureId.UI_MENU_ITEM).height)
        back_bottom = back_pos.y + MENU_ITEM_OFFSET_Y * scale - rise + item_h * scale
        self._panel_lift = min(self._panel_grow, max(0.0, back_bottom - float(self.state.config.display.height)))
        self._entry = MenuEntry(
            element=self._back_element,
            row=MENU_LABEL_ROW_BACK,
            pos=back_pos.offset(dy=-self._panel_lift),
            scale=scale,
            rise=rise,
        )
        super().open()

    def update(self, dt: float) -> None:
        if self._update_panel(dt):
            self._update_back_button()

    def _update_panel(self, dt: float) -> bool:
        """Advance presentation and the Back item's hover without consuming widget or navigation input; False while
        the timeline runs out."""
        live = self._advance(dt)
        if live:
            self._lock_sign(dt)

        # The back element sits later in the element table than the panel, so native's backwards walk registers
        # it for focus before the panel's own widgets.
        entry = self._entry
        if entry is not None:
            item = require_runtime_resources(self.state).texture(TextureId.UI_MENU_ITEM)
            menu_entry_update(
                entry,
                item_size=Vec2(float(item.width), float(item.height)),
                mouse=Vec2.from_xy(canvas.mouse_position()),
                dt_ms=int(min(dt, 0.1) * 1000.0),
                focus=self.state.focus,
                live=live,
            )
        return live

    def _update_back_button(self, *, enabled: bool = True) -> None:
        """The Back item's click or Enter, and Escape once it is in; `enabled` is off while a panel widget holds the
        input."""
        entry = self._entry
        if entry is None or not enabled:
            return
        focus = self.state.focus
        timeline_ms = self.state.ui.timeline_ms
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if (focus.escape and menu_entry_enabled(entry, timeline_ms)) or menu_entry_activated(
            entry, timeline_ms=timeline_ms, focus=focus, click=click,
        ):
            self._begin_close_transition(self._back_action)

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
        rect = ui_panel_rect(index, self.state.ui.timeline_ms, self._menu_screen_width)
        return Rect.from_top_left(rect.top_left.offset(dy=-self._panel_lift), rect.width, rect.height + self._panel_grow)

    def _draw_panel(self) -> None:
        index = self._panel_element
        draw_ui_panel(
            require_runtime_resources(self.state), index, self._panel_rect(index),
            shadow=self.state.config.display.shadows_enabled,
        )

    def _draw_entry(self, entry: MenuEntry) -> None:
        draw_menu_entry(
            require_runtime_resources(self.state),
            entry,
            timeline_ms=self.state.ui.timeline_ms,
            shadows=self.state.config.display.shadows_enabled,
        )

    def _entry_enabled(self) -> bool:
        return self.state.ui.timeline_ms >= ui_element_timeline_window(self._back_element)[1]
