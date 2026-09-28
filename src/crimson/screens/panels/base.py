from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.screens.actions import Route, ScreenAction, StartRun
from crimson.screens.chrome import draw_screen_background, ensure_menu_ground
from crimson.ui.animation import ui_element_anim, ui_element_timeline_window, ui_elements_max_timeline
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_item, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_LABEL_ROW_BACK,
    MENU_PANEL_HEIGHT,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuEntry,
    back_button_scale,
    label_alpha,
    menu_item_bounds,
)
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.audio import play_sfx, update_audio
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...input_codes import PadCode, pad_nav_pressed
from ...ui.menu_panel import draw_classic_menu_panel
from ..assets import require_runtime_resources
from ..transitions import _draw_screen_fade

PANEL_POS_X = -45.0
PANEL_POS_Y = 210.0
PANEL_BACK_POS_X = -55.0
PANEL_BACK_POS_Y = 430.0

class PanelMenuView:
    def __init__(
        self,
        state: GameState,
        *,
        game_state: GameStateId,
        panel_element: int,
        back_element: int,
        title: str,
        body: str | None = None,
        panel_pos: Vec2 = Vec2(PANEL_POS_X, PANEL_POS_Y),
        panel_offset: Vec2 = Vec2(MENU_PANEL_OFFSET_X, MENU_PANEL_OFFSET_Y),
        panel_height: float = MENU_PANEL_HEIGHT,
        back_pos: Vec2 = Vec2(PANEL_BACK_POS_X, PANEL_BACK_POS_Y),
        back_action: ScreenAction = Route.MENU,
    ) -> None:
        self.state = state
        self._game_state = game_state
        self._panel_element = panel_element
        self._back_element = back_element
        self._is_open = False
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._panel_pos = panel_pos
        self._panel_offset = panel_offset
        self._panel_height = panel_height
        self._back_pos = back_pos
        self._back_action = back_action
        self._ground: GroundRenderer | None = None
        self._entry: MenuEntry | None = None
        self._hovered = False
        self._menu_screen_width = 0
        self._widescreen_y_shift = 0.0
        self._panel_open_sfx_played = False

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._entry = MenuEntry(slot=0, row=MENU_LABEL_ROW_BACK, y=self._back_pos.y)
        self._hovered = False
        self.state.ui.enter(ui_elements_max_timeline(self._game_state))
        self._panel_open_sfx_played = False
        self._init_ground()
        self._is_open = True

    def resume(self) -> None:
        self.state.ui.enter(ui_elements_max_timeline(self._game_state))
        self._hovered = False
        self._panel_open_sfx_played = False

    def close(self) -> None:
        self._is_open = False
        self._ground = None

    def update(self, dt: float) -> None:
        if self._update_panel(dt):
            self._update_back_button(dt)

    def _update_panel(self, dt: float, *, play_open_sfx: bool = True) -> bool:
        """Advance presentation without consuming widget or navigation input."""
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if not self.state.ui.advance(dt_ms):
            return False

        if dt_ms > 0 and self.state.ui.timeline_ms >= self.state.ui.max_timeline_ms:
            self.state.menu_sign_locked = True
            if play_open_sfx and (not self._panel_open_sfx_played) and (self.state.audio is not None):
                play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
                self._panel_open_sfx_played = True

        return True

    def _update_back_button(self, dt: float, *, enabled: bool = True, enter: bool = True) -> None:
        dt_ms = int(min(dt, 0.1) * 1000.0)
        entry = self._entry
        if entry is None:
            return

        enabled = enabled and self._entry_enabled()
        hovered = enabled and self._hovered_entry(entry)
        self._hovered = hovered

        if (rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.FACE_RIGHT)) and enabled:
            self._begin_close_transition(self._back_action)
        if enter and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def draw(self) -> None:
        self._assert_open()
        draw_screen_background(self.state, self._ground)
        _draw_screen_fade(self.state)
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

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self.state.ui.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, f"{self.__class__.__name__} must be opened before use"

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

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self.state.ui.closing:
            return
        if isinstance(action, StartRun):
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self.state.ui.begin(action)

    def _init_ground(self) -> None:
        if self.state.pause_background is not None:
            self._ground = None
            return
        self._ground = ensure_menu_ground(self.state)

    def _draw_panel(self) -> None:
        panel = require_runtime_resources(self.state).texture(TextureId.UI_MENU_PANEL)
        _angle_rad, slide_x = ui_element_anim(
            self.state.ui.timeline_ms,
            index=self._panel_element,
            width=MENU_PANEL_WIDTH,
        )
        panel_top_left = (
            Vec2(
                self._panel_pos.x + slide_x,
                self._panel_pos.y + self._widescreen_y_shift,
            )
            + self._panel_offset
        )
        dst = rl.Rectangle(panel_top_left.x, panel_top_left.y, MENU_PANEL_WIDTH, float(self._panel_height))
        shadows_enabled = self.state.config.display.shadows_enabled
        draw_classic_menu_panel(panel, dst=dst, tint=rl.WHITE, shadow=shadows_enabled)

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
        return Vec2(self._back_pos.x + slide_x, entry.y + self._widescreen_y_shift)

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
