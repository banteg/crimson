from __future__ import annotations

from grim.assets import TextureId
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_update, button_width
from ...ui.shadow import UI_SHADOW_OFFSET
from ..assets import require_runtime_resources
from ..chrome.controls import MenuEntry, MenuEntryController
from ..chrome.geometry import (
    MENU_LABEL_ROW_BACK,
    MENU_PANEL_HEIGHT,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    menu_item_scale,
    ui_element_anim,
)
from ..chrome.menu_entries import _MenuEntriesScreenView, draw_menu_entry, menu_entry_bounds
from ..chrome.runtime import (
    BackdropPolicy,
    ChromeSpec,
    MusicPolicy,
    PendingOnceDispatch,
    PlayOpenSfxOnFullyOpen,
    SignPolicy,
)
from ..chrome.view import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS

PANEL_POS_X = -45.0
PANEL_POS_Y = 210.0
PANEL_BACK_POS_X = -55.0
PANEL_BACK_POS_Y = 430.0

FADE_TO_GAME_ACTIONS = frozenset(
    {
        "start_survival",
        "start_rush",
        "start_typo",
        "start_tutorial",
        "start_quest",
    },
)


def save_dirty_config(state: GameState) -> bool:
    try:
        state.config.save()
    except (OSError, ValueError) as exc:
        state.console.log.log(f"config: save failed: {exc}")
        return False
    return True


class _PanelMenuScreenView(_MenuEntriesScreenView):
    def __init__(
        self,
        state: GameState,
        *,
        title: str,
        body: str | None = None,
        panel_pos: Vec2 = Vec2(PANEL_POS_X, PANEL_POS_Y),
        panel_offset: Vec2 = Vec2(MENU_PANEL_OFFSET_X, MENU_PANEL_OFFSET_Y),
        panel_height: float = MENU_PANEL_HEIGHT,
        back_pos: Vec2 = Vec2(PANEL_BACK_POS_X, PANEL_BACK_POS_Y),
        back_action: str = "back_to_menu",
    ) -> None:
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._panel_pos = panel_pos
        self._panel_offset = panel_offset
        self._panel_height = panel_height
        self._back_pos = back_pos
        self._back_action = back_action
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(),
                music=MusicPolicy(),
                sign=SignPolicy(lock_on_fully_open=True),
                dispatch=PendingOnceDispatch(),
                open_sfx=PlayOpenSfxOnFullyOpen(),
                close_sfx="sfx_ui_buttonclick",
                fade_to_game_actions=FADE_TO_GAME_ACTIONS,
            ),
        )
        self._uses_button_back_control = False
        self._back_enter_enabled = True
        self._back_button: UiButtonState | None = None

    @property
    def _entry(self) -> MenuEntry | None:
        if self._uses_button_back_control or not self._menu_entries:
            return None
        return self._menu_entries[0]

    def update(self, dt: float) -> None:
        if self._uses_button_back_control:
            self._assert_open()
            tick = self._update_chrome(dt)
            chrome = self._chrome_state
            if chrome.closing:
                return
            back_interactive = chrome.timeline_ms >= PANEL_TIMELINE_START_MS
            self._update_button_back_control(dt_ms=tick.dt_ms, interactive=back_interactive)
            return
        super().update(dt)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        self._draw_fade()
        self._draw_panel()
        self._draw_menu_items()
        self._draw_sign()
        self._draw_contents()
        self._draw_cursor()

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

    def _panel_frame(
        self,
        *,
        panel_pos: Vec2 | None = None,
        panel_height: float | None = None,
        panel_offset: Vec2 | None = None,
        small_scale: float | None = None,
        start_ms: int = PANEL_TIMELINE_START_MS,
        end_ms: int = PANEL_TIMELINE_END_MS,
    ):
        return super()._panel_frame(
            panel_pos=self._panel_pos if panel_pos is None else panel_pos,
            panel_offset=self._panel_offset if panel_offset is None else panel_offset,
            panel_height=self._panel_height if panel_height is None else panel_height,
            small_scale=self._small_panel_scale() if small_scale is None else small_scale,
            start_ms=start_ms,
            end_ms=end_ms,
        )

    def _small_panel_scale(self) -> float:
        return 0.9

    def _build_menu_entries(self) -> list[MenuEntry]:
        if self._uses_button_back_control:
            return []
        return [MenuEntry(slot=0, row=MENU_LABEL_ROW_BACK, y=self._back_pos.y)]

    def _activate_menu_entry(self, index: int) -> None:
        if index != 0:
            return
        self._begin_close_transition(self._back_action)

    def _escape_entry_index(self) -> int | None:
        if self._uses_button_back_control:
            return None
        return 0

    def _enter_enabled(self) -> bool:
        return self._back_enter_enabled

    def _draw_panel(self) -> None:
        panel = require_runtime_resources(self.state).texture(TextureId.UI_MENU_PANEL)
        frame = self._panel_frame()
        dst = rl.Rectangle(frame.panel_top_left.x, frame.panel_top_left.y, frame.panel_width, frame.panel_height)
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(panel, dst=dst, tint=rl.WHITE, shadow=fx_detail)

    def _draw_entry(self, entry: MenuEntry) -> None:
        resources = require_runtime_resources(self.state)
        item = resources.texture(TextureId.UI_MENU_ITEM)
        item_w = float(item.width)
        chrome = self._chrome_state
        _angle_rad, slide_x = ui_element_anim(
            chrome.timeline_ms,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * self._menu_item_scale(entry.slot)[0],
        )
        pos = Vec2(self._back_pos.x + slide_x, entry.y + chrome.widescreen_y_shift)
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        alpha = MenuEntryController.alpha_for_entry(entry=entry, index=0, list_state=self._list_state)
        draw_menu_entry(
            resources,
            screen_width=float(chrome.screen_width),
            entry=entry,
            pos=pos,
            small_scale=self._small_panel_scale(),
            rotation_deg=0.0,
            label_alpha=alpha,
            glow_alpha=alpha if self._entry_enabled(entry) else None,
            shadow_offset=UI_SHADOW_OFFSET,
            fx_detail=fx_detail,
        )

    def _draw_menu_items(self) -> None:
        entry = self._entry
        if entry is None:
            return
        self._draw_entry(entry)

    def _entry_enabled(self, entry: MenuEntry) -> bool:
        return self._chrome_state.timeline_ms >= PANEL_TIMELINE_START_MS

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        return menu_item_scale(float(self._chrome_state.screen_width), int(slot), small_scale=self._small_panel_scale())

    def _menu_item_bounds(self, entry: MenuEntry, resources) -> Rect:
        item = resources.texture(TextureId.UI_MENU_ITEM)
        item_w = float(item.width)
        item_scale = self._menu_item_scale(entry.slot)[0]
        chrome = self._chrome_state
        _angle_rad, slide_x = ui_element_anim(
            chrome.timeline_ms,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * item_scale,
        )
        pos = Vec2(self._back_pos.x + slide_x, entry.y + chrome.widescreen_y_shift)
        return menu_entry_bounds(
            resources,
            screen_width=float(chrome.screen_width),
            entry=entry,
            pos=pos,
            small_scale=self._small_panel_scale(),
        )

    def _update_button_back_control(self, *, dt_ms: int, interactive: bool) -> None:
        if not interactive or self._back_button is None:
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition(self._back_action)
            return

        pos, width = self._button_back_layout()
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._back_button.enabled = True
        if button_update(
            self._back_button,
            pos=pos,
            width=width,
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            self._begin_close_transition(self._back_action)

    def _button_back_layout(self) -> tuple[Vec2, float]:
        assert self._back_button is not None
        frame = self._panel_frame()
        resources = require_runtime_resources(self.state)
        width = float(
            button_width(
                resources,
                self._back_button.label,
                scale=frame.scale,
                force_wide=self._back_button.force_wide,
            ),
        )
        pos = frame.panel_top_left + Vec2(
            frame.panel_width - width - 22.0 * frame.scale,
            frame.panel_height - 44.0 * frame.scale,
        )
        return pos, width
