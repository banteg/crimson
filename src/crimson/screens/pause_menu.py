from __future__ import annotations

from grim.audio import play_sfx
from grim.raylib_api import rl

from ..game.types import GameState
from .chrome import (
    MENU_LABEL_BASE_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_STEP,
    ActionDispatchPolicy,
    BackdropPolicy,
    ChromeSpec,
    MenuEntry,
    SignPolicy,
    menu_slot_start_ms,
)
from .menu import _MenuEntriesViewBase
from .transitions import _draw_screen_fade

PAUSE_MENU_TO_MAIN_MENU_FADE_MS = 500


class PauseMenuView(_MenuEntriesViewBase):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(
                    allow_pause_background=True,
                    use_menu_ground=False,
                    entity_alpha_mode="close_timeline_fraction",
                    entity_alpha_duration_ms=PAUSE_MENU_TO_MAIN_MENU_FADE_MS,
                    entity_alpha_action="back_to_menu",
                ),
                sign=SignPolicy(animated=True, lock_on_fully_open=True),
                dispatch=ActionDispatchPolicy(mode="pending_once"),
                open_sfx="sfx_ui_panelclick",
                open_sfx_mode="on_fully_open",
                close_sfx=None,
            ),
        )
        self._chrome.draw_fade_fn = lambda runtime_state: _draw_screen_fade(runtime_state)

    def open(self) -> None:
        super().open()
        self._chrome.chrome.timeline_max_ms = max(300, *(menu_slot_start_ms(entry.slot) for entry in self._menu_entries))

    def _build_menu_entries(self) -> list[MenuEntry]:
        widescreen_y_shift = self._chrome.chrome.widescreen_y_shift
        ys = [
            MENU_LABEL_BASE_Y + widescreen_y_shift,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP + widescreen_y_shift,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0 + widescreen_y_shift,
        ]
        return [
            MenuEntry(slot=0, row=MENU_LABEL_ROW_OPTIONS, y=ys[0]),
            MenuEntry(slot=1, row=MENU_LABEL_ROW_QUIT, y=ys[1]),
            MenuEntry(slot=2, row=MENU_LABEL_ROW_BACK, y=ys[2]),
        ]

    def _escape_entry_index(self) -> int | None:
        return self._entry_index_for_row(MENU_LABEL_ROW_BACK)

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        action = self._action_for_entry(entry)
        if action is None:
            return
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._begin_close_transition(action)

    @staticmethod
    def _action_for_entry(entry: MenuEntry) -> str | None:
        if entry.row == MENU_LABEL_ROW_OPTIONS:
            return "open_options"
        if entry.row == MENU_LABEL_ROW_QUIT:
            return "back_to_menu"
        if entry.row == MENU_LABEL_ROW_BACK:
            return "back_to_previous"
        return None

    def _pause_background_entity_alpha(self) -> float | None:
        return self._chrome._pause_background_entity_alpha()

    def _entry_index_for_row(self, row: int) -> int | None:
        for idx, entry in enumerate(self._menu_entries):
            if entry.row == row:
                return idx
        return None


__all__ = [
    "PAUSE_MENU_TO_MAIN_MENU_FADE_MS",
    "PauseMenuView",
    "_draw_screen_fade",
    "rl",
]
