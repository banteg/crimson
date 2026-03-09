from __future__ import annotations

import os

from grim.audio import play_sfx
from grim.geom import Vec2
from grim.raylib_api import rl

from ..game.types import (
    FrontRouteId,
    GameState,
    OpenFrontRoute,
    QuitAfterDemo,
    QuitApp,
    StartDemo,
)
from .chrome.controls import MenuEntry
from .chrome.geometry import (
    MENU_DEMO_IDLE_START_MS,
    MENU_LABEL_BASE_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_MODS,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_OTHER_GAMES,
    MENU_LABEL_ROW_PLAY_GAME,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_LABEL_STEP,
    menu_max_timeline_ms,
)
from .chrome.menu_entries import _MenuEntriesScreenView
from .chrome.runtime import (
    BackdropPolicy,
    ChromeSpec,
    MusicPolicy,
    PendingOnceDispatch,
    PlayOpenSfxOnFullyOpen,
    SignPolicy,
)


class MenuView(_MenuEntriesScreenView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(allow_pause_background=False),
                music=MusicPolicy(
                    primary_track="crimson_theme",
                    demo_track="crimsonquest",
                    refresh_while_open=True,
                    stop_if_track_mismatch=True,
                ),
                sign=SignPolicy(
                    animated=True,
                    lock_on_fully_open=True,
                    unlock_on_actions=(QuitAfterDemo(), QuitApp()),
                ),
                dispatch=PendingOnceDispatch(),
                open_sfx=PlayOpenSfxOnFullyOpen(),
                close_sfx=None,
            ),
        )
        self._full_version = False
        self._idle_ms = 0
        self._last_mouse_pos = Vec2()

    def open(self) -> None:
        self._full_version = not self.state.demo_enabled
        self._idle_ms = 0
        super().open()
        self._chrome_state.timeline_max_ms = menu_max_timeline_ms(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        mouse = rl.get_mouse_position()
        self._last_mouse_pos = Vec2(float(mouse.x), float(mouse.y))

    def _build_menu_entries(self) -> list[MenuEntry]:
        return self._menu_entries_for_flags(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )

    def _before_menu_step(self, *, tick_dt_ms: int, mouse_pos: Vec2) -> None:
        if tick_dt_ms <= 0:
            return
        mouse_moved = Vec2(float(mouse_pos.x), float(mouse_pos.y)) != self._last_mouse_pos
        if mouse_moved:
            self._last_mouse_pos = Vec2(float(mouse_pos.x), float(mouse_pos.y))

        any_key = rl.get_key_pressed() != 0
        any_click = (
            rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            or rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT)
            or rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_MIDDLE)
        )
        if any_key or any_click or mouse_moved:
            self._idle_ms = 0
            return
        self._idle_ms += int(tick_dt_ms)

    def _after_menu_update(self, *, tick_dt_ms: int, interactive: bool) -> None:
        del tick_dt_ms
        if (
            (not self._chrome_state.closing)
            and self._chrome_state.pending_action is None
            and self.state.demo_enabled
            and interactive
            and self._idle_ms >= MENU_DEMO_IDLE_START_MS
        ):
            self._begin_close_transition(StartDemo())

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self.state.console.log.log(f"menu select: {index} (row {entry.row})")
        self.state.console.log.flush()
        if entry.row == MENU_LABEL_ROW_QUIT:
            self._begin_quit_transition()
        elif entry.row == MENU_LABEL_ROW_PLAY_GAME:
            self._begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_PLAY_GAME))
        elif entry.row == MENU_LABEL_ROW_OPTIONS:
            self._begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_OPTIONS))
        elif entry.row == MENU_LABEL_ROW_STATISTICS:
            self._begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_STATISTICS))
        elif entry.row == MENU_LABEL_ROW_MODS:
            self._begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_MODS))
        elif entry.row == MENU_LABEL_ROW_OTHER_GAMES:
            self._begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_OTHER_GAMES))

    def _begin_quit_transition(self) -> None:
        self._begin_close_transition(QuitAfterDemo() if self.state.demo_enabled else QuitApp())

    def _menu_entries_for_flags(
        self,
        *,
        full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[MenuEntry]:
        rows = self._menu_label_rows(full_version, other_games)
        slot_ys = self._menu_slot_ys(other_games, self._chrome_state.widescreen_y_shift)
        active = self._menu_slot_active(full_version, mods_available, other_games)
        entries: list[MenuEntry] = []
        for slot, (row, y, enabled) in enumerate(zip(rows, slot_ys, active, strict=False)):
            if enabled:
                entries.append(MenuEntry(slot=slot, row=row, y=y))
        return entries

    @staticmethod
    def _menu_label_rows(_full_version: bool, other_games: bool) -> list[int]:
        top = MENU_LABEL_ROW_MODS
        if other_games:
            return [top, MENU_LABEL_ROW_PLAY_GAME, MENU_LABEL_ROW_OPTIONS, MENU_LABEL_ROW_STATISTICS, MENU_LABEL_ROW_OTHER_GAMES, MENU_LABEL_ROW_QUIT]
        return [top, MENU_LABEL_ROW_PLAY_GAME, MENU_LABEL_ROW_OPTIONS, MENU_LABEL_ROW_STATISTICS, MENU_LABEL_ROW_QUIT, MENU_LABEL_ROW_BACK]

    @staticmethod
    def _menu_slot_ys(_other_games: bool, y_shift: float) -> list[float]:
        return [MENU_LABEL_BASE_Y + MENU_LABEL_STEP * float(slot) + y_shift for slot in range(6)]

    @staticmethod
    def _menu_slot_active(_full_version: bool, mods_available: bool, other_games: bool) -> list[bool]:
        if other_games:
            return [mods_available, True, True, True, True, True]
        return [mods_available, True, True, True, True, False]

    def _mods_available(self) -> bool:
        mods_dir = self.state.base_dir / "mods"
        if not mods_dir.exists():
            return False
        return any(mods_dir.glob("*.dll"))

    def _other_games_enabled(self) -> bool:
        return os.getenv("CRIMSON_GRIM_CONFIG_VAR_100", "").strip() != ""


__all__ = ["MenuView"]
