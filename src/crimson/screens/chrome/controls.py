from __future__ import annotations

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from .geometry import label_alpha


class MenuEntry(msgspec.Struct):
    slot: int
    row: int
    y: float
    hover_amount: int = 0
    ready_timer_ms: int = 0x100


class MenuListState(msgspec.Struct):
    selected_index: int = -1
    hovered_index: int | None = None
    focus_timer_ms: int = 0
    idle_ms: int = 0
    last_mouse_pos: Vec2 = Vec2()


class MenuEntryController:
    @staticmethod
    def update_ready_timers(entries: list[MenuEntry], dt_ms: int) -> None:
        for entry in entries:
            if int(entry.ready_timer_ms) < 0x100:
                entry.ready_timer_ms = min(0x100, int(entry.ready_timer_ms) + int(dt_ms))

    @staticmethod
    def update_hover_amounts(entries: list[MenuEntry], *, hovered_index: int | None, dt_ms: int) -> None:
        hovered = None if hovered_index is None else int(hovered_index)
        for idx, entry in enumerate(entries):
            if hovered is not None and idx == hovered:
                entry.hover_amount += int(dt_ms) * 6
            else:
                entry.hover_amount -= int(dt_ms) * 2
            entry.hover_amount = max(0, min(1000, int(entry.hover_amount)))

    @staticmethod
    def counter_value(*, entry: MenuEntry, index: int, list_state: MenuListState) -> int:
        if int(index) == int(list_state.selected_index) and int(list_state.focus_timer_ms) > 0:
            return int(list_state.focus_timer_ms)
        return int(entry.hover_amount)

    @staticmethod
    def alpha_for_entry(*, entry: MenuEntry, index: int, list_state: MenuListState) -> int:
        return label_alpha(MenuEntryController.counter_value(entry=entry, index=index, list_state=list_state))


class MenuListController:
    @staticmethod
    def open_state(
        list_state: MenuListState,
        *,
        entry_count: int,
        mouse_pos: Vec2,
    ) -> None:
        list_state.selected_index = 0 if int(entry_count) > 0 else -1
        list_state.hovered_index = None
        list_state.focus_timer_ms = 0
        list_state.idle_ms = 0
        list_state.last_mouse_pos = Vec2(float(mouse_pos.x), float(mouse_pos.y))

    @staticmethod
    def hovered_index(
        entries: list[MenuEntry],
        *,
        is_enabled,
        contains_mouse,
    ) -> int | None:
        for idx, entry in enumerate(entries):
            if not bool(is_enabled(entry)):
                continue
            if bool(contains_mouse(entry)):
                return idx
        return None

    @staticmethod
    def update_idle_timer(list_state: MenuListState, *, dt_ms: int, mouse_pos: Vec2) -> None:
        mouse_moved = Vec2(float(mouse_pos.x), float(mouse_pos.y)) != list_state.last_mouse_pos
        if mouse_moved:
            list_state.last_mouse_pos = Vec2(float(mouse_pos.x), float(mouse_pos.y))

        any_key = rl.get_key_pressed() != 0
        any_click = (
            rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            or rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT)
            or rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_MIDDLE)
        )
        if any_key or any_click or mouse_moved:
            list_state.idle_ms = 0
        else:
            list_state.idle_ms += int(dt_ms)

    @staticmethod
    def step(
        list_state: MenuListState,
        entries: list[MenuEntry],
        *,
        dt_ms: int,
        hovered_index: int | None,
        is_enabled,
        enter_enabled: bool = True,
        escape_index: int | None = None,
    ) -> int | None:
        list_state.hovered_index = hovered_index
        list_state.focus_timer_ms = max(0, int(list_state.focus_timer_ms) - int(dt_ms))

        if entries and rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
            delta = -1 if reverse else 1
            list_state.selected_index = (int(list_state.selected_index) + delta) % len(entries)
            list_state.focus_timer_ms = 1000

        activated_index: int | None = None
        if escape_index is not None and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            activated_index = int(escape_index)
        elif enter_enabled and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            selected = int(list_state.selected_index)
            if 0 <= selected < len(entries) and bool(is_enabled(entries[selected])):
                activated_index = selected

        if activated_index is None and hovered_index is not None:
            hovered = int(hovered_index)
            if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                entry = entries[hovered]
                if bool(is_enabled(entry)):
                    list_state.selected_index = hovered
                    list_state.focus_timer_ms = 1000
                    activated_index = hovered

        MenuEntryController.update_ready_timers(entries, int(dt_ms))
        MenuEntryController.update_hover_amounts(entries, hovered_index=hovered_index, dt_ms=int(dt_ms))
        return activated_index
