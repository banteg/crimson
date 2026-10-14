from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import msgspec

from ..modes.base_gameplay_mode import BaseGameplayMode

if TYPE_CHECKING:
    from ..game.types import Screen


class ScreenEntry(msgspec.Struct, frozen=True):
    view: Screen
    resume: Callable[[], None] | None = None

class ScreenStack:
    """Own open screens; only the top updates, retained runs supply backgrounds."""

    def __init__(self) -> None:
        self._entries: list[ScreenEntry] = []

    @property
    def active(self) -> Screen:
        return self._entries[-1].view

    @property
    def active_gameplay(self) -> BaseGameplayMode | None:
        if not self._entries:
            return None
        view = self._entries[-1].view
        return view if isinstance(view, BaseGameplayMode) else None

    @property
    def gameplay(self) -> BaseGameplayMode | None:
        for entry in reversed(self._entries):
            if isinstance(entry.view, BaseGameplayMode):
                return entry.view
        return None

    @property
    def background(self) -> BaseGameplayMode | None:
        return None if self.active_gameplay is not None else self.gameplay
    def push(self, entry: ScreenEntry) -> None:
        if self._entries:
            assert self._entries[-1].resume is not None, "retained screen must define resumption"
        self._entries.append(entry)
        entry.view.open()

    def replace(self, entry: ScreenEntry) -> None:
        if self._entries:
            self._entries.pop().view.close()
        self.push(entry)

    def reset(self, entry: ScreenEntry) -> None:
        self.close()
        self.push(entry)

    def back(self) -> bool:
        if len(self._entries) < 2:
            return False
        self._entries.pop().view.close()
        resume = self._entries[-1].resume
        assert resume is not None
        resume()
        return True

    def close(self) -> None:
        while self._entries:
            self._entries.pop().view.close()
