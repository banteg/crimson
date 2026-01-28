from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


TYPING_MAX_CHARS = 17


@dataclass(frozen=True, slots=True)
class TypingEnterResult:
    fire_requested: bool = False
    reload_requested: bool = False
    target_creature_idx: int | None = None


@dataclass(slots=True)
class TypingBuffer:
    text: str = ""
    shots_fired: int = 0
    shots_hit: int = 0

    def clear(self) -> None:
        self.text = ""

    def backspace(self) -> None:
        if self.text:
            self.text = self.text[:-1]

    def push_char(self, ch: str) -> None:
        if not ch:
            return
        if len(self.text) >= TYPING_MAX_CHARS:
            return
        self.text += ch[0]

    def enter(self, *, find_target: Callable[[str], int | None]) -> TypingEnterResult:
        if not self.text:
            return TypingEnterResult()

        entered = self.text
        self.shots_fired += 1
        self.clear()

        target = find_target(entered)
        if target is not None:
            self.shots_hit += 1
            return TypingEnterResult(fire_requested=True, target_creature_idx=int(target))
        if entered == "reload":
            return TypingEnterResult(reload_requested=True)
        return TypingEnterResult()

