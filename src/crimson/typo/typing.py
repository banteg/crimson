from __future__ import annotations

import msgspec

TYPING_MAX_CHARS = 17


class TypingBuffer(msgspec.Struct):
    text: str = ""
    submit_count: int = 0
    match_count: int = 0

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

    def submit(self, *, matched: bool) -> str | None:
        if not self.text:
            return None

        entered = self.text
        self.submit_count += 1
        if bool(matched):
            self.match_count += 1
        self.clear()
        return entered
