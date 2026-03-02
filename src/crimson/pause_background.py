from __future__ import annotations

from typing import Protocol


class PauseBackground(Protocol):
    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None: ...
