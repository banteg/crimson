from __future__ import annotations

import pyray as rl

from .registry import register_view
from grim.view import View


class EmptyView:
    def update(self, dt: float) -> None:
        del dt

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)


@register_view("empty", "Empty window")
def build_empty_view() -> View:
    return EmptyView()
