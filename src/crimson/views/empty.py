from __future__ import annotations

from grim.raylib_api import rl
from grim.view import View

from .registry import register_view


class EmptyView:
    def open(self) -> None:
        return None

    def update(self, dt: float) -> None:
        del dt

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)

    def close(self) -> None:
        return None


@register_view("empty", "Empty window")
def build_empty_view() -> View:
    return EmptyView()
