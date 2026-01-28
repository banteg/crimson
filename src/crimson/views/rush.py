from __future__ import annotations

from grim.view import ViewContext

from ..modes.rush_mode import RushMode
from .registry import register_view


class RushView(RushMode):
    pass


@register_view("rush", "Rush")
def _create_rush_view(*, ctx: ViewContext) -> RushView:
    return RushView(ctx)

