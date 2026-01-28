from __future__ import annotations

from grim.view import ViewContext

from ..modes.survival_mode import SurvivalMode
from .registry import register_view


class SurvivalView(SurvivalMode):
    pass


@register_view("survival", "Survival")
def _create_survival_view(*, ctx: ViewContext) -> SurvivalView:
    return SurvivalView(ctx)
