from __future__ import annotations

from ...game.types import BackToPrevious, GameState
from .base import _PanelMenuScreenView


class OtherGamesView(_PanelMenuScreenView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Other games",
            body="This menu is out of scope for the rewrite.",
            back_action=BackToPrevious(),
        )


__all__ = ["OtherGamesView"]
