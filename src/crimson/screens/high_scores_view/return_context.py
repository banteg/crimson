from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from ...game_modes import GameMode
from ...quests.level import QuestLevel

if TYPE_CHECKING:
    from grim.config import CrimsonConfig


class ScoreReturnContext(msgspec.Struct, frozen=True):
    """The native score-browser return latch preserves these run settings."""

    game_mode_id: GameMode
    quest_level: QuestLevel | None
    hardcore: bool

    @classmethod
    def capture(cls, config: CrimsonConfig) -> ScoreReturnContext:
        return cls(config.gameplay.mode, config.gameplay.quest_level, config.gameplay.hardcore)

    def restore(self, config: CrimsonConfig) -> None:
        config.gameplay.mode = self.game_mode_id
        config.gameplay.quest_level = self.quest_level
        config.gameplay.hardcore = self.hardcore
