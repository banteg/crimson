from __future__ import annotations

from enum import Enum, auto
from typing import TYPE_CHECKING

import msgspec

from ..game_modes import GameMode
from ..quests.level import QuestLevel

if TYPE_CHECKING:
    from grim.config import CrimsonConfig

    from ..modes.quest_mode import QuestRunOutcome


class Route(Enum):
    MENU = auto()
    BACK = auto()
    PAUSE = auto()
    PLAY_GAME = auto()
    QUESTS = auto()
    OPTIONS = auto()
    CONTROLS = auto()
    STATISTICS = auto()
    WEAPONS = auto()
    PERKS = auto()
    CREDITS = auto()
    ALIEN_ZOOKEEPER = auto()
    MODS = auto()
    OTHER_GAMES = auto()
    END_NOTE = auto()
    DEMO = auto()
    QUIT = auto()
    QUIT_AFTER_DEMO = auto()


class StartRun(msgspec.Struct, frozen=True):
    mode: GameMode
    player_count: int
    hardcore: bool
    quest_level: QuestLevel | None = None

    @classmethod
    def from_config(cls, config: CrimsonConfig, mode: GameMode, *, quest_level: QuestLevel | None = None) -> StartRun:
        if mode == GameMode.QUESTS:
            assert quest_level is not None, "quest launch requires a selected level"
        return cls(mode, config.gameplay.player_count, config.gameplay.hardcore, quest_level)


class ScoreQuery(msgspec.Struct):
    game_mode_id: GameMode
    quest_level: QuestLevel | None = None
    highlight_rank: int | None = None

    @classmethod
    def from_config(cls, config: CrimsonConfig) -> ScoreQuery:
        level = (config.gameplay.quest_level or QuestLevel(1, 1)) if config.gameplay.mode == GameMode.QUESTS else None
        return cls(config.gameplay.mode, level)


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


class ShowScores(msgspec.Struct, frozen=True):
    query: ScoreQuery
    return_context: ScoreReturnContext | None = None


class ShowQuestOutcome(msgspec.Struct, frozen=True):
    outcome: QuestRunOutcome


class ResultAction(Enum):
    PLAY_AGAIN = auto()
    PLAY_NEXT = auto()
    HIGH_SCORES = auto()
    MAIN_MENU = auto()


type ScreenAction = Route | StartRun | ShowScores | ShowQuestOutcome
