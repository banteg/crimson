from __future__ import annotations

from enum import IntEnum


class GameMode(IntEnum):
    """Known `game_mode` ids from the original config / highscore tables."""

    DEMO = 0
    SURVIVAL = 1
    RUSH = 2
    QUESTS = 3
    TYPO = 4
    TUTORIAL = 8

