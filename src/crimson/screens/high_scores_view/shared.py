from __future__ import annotations

from ...game_modes import GameMode


def mode_label(mode_id: GameMode, quest_major: int, quest_minor: int) -> str:
    match mode_id:
        case GameMode.SURVIVAL:
            return "Survival"
        case GameMode.RUSH:
            return "Rush"
        case GameMode.TYPO:
            return "Typ-o Shooter"
        case GameMode.QUESTS:
            if int(quest_major) > 0 and int(quest_minor) > 0:
                return f"Quest {int(quest_major)}.{int(quest_minor)}"
            return "Quests"
        case _:
            return "Unknown"
__all__ = ["mode_label"]
