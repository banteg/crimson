from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.quests.level import QuestLevel

from ...game_modes import GameMode

if TYPE_CHECKING:
    from ...persistence.highscores import HighScoreRecord


def ordinal(value: int) -> str:
    n = int(value)
    if 10 <= (n % 100) <= 20:
        return f"{n}th"
    suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def format_elapsed_mm_ss(value_ms: int) -> str:
    total = max(0, int(value_ms)) // 1000
    minutes, seconds = divmod(total, 60)
    return f"{minutes}:{seconds:02d}"


def format_score_date(entry: "HighScoreRecord") -> str:
    day = int(entry.day)
    month = int(entry.month)
    year_off = int(entry.year_offset)
    if day <= 0 or month <= 0:
        return ""
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    month_name = months[month - 1] if 1 <= month <= 12 else f"{month}"
    year = 2000 + year_off if year_off >= 0 else 2000
    return f"{day}. {month_name} {year}"


def parse_quest_level(level: str | None) -> tuple[int, int]:
    parsed = QuestLevel.try_parse(level)
    if parsed is None:
        return (0, 0)
    return parsed.to_stage_pair()


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


def quest_title(major: int, minor: int) -> str:
    from ...quests import quest_by_stage

    q = quest_by_stage(major, minor)
    if q is not None and q.title:
        return str(q.title)
    return "???"


__all__ = [
    "format_elapsed_mm_ss",
    "format_score_date",
    "mode_label",
    "ordinal",
    "parse_quest_level",
    "quest_title",
]
