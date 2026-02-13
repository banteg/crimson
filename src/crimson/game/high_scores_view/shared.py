from __future__ import annotations

from ...quests.types import parse_level


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


def format_score_date(entry: object) -> str:
    try:
        day = int(getattr(entry, "day", 0) or 0)
        month = int(getattr(entry, "month", 0) or 0)
        year_off = int(getattr(entry, "year_offset", 0) or 0)
    except Exception:
        return ""
    if day <= 0 or month <= 0:
        return ""
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    month_name = months[month - 1] if 1 <= month <= 12 else f"{month}"
    year = 2000 + year_off if year_off >= 0 else 2000
    return f"{day}. {month_name} {year}"


def parse_quest_level(level: str | None) -> tuple[int, int]:
    if not level:
        return (0, 0)
    try:
        return parse_level(str(level))
    except ValueError:
        return (0, 0)


def mode_label(mode_id: int, quest_major: int, quest_minor: int) -> str:
    if int(mode_id) == 1:
        return "Survival"
    if int(mode_id) == 2:
        return "Rush"
    if int(mode_id) == 4:
        return "Typ-o Shooter"
    if int(mode_id) == 3:
        if int(quest_major) > 0 and int(quest_minor) > 0:
            return f"Quest {int(quest_major)}.{int(quest_minor)}"
        return "Quests"
    return f"Mode {int(mode_id)}"


def quest_title(major: int, minor: int) -> str:
    from ...quests import quest_by_level

    q = quest_by_level(f"{int(major)}.{int(minor)}")
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
