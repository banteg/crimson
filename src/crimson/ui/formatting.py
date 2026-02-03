from __future__ import annotations


def format_ordinal(value_1_based: int) -> str:
    value = int(value_1_based)
    if value % 100 in (11, 12, 13):
        suffix = "th"
    elif value % 10 == 1:
        suffix = "st"
    elif value % 10 == 2:
        suffix = "nd"
    elif value % 10 == 3:
        suffix = "rd"
    else:
        suffix = "th"
    return f"{value}{suffix}"


def format_time_mm_ss(ms: int) -> str:
    total_s = max(0, int(ms)) // 1000
    minutes = total_s // 60
    seconds = total_s % 60
    return f"{minutes}:{seconds:02d}"

