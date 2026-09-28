from __future__ import annotations

_MONTH_LABELS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def format_ordinal(value: int) -> str:
    """`format_ordinal`: 8..20 take "th"; otherwise the last digit picks st/nd/rd."""
    if value < 8 or value > 20:
        match value % 10:
            case 1:
                return f"{value}st"
            case 2:
                return f"{value}nd"
            case 3:
                return f"{value}rd"
    return f"{value}th"


def highscore_format_date_label(day: int, month_index: int, year: int) -> str:
    month = _MONTH_LABELS[month_index - 1] if 1 <= month_index <= 12 else "???"
    return f"{day}. {month} {year}"


def format_time_mm_ss(ms: int) -> str:
    total_s = max(0, int(ms)) // 1000
    minutes = total_s // 60
    seconds = total_s % 60
    return f"{minutes}:{seconds:02d}"
