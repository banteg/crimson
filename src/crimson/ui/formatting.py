from __future__ import annotations

_MONTH_LABELS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def format_ordinal(value: int) -> str:
    """`format_ordinal`: 8..20 take "th"; otherwise the last digit picks st/nd/rd. A rank the card does not know (a
    replay watched from its file), which no screen of the original's asks for, is a dash."""
    if value <= 0:
        return "-"
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
    """`time_format_mm_ss(ms / 1000)`, signed: quest final times can go negative, which native prints as "0:0-1"."""
    total_s = abs(int(ms)) // 1000
    sign = "-" if ms < 0 else ""
    return f"{sign}{total_s // 60}:{total_s % 60:02d}"
