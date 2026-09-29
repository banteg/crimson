from __future__ import annotations

from grim.fonts.small import SmallFontData, measure_small_text_width

from ..perks import PerkId, perk_display_description

# `perks_init_database` wraps every perk description to 0x100 px.
PERK_DESCRIPTION_WRAP_PX = 0x100


def wrap_text_to_width(font: SmallFontData, text: str, max_width_px: int) -> str:
    """`wrap_text_to_width_alloc`: once the glyph widths run past the line, the last space becomes a newline."""
    wrapped = list(text)
    remaining = max_width_px
    i = 0
    while i < len(wrapped):
        remaining -= int(measure_small_text_width(font, wrapped[i]))
        if remaining < 0:
            # Native walks back to the previous space without a bound; the port stops at the start.
            while i > 0 and wrapped[i] != " ":
                i -= 1
            remaining = max_width_px
            wrapped[i] = "\n"
        i += 1
    return "".join(wrapped)


def perk_description_wrapped(font: SmallFontData, perk_id: PerkId, *, violence_disabled: int) -> str:
    """The perk's description as `perks_init_database` stores it, wrapped to 256 px."""
    return wrap_text_to_width(
        font, perk_display_description(perk_id, violence_disabled=violence_disabled), PERK_DESCRIPTION_WRAP_PX,
    )
