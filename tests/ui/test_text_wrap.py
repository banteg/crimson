from __future__ import annotations

from crimson.perks import PerkId
from crimson.ui.text_wrap import PERK_DESCRIPTION_WRAP_PX, perk_description_wrapped, wrap_text_to_width
from grim.assets import RuntimeResources
from grim.fonts.small import measure_small_text_width


def test_the_space_before_the_overflowing_glyph_becomes_a_newline(headless_resources: RuntimeResources) -> None:
    font = headless_resources.small_font
    width = int(measure_small_text_width(font, "alpha be"))

    assert wrap_text_to_width(font, "alpha beta", width) == "alpha\nbeta"
    assert wrap_text_to_width(font, "alpha beta", width + 100) == "alpha beta"


def test_perk_descriptions_wrap_within_256_px(headless_resources: RuntimeResources) -> None:
    font = headless_resources.small_font
    for perk_id in PerkId:
        text = perk_description_wrapped(font, perk_id, violence_disabled=0)
        for line in text.split("\n"):
            assert sum(int(measure_small_text_width(font, glyph)) for glyph in line) <= PERK_DESCRIPTION_WRAP_PX, line
