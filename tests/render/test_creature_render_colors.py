from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from crimson.creatures.spawn import CreatureFlags
from crimson.render.world.creatures import creature_color_byte, creature_render_tint, creature_shadow_alpha
from grim.color import RGBA
from tests.support.creature_draw_capture import capture_creature_draws

WITNESSES = json.loads(
    (Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/creature-render-colors.json").read_text(),
)["cases"]


def _bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


@pytest.mark.parametrize("witness", WITNESSES, ids=lambda row: row["input"]["name"])
def test_creature_color_float_words_match_native(witness) -> None:
    case = witness["input"]
    creatures = {row["index"]: row for row in case["creatures"]}
    for draw in witness["expected"]:
        creature = creatures[draw["index"]]
        if draw["pass"] == "body":
            tint = creature_render_tint(
                RGBA(*(creature[f"tint_{channel}"] for channel in "rgba")),
                max_hp=creature["max_health"],
                energizer_timer=case["energizer"],
                lifecycle_stage=creature["lifecycle_stage"],
                transition=case["transition"],
            )
            assert [_bits(channel) for channel in tint] == draw["rgba_bits"]
            packed = sum(
                creature_color_byte(channel) << shift for channel, shift in zip(tint, (16, 8, 0, 24), strict=True)
            )
            assert packed == draw["packed_color"]
        elif draw["pass"] == "shadow":
            alpha = creature_shadow_alpha(
                creature["tint_a"],
                flags=CreatureFlags(creature["flags"]),
                lifecycle_stage=creature["lifecycle_stage"],
                transition=case["transition"],
            )
            assert _bits(alpha) == draw["rgba_bits"][3]
            assert creature_color_byte(alpha) == draw["packed_color"] >> 24


@pytest.mark.parametrize("texture_size", [256, 512])
@pytest.mark.parametrize("witness", WITNESSES, ids=lambda row: row["input"]["name"])
def test_creature_draw_colors_match_native(witness, texture_size) -> None:
    drawn = capture_creature_draws(witness["input"], texture_size=texture_size, include_color=True)
    assert len(drawn) == len(witness["expected"])
    for actual, native in zip(drawn, witness["expected"], strict=True):
        assert {key: actual[key] for key in ("pass", "index", "frame")} == {
            key: native[key] for key in ("pass", "index", "frame")
        }
        expected = [(native["packed_color"] >> shift) & 255 for shift in (16, 8, 0, 24)]
        if native["pass"] == "shadow":
            expected[:3] = [0, 0, 0]
        assert actual["rgba"] == expected
