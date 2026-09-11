from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from tests.support.creature_draw_capture import capture_creature_draws

WITNESSES = json.loads(
    (Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/creature-pass-order.json").read_text(),
)["cases"]


@pytest.mark.parametrize("texture_size", [256, 512])
@pytest.mark.parametrize("witness", WITNESSES, ids=lambda row: row["input"]["name"])
def test_creature_pass_order_frames_and_sizes_match_native(witness, texture_size) -> None:
    drawn = capture_creature_draws(witness["input"], texture_size=texture_size)
    expected = witness["expected"]
    assert len(drawn) == len(expected)
    for actual, native in zip(drawn, expected, strict=True):
        assert {name: actual[name] for name in ("index", "type_id", "pass", "frame")} == {
            name: native[name] for name in ("index", "type_id", "pass", "frame")
        }
        width, height = struct.unpack("<2f", struct.pack("<2I", *native["quad_bits"][2:]))
        # Shadow geometry still uses the backend's arithmetic; body sizes are exact.
        if native["pass"] == "shadow":
            assert actual["width"] == pytest.approx(width, rel=1e-6)
            assert actual["height"] == pytest.approx(height, rel=1e-6)
        else:
            assert (actual["width"], actual["height"]) == (width, height)
