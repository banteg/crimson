from __future__ import annotations

import json
from pathlib import Path

from crimson.sim.terrain_generate import terrain_generate
from grim.math import f32
from grim.rand import Crand

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "ground"
CASES_PATH = FIXTURE_DIR / "ground_stamp_cases.json"


def test_generated_stamps_match_captured_native_draws() -> None:
    """Each capture holds the raw rotation, y and x `crt_rand()` values of one native terrain generation."""

    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    assert cases, "stamp fixtures must contain captured cases"

    for case in cases:
        slots = (int(case["tex0_index"]), int(case["tex1_index"]), int(case["tex2_index"]))
        setup = terrain_generate(Crand(int(case["seed_state"])), slots)
        layers = setup.layers
        triplets = case["triplets_rot_y_x"]
        # Layer boundaries: 1600 base, 70 overlay and 30 detail stamps.
        captured = (triplets[:1600], triplets[1600:1670], triplets[1670:])
        assert len(triplets) == int(case["stamps"]) == 1700, case["fixture"]
        for name, layer, raw in zip(("base", "overlay", "detail"), (layers.base, layers.overlay, layers.detail), captured, strict=True):
            expected = [
                (f32(float(rot % 314) * f32(0.01)), float(rx % 1152) - 64.0, float(ry % 1152) - 64.0)
                for rot, ry, rx in raw
            ]
            assert [tuple(stamp) for stamp in layer] == expected, f"{case['fixture']} {name}"
