"""Native particle impacts shared with the Zig runtime regressions."""

import json
from pathlib import Path

import pytest

from tests.support.particle_impact import compare

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/particle-impact.json"


@pytest.mark.parametrize("witness", json.loads(FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_particle_impact_native(witness) -> None:
    compare(witness)
