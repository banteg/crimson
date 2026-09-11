"""Native particle trajectories shared with the Zig runtime regressions."""

import json
from pathlib import Path

import pytest

from tests.support.particle_update import compare

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/particle-update.json"


@pytest.mark.parametrize("witness", json.loads(FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_particle_update_native_trajectory(witness) -> None:
    compare(witness)
