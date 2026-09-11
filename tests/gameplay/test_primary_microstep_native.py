"""Shared native movement-threshold and player-hit witnesses."""

import json
from pathlib import Path

import pytest

from tests.support.primary_microstep import compare

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/primary-microstep-threshold.json"


@pytest.mark.parametrize("witness", json.loads(FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_primary_microstep_matches_native(witness) -> None:
    compare(witness)
