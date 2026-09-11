"""Shared original-executable primary impact and presentation witnesses."""

import json
from pathlib import Path

import pytest

from tests.support.primary_impact import compare

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/primary-impact-presentation.json"


@pytest.mark.parametrize("witness", json.loads(FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_primary_impact_matches_native(witness) -> None:
    compare(witness)
