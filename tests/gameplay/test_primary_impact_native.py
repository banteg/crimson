"""Shared original-executable primary impact and presentation witnesses."""

import json
from pathlib import Path

import pytest

from tests.support.primary_impact import compare

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/primary-impact-presentation.json"
POST_FIXTURES = FIXTURES.with_name("primary-post-hit-position.json")


@pytest.mark.parametrize("witness", json.loads(FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_primary_impact_matches_native(witness) -> None:
    compare(witness)


@pytest.mark.parametrize("witness", json.loads(POST_FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_primary_post_hit_position_matches_native(witness) -> None:
    compare(witness)
