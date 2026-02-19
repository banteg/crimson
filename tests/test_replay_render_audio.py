from __future__ import annotations

import pytest

from crimson.sim.driver.replay_render import ReplayRenderError, _build_atempo_filters


def test_build_atempo_filters_identity_tempo_returns_empty() -> None:
    assert _build_atempo_filters(1.0) == []


def test_build_atempo_filters_splits_large_tempo() -> None:
    assert _build_atempo_filters(3.0) == ["atempo=2.000000000", "atempo=1.500000000"]


def test_build_atempo_filters_splits_small_tempo() -> None:
    assert _build_atempo_filters(0.125) == [
        "atempo=0.500000000",
        "atempo=0.500000000",
        "atempo=0.500000000",
    ]


def test_build_atempo_filters_rejects_invalid_tempo() -> None:
    with pytest.raises(ReplayRenderError, match="invalid audio tempo factor"):
        _build_atempo_filters(0.0)
