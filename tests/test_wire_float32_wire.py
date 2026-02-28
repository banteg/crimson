from __future__ import annotations

import math

import pytest

from crimson.math_parity import f32
from crimson.wire.float32_wire import assert_wire_f32, wire_f32, wire_f32_opt


def test_wire_f32_narrows_to_f32() -> None:
    value = 0.1
    assert wire_f32(value) == float(f32(value))


def test_wire_f32_rejects_nonfinite() -> None:
    with pytest.raises(ValueError, match="must be finite"):
        wire_f32(math.inf, field="player.pos_x")


def test_wire_f32_opt_allows_none() -> None:
    assert wire_f32_opt(None, field="player.reload_timer") is None


def test_assert_wire_f32_rejects_noncanonical() -> None:
    with pytest.raises(ValueError, match="must be f32-canonical"):
        assert_wire_f32(0.1, field="player.health")


def test_assert_wire_f32_accepts_canonical_value() -> None:
    canonical = float(f32(0.1))
    assert assert_wire_f32(canonical, field="player.health") == canonical
