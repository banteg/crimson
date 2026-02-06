from __future__ import annotations

import math

import pytest

from crimson.creatures.spawn import (
    build_tutorial_stage3_fire_spawns,
    build_tutorial_stage4_clear_spawns,
    build_tutorial_stage5_repeat_spawns,
    build_tutorial_stage6_perks_done_spawns,
)


def _assert_call(call, *, template_id: int, x: float, y: float) -> None:
    assert call.template_id == template_id
    assert call.pos.x == pytest.approx(x, abs=1e-9)
    assert call.pos.y == pytest.approx(y, abs=1e-9)
    assert call.heading == pytest.approx(math.pi, abs=1e-9)


def test_build_tutorial_stage3_fire_spawns() -> None:
    spawns = build_tutorial_stage3_fire_spawns()
    assert len(spawns) == 3
    _assert_call(spawns[0], template_id=0x24, x=-164.0, y=412.0)
    _assert_call(spawns[1], template_id=0x26, x=-184.0, y=512.0)
    _assert_call(spawns[2], template_id=0x24, x=-154.0, y=612.0)


def test_build_tutorial_stage4_clear_spawns() -> None:
    spawns = build_tutorial_stage4_clear_spawns()
    assert len(spawns) == 3
    _assert_call(spawns[0], template_id=0x24, x=1188.0, y=412.0)
    _assert_call(spawns[1], template_id=0x26, x=1208.0, y=512.0)
    _assert_call(spawns[2], template_id=0x24, x=1178.0, y=612.0)


def test_build_tutorial_stage6_perks_done_spawns() -> None:
    spawns = build_tutorial_stage6_perks_done_spawns()
    assert len(spawns) == 7
    _assert_call(spawns[0], template_id=0x24, x=-164.0, y=412.0)
    _assert_call(spawns[1], template_id=0x26, x=-184.0, y=512.0)
    _assert_call(spawns[2], template_id=0x24, x=-154.0, y=612.0)
    _assert_call(spawns[3], template_id=0x28, x=-32.0, y=-32.0)
    _assert_call(spawns[4], template_id=0x24, x=1188.0, y=412.0)
    _assert_call(spawns[5], template_id=0x26, x=1208.0, y=512.0)
    _assert_call(spawns[6], template_id=0x24, x=1178.0, y=612.0)


@pytest.mark.parametrize(
    ("repeat", "expected_calls"),
    [
        (
            1,
            [
                (0x27, -32.0, 1056.0),
                (0x24, -164.0, 412.0),
                (0x26, -184.0, 512.0),
                (0x24, -154.0, 612.0),
            ],
        ),
        (
            2,
            [
                (0x27, 1056.0, 1056.0),
                (0x24, 1188.0, 1136.0),
                (0x26, 1208.0, 512.0),
                (0x24, 1178.0, 612.0),
            ],
        ),
        (
            4,
            [
                (0x27, 1056.0, 1056.0),
                (0x24, 1188.0, 1136.0),
                (0x26, 1208.0, 512.0),
                (0x24, 1178.0, 612.0),
                (0x40, 512.0, 1056.0),
            ],
        ),
        (
            6,
            [
                (0x24, 1188.0, 1136.0),
                (0x26, 1208.0, 512.0),
                (0x24, 1178.0, 612.0),
            ],
        ),
        (0, []),
        (8, []),
    ],
)
def test_build_tutorial_stage5_repeat_spawns(repeat: int, expected_calls: list[tuple[int, float, float]]) -> None:
    spawns = build_tutorial_stage5_repeat_spawns(repeat)
    assert len(spawns) == len(expected_calls)
    for call, (template_id, x, y) in zip(spawns, expected_calls, strict=True):
        _assert_call(call, template_id=template_id, x=x, y=y)

