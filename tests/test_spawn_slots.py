from __future__ import annotations

import pytest

from crimson.creatures.spawn import SpawnSlotInit, tick_spawn_slot
from tests.helpers import assert_float_close


@pytest.mark.parametrize(
    ("timer", "count", "dt", "expected_spawn", "expected_timer", "expected_count"),
    [
        (1.0, 0, 0.3, None, 0.7, 0),
        (0.1, 0, 0.3, 0x41, 0.5, 1),
        (0.1, 10, 0.3, None, 0.5, 10),
        (0.1, 0, 2.0, 0x41, -1.2, 1),
    ],
    ids=["no-trigger", "triggers-and-increments", "resets-at-limit", "does-not-loop-large-dt"],
)
def test_tick_spawn_slot_behavior(
    timer: float,
    count: int,
    dt: float,
    expected_spawn: int | None,
    expected_timer: float,
    expected_count: int,
) -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=timer,
        count=count,
        limit=10,
        interval=0.7,
        child_template_id=0x41,
    )

    assert tick_spawn_slot(slot, dt) == expected_spawn
    assert_float_close(slot.timer, expected_timer)
    assert slot.count == expected_count


def test_tick_spawn_slot_uses_float32_cadence_at_boundary() -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=2.4,
        count=0,
        limit=10,
        interval=2.4,
        child_template_id=0x41,
    )

    spawn_ticks: list[int] = []
    for tick in range(1, 26):
        if tick_spawn_slot(slot, 0.1) is not None:
            spawn_ticks.append(tick)

    # Native float32 timer arithmetic crosses this boundary on tick 25, not 24.
    assert spawn_ticks == [25]
