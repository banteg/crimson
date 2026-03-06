from __future__ import annotations

import pytest

from crimson.creatures.spawn import SpawnId, SpawnSlotInit, tick_spawn_slot
from crimson.math_parity import f32
from tests.support.helpers import assert_float_close


@pytest.mark.parametrize(
    ("timer", "count", "dt", "expected_spawn", "expected_count"),
    [
        (1.0, 0, 0.3, None, 0),
        (0.1, 0, 0.3, SpawnId.ZOMBIE_RANDOM_41, 1),
        (0.1, 10, 0.3, None, 10),
        (0.1, 0, 2.0, SpawnId.ZOMBIE_RANDOM_41, 1),
    ],
    ids=["no-trigger", "triggers-and-increments", "resets-at-limit", "does-not-loop-large-dt"],
)
def test_tick_spawn_slot_behavior(
    timer: float,
    count: int,
    dt: float,
    expected_spawn: SpawnId | None,
    expected_count: int,
) -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=timer,
        count=count,
        limit=10,
        interval=0.7,
        child_template_id=SpawnId.ZOMBIE_RANDOM_41,
    )

    assert tick_spawn_slot(slot, dt) == expected_spawn
    expected_timer = float(f32(float(f32(timer)) - float(f32(dt))))
    if expected_timer < 0.0:
        expected_timer = float(f32(float(expected_timer) + float(f32(slot.interval))))
    assert_float_close(slot.timer, expected_timer)
    assert slot.count == expected_count


def test_tick_spawn_slot_uses_float32_cadence_at_boundary() -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=2.4,
        count=0,
        limit=10,
        interval=2.4,
        child_template_id=SpawnId.ZOMBIE_RANDOM_41,
    )

    spawn_ticks: list[int] = []
    for tick in range(1, 26):
        if tick_spawn_slot(slot, 0.1) is not None:
            spawn_ticks.append(tick)

    # Native float32 timer arithmetic crosses this boundary on tick 25, not 24.
    assert spawn_ticks == [25]
