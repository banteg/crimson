from __future__ import annotations

from crimson.creatures.spawn import SpawnSlotInit, tick_spawn_slot
from tests.helpers import assert_float_close


def test_tick_spawn_slot_no_trigger() -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=1.0,
        count=0,
        limit=10,
        interval=0.7,
        child_template_id=0x41,
    )

    assert tick_spawn_slot(slot, 0.3) is None
    assert_float_close(slot.timer, 0.7)
    assert slot.count == 0


def test_tick_spawn_slot_triggers_and_increments_count() -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=0.1,
        count=0,
        limit=10,
        interval=0.7,
        child_template_id=0x41,
    )

    assert tick_spawn_slot(slot, 0.3) == 0x41
    assert_float_close(slot.timer, 0.5)
    assert slot.count == 1


def test_tick_spawn_slot_resets_timer_even_when_at_limit() -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=0.1,
        count=10,
        limit=10,
        interval=0.7,
        child_template_id=0x41,
    )

    assert tick_spawn_slot(slot, 0.3) is None
    assert_float_close(slot.timer, 0.5)
    assert slot.count == 10


def test_tick_spawn_slot_does_not_loop_when_dt_is_large() -> None:
    slot = SpawnSlotInit(
        owner_creature=0,
        timer=0.1,
        count=0,
        limit=10,
        interval=0.7,
        child_template_id=0x41,
    )

    assert tick_spawn_slot(slot, 2.0) == 0x41
    assert_float_close(slot.timer, -1.2)
    assert slot.count == 1


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
