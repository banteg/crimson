from __future__ import annotations

import pytest

from crimson.creatures.spawn import SpawnSlotInit, tick_spawn_slot


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
    assert slot.timer == pytest.approx(0.7, abs=1e-9)
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
    assert slot.timer == pytest.approx(0.5, abs=1e-9)
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
    assert slot.timer == pytest.approx(0.5, abs=1e-9)
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
    assert slot.timer == pytest.approx(-1.2, abs=1e-9)
    assert slot.count == 1

