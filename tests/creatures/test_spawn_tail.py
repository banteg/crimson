from __future__ import annotations

import pytest

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import SpawnId, SpawnSlot
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from grim.rand import Crand


def _spawn(template_id: SpawnId, pos: Vec2, *, hardcore: bool = False, retry_count: int = 0) -> tuple[CreaturePool, GameplayState]:
    pool = CreaturePool()
    state = GameplayState(rng=Crand(0), hardcore=hardcore, quest_fail_retry_count=retry_count)
    pool.spawn_template(template_id, pos, 0.0, state=state, detail_preset=5)
    return pool, state


def _splitter(*, retry_count: int) -> CreatureState:
    pool, _ = _spawn(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), retry_count=retry_count)
    return pool.entries[0]


def _spawner_slot(*, hardcore: bool = False, retry_count: int) -> SpawnSlot:
    pool, _ = _spawn(SpawnId.DEN_ALIEN_BASIC_07, Vec2(100.0, 200.0), hardcore=hardcore, retry_count=retry_count)
    return pool.spawn_slots[pool.entries[0].link_index]


@pytest.mark.parametrize(
    ("pos", "bursts"),
    [
        (Vec2(100.0, 200.0), 8),
        (Vec2(0.0, 200.0), 0),
        (Vec2(1024.0, 200.0), 0),
        (Vec2(100.0, 0.0), 0),
        (Vec2(100.0, 1024.0), 0),
    ],
)
def test_tail_burst_effect_is_gated_by_bounds(pos: Vec2, bursts: int) -> None:
    _, state = _spawn(SpawnId.SPIDER_SP2_SPLITTER_01, pos)

    assert len(state.effects.iter_active()) == bursts


@pytest.mark.parametrize(
    ("retry_count", "reward_scale", "speed_scale", "contact_scale", "health_scale"),
    [
        (1, 0.9, 0.95, 0.95, 0.95),
        (2, 0.85, 0.9, 0.9, 0.9),
        (3, 0.85, 0.8, 0.8, 0.8),
        (4, 0.8, 0.7, 0.7, 0.7),
        (5, 0.8, 0.6, 0.5, 0.5),
    ],
)
def test_tail_applies_retry_count_scaling(
    retry_count: int,
    reward_scale: float,
    speed_scale: float,
    contact_scale: float,
    health_scale: float,
) -> None:
    c = _splitter(retry_count=retry_count)

    # Native multiplies each float field by a float literal at PC24.
    assert c.reward_value == x87_pc24_mul(1000.0, f32(reward_scale))
    assert c.move_speed == x87_pc24_mul(2.0, f32(speed_scale))
    assert c.contact_damage == x87_pc24_mul(17.0, f32(contact_scale))
    assert c.hp == x87_pc24_mul(400.0, f32(health_scale))
    assert c.max_hp == 400.0


def test_tail_applies_hardcore_scaling_and_clears_the_retry_count() -> None:
    pool, state = _spawn(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), hardcore=True, retry_count=4)

    c = pool.entries[0]
    assert c.reward_value == 1000.0
    assert c.move_speed == x87_pc24_mul(2.0, f32(1.05))
    assert c.contact_damage == x87_pc24_mul(17.0, f32(1.4))
    assert c.hp == x87_pc24_mul(400.0, f32(1.2))
    assert c.max_hp == 400.0
    assert state.quest_fail_retry_count == 0


@pytest.mark.parametrize(
    ("retry_count", "expected_extra"),
    [
        (1, x87_pc24_mul(1.0, f32(0.35))),
        (9, 3.0),
    ],
)
def test_tail_spawn_slot_interval_scales_with_retry_count(retry_count: int, expected_extra: float) -> None:
    slot = _spawner_slot(retry_count=retry_count)

    interval = x87_pc24_add(f32(2.2), f32(0.2))
    assert slot.interval == x87_pc24_add(interval, f32(expected_extra))


def test_tail_spawn_slot_interval_hardcore_decrease() -> None:
    slot = _spawner_slot(hardcore=True, retry_count=9)

    assert slot.interval == x87_pc24_sub(f32(2.2), f32(0.2))
