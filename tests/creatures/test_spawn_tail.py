from __future__ import annotations

import pytest

from crimson.creatures.spawn import BurstEffect, SpawnEnv, SpawnId, build_spawn_plan
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.helpers import assert_float_close


def test_spawn_plan_tail_burst_effect_is_gated_by_demo_and_bounds() -> None:
    env_demo = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    env_live = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    plan_demo = build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), 0.0, Crand(0), env_demo)
    assert plan_demo.effects == ()

    plan_live = build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), 0.0, Crand(0), env_live)
    assert plan_live.effects == (BurstEffect(pos=Vec2(100.0, 200.0), count=8),)

    assert build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(0.0, 200.0), 0.0, Crand(0), env_live).effects == ()
    assert build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(1024.0, 200.0), 0.0, Crand(0), env_live).effects == ()
    assert build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 0.0), 0.0, Crand(0), env_live).effects == ()
    assert build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 1024.0), 0.0, Crand(0), env_live).effects == ()


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
def test_spawn_plan_tail_applies_retry_count_scaling(
    retry_count: int,
    reward_scale: float,
    speed_scale: float,
    contact_scale: float,
    health_scale: float,
) -> None:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        quest_fail_retry_count=retry_count,
    )
    plan = build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), 0.0, Crand(0), env)

    c = plan.creatures[0]
    assert_float_close(c.reward_value, 1000.0 * reward_scale)
    assert_float_close(c.move_speed or 0.0, 2.0 * speed_scale)
    assert_float_close(c.contact_damage or 0.0, 17.0 * contact_scale)
    assert_float_close(c.health or 0.0, 400.0 * health_scale)
    assert c.max_health == 400.0


def test_spawn_plan_tail_applies_hardcore_scaling_and_ignores_retry_count() -> None:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=True,
        quest_fail_retry_count=4,
    )
    plan = build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), 0.0, Crand(0), env)

    c = plan.creatures[0]
    assert c.reward_value == 1000.0
    assert_float_close(c.move_speed or 0.0, 2.0 * 1.05)
    assert_float_close(c.contact_damage or 0.0, 17.0 * 1.4)
    assert_float_close(c.health or 0.0, 400.0 * 1.2)
    assert c.max_health == 400.0


@pytest.mark.parametrize(
    ("retry_count", "expected_extra"),
    [
        (1, 0.35),
        (9, 3.0),
    ],
)
def test_spawn_plan_tail_spawn_slot_interval_scales_with_retry_count(retry_count: int, expected_extra: float) -> None:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        quest_fail_retry_count=retry_count,
    )
    plan = build_spawn_plan(SpawnId.DEN_ALIEN_BASIC_07, Vec2(100.0, 200.0), 0.0, Crand(0), env)

    assert len(plan.spawn_slots) == 1
    assert_float_close(plan.spawn_slots[0].interval, 2.2 + 0.2 + expected_extra)


def test_spawn_plan_tail_spawn_slot_interval_hardcore_decrease() -> None:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=True,
        quest_fail_retry_count=9,
    )
    plan = build_spawn_plan(SpawnId.DEN_ALIEN_BASIC_07, Vec2(100.0, 200.0), 0.0, Crand(0), env)

    assert len(plan.spawn_slots) == 1
    assert_float_close(plan.spawn_slots[0].interval, 2.2 - 0.2)
