from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from crimson.math_parity import f32
from grim.geom import Vec2
from crimson.creatures.ai import creature_ai7_tick_link_timer, creature_ai_update_target
from crimson.creatures.spawn import CreatureFlags


@dataclass(slots=True)
class StubCreature:
    pos: Vec2
    hp: float = 1.0
    flags: CreatureFlags = CreatureFlags(0)
    ai_mode: int = 0
    link_index: int = 0
    target_offset: Vec2 | None = None
    phase_seed: float = 0.0
    orbit_angle: float = 0.0
    orbit_radius: float = 0.0
    heading: float = 0.0

    target: Vec2 = field(default_factory=Vec2)
    target_heading: float = 0.0
    force_target: int = 0


def test_ai7_tick_link_timer_negative_to_positive_forces_hold() -> None:
    c = StubCreature(pos=Vec2(), flags=CreatureFlags.AI7_LINK_TIMER, link_index=-10, ai_mode=0)
    creature_ai7_tick_link_timer(c, dt_ms=10, rand=lambda: 0)
    assert c.ai_mode == 7
    assert c.link_index == 500


def test_ai7_tick_link_timer_positive_rolls_back_negative() -> None:
    c = StubCreature(pos=Vec2(), flags=CreatureFlags.AI7_LINK_TIMER, link_index=1, ai_mode=7)
    creature_ai7_tick_link_timer(c, dt_ms=1, rand=lambda: 0)
    assert c.link_index == -700


def test_ai_mode_0_orbits_when_close() -> None:
    c = StubCreature(pos=Vec2(), ai_mode=0, phase_seed=0.0)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), creatures=[c], dt=1.0 / 60.0)
    assert ai.move_scale == pytest.approx(1.0)
    assert (c.target.x, c.target.y) == (pytest.approx(185.0, abs=1e-6), pytest.approx(0.0, abs=1e-6))
    assert c.force_target == 0


def test_ai_mode_5_scales_down_near_link() -> None:
    link = StubCreature(pos=Vec2(100.0, 100.0), hp=10.0)
    c = StubCreature(pos=Vec2(100.0, 50.0), ai_mode=5, link_index=0, target_offset=Vec2())
    ai = creature_ai_update_target(c, player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)
    assert c.force_target == 0
    assert (c.target.x, c.target.y) == (pytest.approx(100.0, abs=1e-6), pytest.approx(100.0, abs=1e-6))
    assert ai.move_scale == pytest.approx(50.0 * 0.015625, abs=1e-6)


def test_ai_mode_4_link_dead_self_damage() -> None:
    dead = StubCreature(pos=Vec2(), hp=0.0)
    c = StubCreature(pos=Vec2(10.0, 10.0), ai_mode=4, link_index=0)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), creatures=[dead, c], dt=1.0 / 60.0)
    assert c.ai_mode == 0
    assert ai.self_damage == 1000.0


def test_ai_mode_6_orbits_linked_creature() -> None:
    link = StubCreature(pos=Vec2(100.0, 0.0), hp=10.0)
    c = StubCreature(pos=Vec2(), ai_mode=6, link_index=0, orbit_angle=0.0, orbit_radius=10.0, heading=0.0)
    ai = creature_ai_update_target(c, player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)
    assert ai.self_damage is None
    assert c.ai_mode == 6
    assert c.force_target == 0
    assert (c.target.x, c.target.y) == (pytest.approx(110.0, abs=1e-6), pytest.approx(0.0, abs=1e-6))


def test_ai_mode_7_orbit_radius_timer_counts_down() -> None:
    c = StubCreature(pos=Vec2(), ai_mode=7, orbit_radius=1.5)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), creatures=[c], dt=0.5)
    assert ai.self_damage is None
    assert c.ai_mode == 7
    assert c.orbit_radius == pytest.approx(1.0, abs=1e-6)


def test_ai_targets_and_heading_are_float32_quantized() -> None:
    c = StubCreature(pos=Vec2(0.125, -0.25), ai_mode=0, phase_seed=13.0)
    creature_ai_update_target(c, player_pos=Vec2(123.5, 456.25), creatures=[c], dt=1.0 / 60.0)
    assert c.target.x == pytest.approx(f32(c.target.x), abs=0.0)
    assert c.target.y == pytest.approx(f32(c.target.y), abs=0.0)
    assert c.target_heading == pytest.approx(f32(c.target_heading), abs=0.0)
