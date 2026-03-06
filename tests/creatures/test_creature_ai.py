from __future__ import annotations

from dataclasses import dataclass, field

from crimson.creatures.ai import creature_ai7_tick_link_timer, creature_ai_update_target
from crimson.creatures.spawn import CreatureAiMode, CreatureFlags
from crimson.math_parity import f32
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


@dataclass(slots=True)
class StubCreature:
    pos: Vec2
    hp: float = 1.0
    flags: CreatureFlags = CreatureFlags(0)
    ai_mode: CreatureAiMode = CreatureAiMode.ORBIT_PLAYER
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
    c = StubCreature(
        pos=Vec2(),
        flags=CreatureFlags.AI7_LINK_TIMER,
        link_index=-10,
        ai_mode=CreatureAiMode.ORBIT_PLAYER,
    )
    creature_ai7_tick_link_timer(c, dt_ms=10, rand=lambda: 0)
    assert c.ai_mode == CreatureAiMode.HOLD_TIMER
    assert c.link_index == 500


def test_ai7_tick_link_timer_positive_rolls_back_negative() -> None:
    c = StubCreature(pos=Vec2(), flags=CreatureFlags.AI7_LINK_TIMER, link_index=1, ai_mode=CreatureAiMode.HOLD_TIMER)
    creature_ai7_tick_link_timer(c, dt_ms=1, rand=lambda: 0)
    assert c.link_index == -700


def test_ai_mode_0_orbits_when_close() -> None:
    c = StubCreature(pos=Vec2(), ai_mode=CreatureAiMode.ORBIT_PLAYER, phase_seed=0.0)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), creatures=[c], dt=1.0 / 60.0)
    assert_float_close(ai.move_scale, 1.0)
    assert_float_close(c.target.x, 185.0)
    assert_float_close(c.target.y, 0.0)
    assert c.force_target == 0


def test_ai_mode_5_scales_down_near_link() -> None:
    link = StubCreature(pos=Vec2(100.0, 100.0), hp=10.0)
    c = StubCreature(
        pos=Vec2(100.0, 50.0),
        ai_mode=CreatureAiMode.FOLLOW_LINK_TETHERED,
        link_index=0,
        target_offset=Vec2(),
    )
    ai = creature_ai_update_target(c, player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)
    assert c.force_target == 0
    assert_float_close(c.target.x, 100.0)
    assert_float_close(c.target.y, 100.0)
    assert_float_close(ai.move_scale, 50.0 * 0.015625)


def test_ai_mode_4_link_dead_self_damage() -> None:
    dead = StubCreature(pos=Vec2(), hp=0.0)
    c = StubCreature(pos=Vec2(10.0, 10.0), ai_mode=CreatureAiMode.LINK_GUARD, link_index=0)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), creatures=[dead, c], dt=1.0 / 60.0)
    assert c.ai_mode == CreatureAiMode.ORBIT_PLAYER
    assert ai.self_damage == 1000.0


def test_ai_mode_6_orbits_linked_creature() -> None:
    link = StubCreature(pos=Vec2(100.0, 0.0), hp=10.0)
    c = StubCreature(
        pos=Vec2(),
        ai_mode=CreatureAiMode.ORBIT_LINK,
        link_index=0,
        orbit_angle=0.0,
        orbit_radius=10.0,
        heading=0.0,
    )
    ai = creature_ai_update_target(c, player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)
    assert ai.self_damage is None
    assert c.ai_mode == CreatureAiMode.ORBIT_LINK
    assert c.force_target == 0
    assert_float_close(c.target.x, 110.0)
    assert_float_close(c.target.y, 0.0)


def test_ai_mode_7_orbit_radius_timer_counts_down() -> None:
    c = StubCreature(pos=Vec2(), ai_mode=CreatureAiMode.HOLD_TIMER, orbit_radius=1.5)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), creatures=[c], dt=0.5)
    assert ai.self_damage is None
    assert c.ai_mode == CreatureAiMode.HOLD_TIMER
    assert_float_close(c.orbit_radius, 1.0)


def test_ai_targets_and_heading_are_float32_quantized() -> None:
    c = StubCreature(pos=Vec2(0.125, -0.25), ai_mode=CreatureAiMode.ORBIT_PLAYER, phase_seed=13.0)
    creature_ai_update_target(c, player_pos=Vec2(123.5, 456.25), creatures=[c], dt=1.0 / 60.0)
    assert_float_close(c.target.x, f32(c.target.x))
    assert_float_close(c.target.y, f32(c.target.y))
    assert_float_close(c.target_heading, f32(c.target_heading))
