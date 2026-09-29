from __future__ import annotations

import math

from crimson.bonuses import BonusId
from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE
from crimson.creatures.spawn import CreatureFlags
from crimson.math_parity import f32, x87_pc24_sub
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures


def _wrap_angle(angle: float) -> float:
    return (angle + math.pi) % math.tau - math.pi


def _angle_delta(a: float, b: float) -> float:
    return _wrap_angle(a - b)


def test_energizer_inverts_target_heading_for_weak_creatures() -> None:
    world = make_world()
    world.state.bonuses.energizer = 1.0

    player = world.players[0]
    player.pos = Vec2(300.0, 100.0)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.max_hp = 400.0

    step_creatures(world, 0.016)

    base_heading = math.atan2(player.pos.y - creature.pos.y, player.pos.x - creature.pos.x) + math.pi / 2.0
    expected = _wrap_angle(base_heading + math.pi)
    assert abs(_angle_delta(float(creature.target_heading), expected)) < 1e-6


def test_energizer_eat_kills_award_xp_without_contact_damage() -> None:
    world = make_world()
    state = world.state
    state.bonuses.energizer = 1.0
    state.bonus_spawn_guard = True

    player = world.players[0]
    player.pos = Vec2(-10.0, 0.0)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = player.pos
    creature.hp = 10.0
    creature.max_hp = 300.0
    creature.size = 20.0
    creature.move_speed = 0.0
    creature.reward_value = 10.0
    creature.contact_damage = 999.0

    step_runtime = step_creatures(world, 0.016)

    assert len(step_runtime.deaths) == 1
    assert not creature.active
    # Native double-pays the eat kill: a direct exp += reward store in
    # creature_update_all plus creature_handle_death's own award.
    assert player.experience == 20
    assert player.health == 100.0
    assert SfxId.UI_BONUS in sfx_ids(step_runtime.sfx)
    assert not any(entry.bonus_id != BonusId.UNUSED for entry in state.bonus_pool.entries)
    assert creature.pos == Vec2(-10.0, 0.0)
    assert not state.bonus_spawn_guard
    # Native returns from no-corpse death into the unconditional size-30 tail.
    assert creature.hp == 0.0
    assert creature.lifecycle_stage == x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, f32(0.016))
