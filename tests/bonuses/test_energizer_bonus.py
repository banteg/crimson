from __future__ import annotations

import math

from crimson.bonuses import BonusId
from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.factories import make_creature_update_options


def _wrap_angle(angle: float) -> float:
    return (angle + math.pi) % math.tau - math.pi


def _angle_delta(a: float, b: float) -> float:
    return _wrap_angle(a - b)


def test_energizer_inverts_target_heading_for_weak_creatures() -> None:
    state = GameplayState()
    state.bonuses.energizer = 1.0

    player = PlayerState(index=0, pos=Vec2(300.0, 100.0))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.max_hp = 400.0

    pool.update(0.016, options=make_creature_update_options(state=state, players=[player]))

    base_heading = math.atan2(player.pos.y - creature.pos.y, player.pos.x - creature.pos.x) + math.pi / 2.0
    expected = _wrap_angle(base_heading + math.pi)
    assert abs(_angle_delta(float(creature.target_heading), expected)) < 1e-6


def test_energizer_eat_kills_award_xp_without_contact_damage() -> None:
    state = GameplayState()
    state.bonuses.energizer = 1.0

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = player.pos + Vec2(1.0, 0.0)
    creature.hp = 10.0
    creature.max_hp = 300.0
    creature.reward_value = 10.0
    creature.contact_damage = 999.0

    result = pool.update(0.016, options=make_creature_update_options(state=state, players=[player]))

    assert len(result.deaths) == 1
    assert not creature.active
    # Native double-pays the eat kill: a direct exp += reward store in
    # creature_update_all plus creature_handle_death's own award.
    assert player.experience == 20
    assert player.health == 100.0
    assert SfxId.UI_BONUS in result.sfx
    assert not any(entry.bonus_id != BonusId.UNUSED for entry in state.bonus_pool.entries)
