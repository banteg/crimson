from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.update import bonus_telekinetic_update
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.state_types import BonusPickupEvent
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state, make_step_runtime, place_creatures
from tests.support.helpers import assert_float_close


def _telekinetic_update(world: WorldState, *, dt: float) -> list[BonusPickupEvent]:
    return bonus_telekinetic_update(
        world.state,
        world.players,
        dt=dt,
        step_runtime=make_step_runtime(world, dt=dt),
        creatures=world.creatures.entries,
    )


def test_telekinetic_picks_up_bonus_after_hover_time() -> None:
    world = make_world()
    state = world.state
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert entry is not None

    player = world.players[0]
    player.aim = Vec2(100.0, 100.0)
    assert _telekinetic_update(world, dt=0.7) == []
    assert entry.picked is False

    player.bonus_aim_hover_timer_ms = 0.0
    state.perks[int(PerkId.TELEKINETIC)] = 1
    pickups = _telekinetic_update(world, dt=0.7)

    assert len(pickups) == 1
    assert entry.picked is True
    assert player.experience == 500


def test_telekinetic_hover_timer_accumulates_whole_frame_milliseconds() -> None:
    world = make_world()
    state = world.state
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert entry is not None
    player = world.players[0]
    player.aim = Vec2(100.0, 100.0)
    state.perks[int(PerkId.TELEKINETIC)] = 1

    # bonus_render adds the int frame_dt_ms: 60 Hz frames add __ftol(16.67) = 16,
    # so the > 650 ms gate passes on frame 41 (656 ms), not on frame 39.
    for _ in range(40):
        _telekinetic_update(world, dt=f32(1.0 / 60.0))
    assert entry.picked is False
    assert player.bonus_aim_hover_timer_ms == 640
    _telekinetic_update(world, dt=f32(1.0 / 60.0))
    assert entry.picked is True


def test_telekinetic_nuke_origin_is_bonus_position() -> None:
    world = make_world()
    state = world.state
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.NUKE, state=state)
    assert entry is not None

    world.players[0].aim = Vec2(100.0, 100.0)
    state.perks[int(PerkId.TELEKINETIC)] = 1

    _telekinetic_update(world, dt=0.7)

    active = [proj for proj in state.projectiles.entries if proj.active]
    assert active
    for proj in active:
        assert_float_close(proj.pos.x, 100.0)
        assert_float_close(proj.pos.y, 100.0)


def test_telekinetic_shock_chain_origin_is_bonus_position() -> None:
    world = make_world()
    state = world.state
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.SHOCK_CHAIN, state=state)
    assert entry is not None

    world.players[0].aim = Vec2(100.0, 100.0)
    state.perks[int(PerkId.TELEKINETIC)] = 1
    place_creatures(world, [make_creature_state(pos=Vec2(140.0, 100.0), hp=10.0)])

    _telekinetic_update(world, dt=0.7)

    proj_id = int(state.shock_chain_projectile_id)
    assert proj_id != -1
    proj = state.projectiles.entries[proj_id]
    assert_float_close(proj.pos.x, 100.0)
    assert_float_close(proj.pos.y, 100.0)


def test_telekinetic_picks_only_one_bonus_per_frame_across_players() -> None:
    world = make_world(player_count=2)
    state = world.state
    first = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    second = state.bonus_pool.spawn_at(pos=Vec2(200.0, 200.0), bonus_id=BonusId.POINTS, state=state)
    assert first is not None
    assert second is not None

    world.players[0].aim = Vec2(100.0, 100.0)
    world.players[1].aim = Vec2(200.0, 200.0)
    state.perks[int(PerkId.TELEKINETIC)] = 1

    pickups = _telekinetic_update(world, dt=0.7)

    assert len(pickups) == 1
    assert pickups[0].player_index == 0
    assert first.picked is True
    assert second.picked is False


def test_telekinetic_hover_timer_carries_across_bonus_switch() -> None:
    world = make_world()
    state = world.state
    first = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    second = state.bonus_pool.spawn_at(pos=Vec2(130.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert first is not None
    assert second is not None

    player = world.players[0]
    player.aim = Vec2(100.0, 100.0)
    state.perks[int(PerkId.TELEKINETIC)] = 1

    assert _telekinetic_update(world, dt=0.4) == []
    assert first.picked is False
    assert second.picked is False

    player.aim = Vec2(130.0, 100.0)
    pickups = _telekinetic_update(world, dt=0.3)

    assert len(pickups) == 1
    assert pickups[0].bonus_id == BonusId.POINTS
    assert_float_close(pickups[0].pos.x, 130.0)
    assert_float_close(pickups[0].pos.y, 100.0)
    assert first.picked is False
    assert second.picked is True
