from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.update import bonus_telekinetic_update
from crimson.perks import PerkId
from crimson.sim.state_types import BonusPickupEvent
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime


def _telekinetic_update(world: WorldState, *, dt: float) -> list[BonusPickupEvent]:
    return bonus_telekinetic_update(
        world.state,
        world.players,
        dt=dt,
        step_runtime=make_step_runtime(world, dt=dt),
        creatures=world.creatures.entries,
    )


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
