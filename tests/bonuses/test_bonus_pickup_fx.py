from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.effects_atlas import EffectId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import BonusPickupEvent, PlayerState
from crimson.sim.world_state import WorldEvents, WorldState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, player_input


def _step_world_over_bonuses(
    bonuses: list[tuple[Vec2, BonusId]],
) -> tuple[WorldState, WorldEvents, list[RngCallerStatic]]:
    """Step one real world tick with a player at (512, 512) over `bonuses`; return `bonus_apply` RNG callers."""
    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    state = world.state
    for pos, bonus_id in bonuses:
        assert state.bonus_pool.spawn_at(pos=pos, bonus_id=bonus_id, state=state) is not None
    rng = state.rng
    assert isinstance(rng, Crand)
    rng.srand(0x150767)
    callers: list[RngCallerStatic] = []
    rng.set_trace_sink(
        lambda _before, _after, _value, caller: callers.append(RngCallerStatic(caller)) if caller is not None else None,
    )
    events = world.step(
        0.016,
        inputs=[player_input() for _ in world.players],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )
    return world, events, [caller for caller in callers if caller.name.startswith("BONUS_APPLY_")]


def test_reflex_boost_and_freeze_pickups_spawn_ring_and_burst() -> None:
    world, events, _callers = _step_world_over_bonuses(
        [(Vec2(500.0, 512.0), BonusId.REFLEX_BOOST), (Vec2(524.0, 512.0), BonusId.FREEZE)],
    )

    assert [pickup.bonus_id for pickup in events.pickups] == [BonusId.REFLEX_BOOST, BonusId.FREEZE]
    effect_ids = [int(effect.effect_id) for effect in world.state.effects.iter_active()]
    # Each `bonus_spawn_at` left its 16-particle burst alive (0.5s lifetime); each pickup adds 12.
    assert effect_ids.count(int(EffectId.BURST)) == 2 * 16 + 2 * 12
    assert effect_ids.count(int(EffectId.RING)) == 2


def _update_bonus_pool(world: WorldState, dt: float) -> list[BonusPickupEvent]:
    return world.state.bonus_pool.update(
        dt,
        step_runtime=make_step_runtime(world, dt=dt),
        state=world.state,
        players=world.players,
        creatures=world.creatures.entries,
    )


def test_coop_players_on_same_bonus_both_apply_in_one_tick() -> None:
    world = make_world(player_count=2)
    entry = world.state.bonus_pool.spawn_at(
        pos=Vec2(500.0, 500.0),
        bonus_id=BonusId.SHIELD,
        state=world.state,
    )
    assert entry is not None

    players = world.players
    players[0].pos = Vec2(500.0, 500.0)
    players[1].pos = Vec2(510.0, 500.0)
    pickups = _update_bonus_pool(world, 0.016)

    # Native's pickup loop has no break: both in-range players apply the bonus.
    assert [pickup.player_index for pickup in pickups] == [0, 1]
    assert players[0].shield_timer > 0.0
    assert players[1].shield_timer > 0.0
