from __future__ import annotations

from pathlib import Path

from crimson.bonuses import BonusId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.effects_atlas import EffectId
from crimson.game_modes import GameMode
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import BonusPickupEvent, PlayerState
from crimson.sim.world_state import WorldEvents, WorldState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime
from tests.support.world_runtime import WorldRuntimeHost

_PICKUP_BURST = [
    RngCallerStatic.BONUS_APPLY_PICKUP_BURST_ROTATION,
    RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_X,
    RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_Y,
] * 12


def _step_world_over_bonuses(
    bonuses: list[tuple[Vec2, BonusId]],
) -> tuple[WorldState, WorldEvents, list[RngCallerStatic]]:
    """Step one real world tick with a player at (512, 512) over `bonuses`; return `bonus_apply` RNG callers."""
    world = WorldState.build(demo_mode_active=False, hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    state = world.state
    for pos, bonus_id in bonuses:
        assert state.bonus_pool.spawn_at(pos=pos, bonus_id=bonus_id, state=state, emit_burst=False) is not None
    rng = state.rng
    assert isinstance(rng, Crand)
    rng.srand(0x150767)
    callers: list[RngCallerStatic] = []
    rng.set_trace_sink(
        lambda _before, _after, _value, caller: callers.append(RngCallerStatic(caller)) if caller is not None else None,
    )
    events = world.step(
        0.016,
        inputs=None,
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    return world, events, [caller for caller in callers if caller.name.startswith("BONUS_APPLY_")]


def test_bonus_pickup_burst_tags_inlined_native_callers() -> None:
    _world, events, callers = _step_world_over_bonuses([(Vec2(512.0, 512.0), BonusId.POINTS)])

    assert [pickup.bonus_id for pickup in events.pickups] == [BonusId.POINTS]
    assert callers == _PICKUP_BURST


def test_reflex_boost_and_freeze_pickups_spawn_ring_and_burst() -> None:
    world, events, _callers = _step_world_over_bonuses(
        [(Vec2(500.0, 512.0), BonusId.REFLEX_BOOST), (Vec2(524.0, 512.0), BonusId.FREEZE)],
    )

    assert [pickup.bonus_id for pickup in events.pickups] == [BonusId.REFLEX_BOOST, BonusId.FREEZE]
    effect_ids = [int(effect.effect_id) for effect in world.state.effects.iter_active()]
    assert effect_ids.count(int(EffectId.BURST)) == 24
    assert effect_ids.count(int(EffectId.RING)) == 2


def test_second_pickup_in_a_tick_draws_after_the_first_pickup_burst() -> None:
    # Two kill drops land 34 units apart, both inside the 26-unit pickup radius.
    # Native `bonus_update` applies both in slot order, and `bonus_apply` draws
    # each pickup burst before returning, so the Points burst precedes Nuke's
    # draws. Nuke itself skips the burst.
    _world, events, callers = _step_world_over_bonuses(
        [(Vec2(495.0, 512.0), BonusId.POINTS), (Vec2(529.0, 512.0), BonusId.NUKE)],
    )

    assert [pickup.bonus_id for pickup in events.pickups] == [BonusId.POINTS, BonusId.NUKE]
    assert callers[: len(_PICKUP_BURST) + 1] == [*_PICKUP_BURST, RngCallerStatic.BONUS_APPLY_NUKE_BULLET_COUNT]
    assert [caller for caller in callers if caller in _PICKUP_BURST] == _PICKUP_BURST


def test_bonus_pickup_spawns_burst_effect() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = runtime.world.players[0]
    entry = runtime.world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.POINTS,
        state=runtime.world.state,
        emit_burst=False,
    )
    assert entry is not None

    assert not runtime.world.state.effects.iter_active()
    runtime.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    active = runtime.world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}


def test_expired_bonus_can_still_pickup_as_unused_in_same_tick() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = runtime.world.players[0]
    entry = runtime.world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.FREEZE,
        state=runtime.world.state,
        emit_burst=False,
    )
    assert entry is not None
    entry.time_left = 0.01
    runtime.world.state.bonuses.freeze = 0.0

    runtime.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert entry.bonus_id == BonusId.UNUSED
    assert runtime.world.state.bonuses.freeze == 0.0
    active = runtime.world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}


def _update_bonus_pool(world: WorldState, dt: float) -> list[BonusPickupEvent]:
    return world.state.bonus_pool.update(
        dt,
        step_runtime=make_step_runtime(world, dt=dt),
        state=world.state,
        players=world.players,
        creatures=world.creatures.entries,
    )


def test_bonus_lifetime_decrement_stores_native_f32_result() -> None:
    world = make_world()
    entry = world.state.bonus_pool.spawn_at(
        pos=Vec2(100.0, 100.0),
        bonus_id=BonusId.POINTS,
        state=world.state,
        emit_burst=False,
    )
    assert entry is not None
    entry.time_left = 9.85200023651123

    _update_bonus_pool(world, 0.04400000348687172)

    assert entry.time_left == 9.808000564575195


def test_bonus_pickup_uses_native_pc24_radius_boundary() -> None:
    world = make_world()
    entry = world.state.bonus_pool.entries[0]
    entry.bonus_id = BonusId.SHIELD
    entry.time_left = 1.0
    entry.time_max = 1.0
    entry.pos = Vec2()
    player = world.players[0]
    player.pos = Vec2(25.999998092651367, 0.009600000455975533)

    # Double squared distance falls just below 26^2, but native PC24 rounds
    # the sum and hypotenuse to exactly 676 and 26, which fails strict `< 26`.
    assert Vec2.distance_sq(entry.pos, player.pos) < 26.0 * 26.0
    pickups = _update_bonus_pool(world, 0.01)

    assert pickups == []
    assert entry.picked is False
    assert player.shield_timer == 0.0


def test_coop_players_on_same_bonus_both_apply_in_one_tick() -> None:
    world = make_world(player_count=2)
    entry = world.state.bonus_pool.spawn_at(
        pos=Vec2(500.0, 500.0),
        bonus_id=BonusId.SHIELD,
        state=world.state,
        emit_burst=False,
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
