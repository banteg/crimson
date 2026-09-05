from __future__ import annotations

from pathlib import Path

from crimson.bonuses import BonusId
from crimson.bonuses.pickup_fx import emit_bonus_pickup_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import BonusPickupEvent, PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand
from tests.support.world_runtime import WorldRuntimeHost


def test_bonus_pickup_burst_tags_inlined_native_callers() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng)

    emit_bonus_pickup_effects(
        state=state,
        pickups=[BonusPickupEvent(player_index=0, bonus_id=BonusId.POINTS, amount=1, pos=Vec2())],
        detail_preset=5,
    )

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.BONUS_APPLY_PICKUP_BURST_ROTATION,
        RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_X,
        RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_Y,
    ] * 12


def test_bonus_pickup_spawns_burst_effect() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.POINTS,
        state=world.sim_world.state,
        emit_burst=False,
    )
    assert entry is not None

    assert not world.sim_world.state.effects.iter_active()
    world.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    active = world.sim_world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}


def test_expired_bonus_can_still_pickup_as_unused_in_same_tick() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.FREEZE,
        state=world.sim_world.state,
        emit_burst=False,
    )
    assert entry is not None
    entry.time_left = 0.01
    world.sim_world.state.bonuses.freeze = 0.0

    world.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert entry.bonus_id == BonusId.UNUSED
    assert world.sim_world.state.bonuses.freeze == 0.0
    active = world.sim_world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}


def test_bonus_lifetime_decrement_stores_native_f32_result() -> None:
    state = GameplayState()
    entry = state.bonus_pool.spawn_at(
        pos=Vec2(100.0, 100.0),
        bonus_id=BonusId.POINTS,
        state=state,
        emit_burst=False,
    )
    assert entry is not None
    entry.time_left = 9.85200023651123

    state.bonus_pool.update(
        0.04400000348687172,
        state=state,
        players=[PlayerState(index=0, pos=Vec2(500.0, 500.0))],
        creatures=[],
    )

    assert entry.time_left == 9.808000564575195


def test_bonus_pickup_uses_native_pc24_radius_boundary() -> None:
    state = GameplayState()
    entry = state.bonus_pool.entries[0]
    entry.bonus_id = BonusId.SHIELD
    entry.time_left = 1.0
    entry.time_max = 1.0
    entry.pos = Vec2()
    player = PlayerState(
        index=0,
        pos=Vec2(25.999998092651367, 0.009600000455975533),
    )

    # Double squared distance falls just below 26^2, but native PC24 rounds
    # the sum and hypotenuse to exactly 676 and 26, which fails strict `< 26`.
    assert Vec2.distance_sq(entry.pos, player.pos) < 26.0 * 26.0
    pickups = state.bonus_pool.update(
        0.01,
        state=state,
        players=[player],
        creatures=[],
    )

    assert pickups == []
    assert entry.picked is False
    assert player.shield_timer == 0.0


def test_coop_players_on_same_bonus_both_apply_in_one_tick() -> None:
    state = GameplayState()
    entry = state.bonus_pool.spawn_at(
        pos=Vec2(500.0, 500.0),
        bonus_id=BonusId.SHIELD,
        state=state,
        emit_burst=False,
    )
    assert entry is not None

    players = [
        PlayerState(index=0, pos=Vec2(500.0, 500.0)),
        PlayerState(index=1, pos=Vec2(510.0, 500.0)),
    ]
    pickups = state.bonus_pool.update(
        0.016,
        state=state,
        players=players,
        creatures=[],
    )

    # Native's pickup loop has no break: both in-range players apply the bonus.
    assert [pickup.player_index for pickup in pickups] == [0, 1]
    assert players[0].shield_timer > 0.0
    assert players[1].shield_timer > 0.0
