from __future__ import annotations

from pathlib import Path

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.camera import camera_shake_update
from crimson.game_modes import GameMode
from crimson.replay.driver.setup import build_damage_scale_by_type, reset_players
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import (
    DeterministicSession,
    RushSessionRuntime,
    SurvivalSessionRuntime,
)
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.factories import RecordingCreatureDamageRuntime
from tests.support.factories import make_creature_state as _creature
from tests.support.helpers import assert_float_close
from tests.support.world_runtime import WorldRuntimeHost


def test_camera_shake_update_resets_offsets_when_inactive() -> None:
    state = GameplayState()
    state.camera_shake_timer = 0.0
    state.camera_shake_offset = Vec2(5.0, -3.0)

    camera_shake_update(state, 0.016)

    assert state.camera_shake_offset == Vec2()


def test_camera_shake_update_decays_timer_without_pulse() -> None:
    state = GameplayState()
    state.camera_shake_timer = 1.0
    state.camera_shake_pulses = 10
    state.camera_shake_offset = Vec2(7.0, -9.0)

    camera_shake_update(state, 0.1)

    assert_float_close(state.camera_shake_timer, 0.7)
    assert state.camera_shake_pulses == 10
    assert state.camera_shake_offset == Vec2(7.0, -9.0)


def test_camera_shake_update_matches_decompile_first_pulse() -> None:
    rng = RecordingCrand(Crand(0xBEEF))
    state = GameplayState(rng=rng)
    state.camera_shake_pulses = 0x14
    state.camera_shake_timer = 0.2

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0x13
    assert_float_close(state.camera_shake_timer, 0.1)
    assert state.camera_shake_offset == Vec2(28.0, -32.0)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CAMERA_UPDATE_OFFSET_X_BASE,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_X_SPREAD,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_X_SIGN,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_Y_BASE,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_Y_SPREAD,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_Y_SIGN,
    ]


def test_camera_shake_update_reflex_boost_uses_shorter_interval() -> None:
    rng = RecordingCrand(Crand(0xBEEF))
    state = GameplayState(rng=rng)
    state.bonuses.reflex_boost = 1.0
    state.time_scale_active = True
    state.camera_shake_pulses = 5
    state.camera_shake_timer = 0.01

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 4
    assert_float_close(state.camera_shake_timer, 0.06)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CAMERA_UPDATE_OFFSET_X_BASE,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_X_SPREAD,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_X_SIGN,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_Y_BASE,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_Y_SPREAD,
        RngCallerStatic.CAMERA_UPDATE_OFFSET_Y_SIGN,
    ]


@pytest.mark.parametrize(("latched", "bonus_timer", "interval"), [(True, -0.01, 0.06), (False, 1.0, 0.1)])
def test_camera_shake_interval_uses_latched_scaling(latched: bool, bonus_timer: float, interval: float) -> None:
    state = GameplayState()
    state.time_scale_active = latched
    state.bonuses.reflex_boost = bonus_timer
    state.camera_shake_timer = 0.01
    state.camera_shake_pulses = 5

    camera_shake_update(state, 0.01)

    assert_float_close(state.camera_shake_timer, interval)
    assert state.camera_shake_pulses == 4


def test_camera_shake_update_clears_offsets_one_frame_after_last_pulse() -> None:
    state = GameplayState()
    state.camera_shake_pulses = 1
    state.camera_shake_timer = 0.01
    state.camera_shake_offset = Vec2(11.0, -13.0)

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0
    assert_float_close(state.camera_shake_timer, 0.0)
    assert state.camera_shake_offset == Vec2(11.0, -13.0)

    camera_shake_update(state, 0.1)

    assert state.camera_shake_offset == Vec2()


def test_bonus_apply_nuke_starts_camera_shake_and_damages_creatures() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    creatures = [_creature(pos=Vec2(100.0, 100.0), hp=100.0), _creature(pos=Vec2(500.0, 500.0), hp=100.0)]

    bonus_apply(
        state,
        player,
        BonusId.NUKE,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=creatures),
        origin=player.pos,
        creatures=creatures,
        players=[player],
    )

    assert state.camera_shake_pulses == 0x14
    assert_float_close(state.camera_shake_timer, 0.2)
    assert creatures[0].hp <= 0.0
    assert creatures[1].hp == 100.0


def test_game_world_nuke_pickup_defers_shake_decay_to_next_frame() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.NUKE,
        state=world.sim_world.state,
    )
    assert entry is not None

    world.step_survival_frame(1.0 / 60.0, perk_progression_enabled=False)

    assert entry.picked
    assert world.sim_world.state.camera_shake_pulses == 0x14
    assert_float_close(world.sim_world.state.camera_shake_timer, 0.2)


def _spawn_nuke_pickup_on_player(world: WorldState) -> object:
    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.NUKE,
        state=world.state,
    )
    assert entry is not None
    return entry


def _build_session_world(*, seed: int = 0x1234, world_size: float = 1024.0) -> WorldState:
    world = WorldState.build(
        world_size=float(world_size),
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    reset_players(world.players, state=world.state, world_size=float(world_size), player_count=1)
    world.state.rng.srand(int(seed))
    return world


def test_survival_session_nuke_pickup_skips_deferred_camera_decay() -> None:
    world = _build_session_world(seed=0x1234)
    entry = _spawn_nuke_pickup_on_player(world)
    player = world.players[0]
    session = DeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type=build_damage_scale_by_type(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
        mode_runtime=SurvivalSessionRuntime(),
        finalize_post_render_lifecycle=True,
    )

    _tick = session.step_tick(
        dt=1.0 / 60.0,
        inputs=[PlayerInput(aim=Vec2(player.pos.x, player.pos.y))],
    )

    assert bool(getattr(entry, "picked", False))
    assert world.state.camera_shake_pulses == 0x14
    assert_float_close(world.state.camera_shake_timer, 0.2)


def test_rush_session_nuke_pickup_skips_deferred_camera_decay() -> None:
    world = _build_session_world(seed=0x5678)
    entry = _spawn_nuke_pickup_on_player(world)
    player = world.players[0]
    session = DeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type=build_damage_scale_by_type(),
        game_mode=GameMode.RUSH,
        perk_progression_enabled=False,
        mode_runtime=RushSessionRuntime(world=world),
        elapsed_uses_raw_dt=True,
        finalize_post_render_lifecycle=True,
    )

    _tick = session.step_tick(
        dt=1.0 / 60.0,
        inputs=[PlayerInput(aim=Vec2(player.pos.x, player.pos.y))],
    )

    assert bool(getattr(entry, "picked", False))
    assert world.state.camera_shake_pulses == 0x14
    assert_float_close(world.state.camera_shake_timer, 0.2)
