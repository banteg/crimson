from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import NUKE_CAMERA_SHAKE_TIMER
from crimson.camera import camera_shake_update
from crimson.math_parity import f32
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.mode_updates import SurvivalSpawnState
from crimson.sim.sessions import DeterministicSession
from crimson.sim.world_reset import reset_world_players
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.factories import player_input
from tests.support.helpers import assert_float_close


def test_camera_shake_update_matches_decompile_first_pulse() -> None:
    rng = RecordingCrand(Crand(0xBEEF))
    state = GameplayState(rng=rng)
    state.camera_shake_pulses = 0x14
    state.camera_shake_timer = 0.2

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0x13
    assert_float_close(state.camera_shake_timer, f32(0.1))
    assert state.camera_shake_offset == Vec2(28.0, -32.0)
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

    assert_float_close(state.camera_shake_timer, f32(interval))
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


def _spawn_nuke_pickup_on_player(world: WorldState) -> object:
    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.NUKE,
        state=world.state,
    )
    assert entry is not None
    return entry


def _build_session_world(*, seed: int = 0x1234) -> WorldState:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    reset_world_players(world.players, state=world.state, player_count=1)
    world.state.rng.srand(int(seed))
    return world


def test_survival_session_nuke_pickup_skips_deferred_camera_decay() -> None:
    world = _build_session_world(seed=0x1234)
    entry = _spawn_nuke_pickup_on_player(world)
    player = world.players[0]
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=True,
        mode_state=SurvivalSpawnState(),
    )

    _tick = session.step_tick(
        dt=1.0 / 60.0,
        inputs=[player_input(aim=Vec2(player.pos.x, player.pos.y))],
    )

    assert bool(getattr(entry, "picked", False))
    assert world.state.camera_shake_pulses == 0x14
    assert_float_close(world.state.camera_shake_timer, NUKE_CAMERA_SHAKE_TIMER)
