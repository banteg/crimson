from __future__ import annotations

from crimson.dbg.checkpoint_diff import compare_checkpoints
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.sim.input import PlayerInput
from crimson.sim.input_frame import normalize_input_frame
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close
from tests.support.replay_runner_helpers import _run_verify_playback


def test_normalize_input_frame_is_player_index_ordered_and_fixed_size() -> None:
    frame = normalize_input_frame(
        [
            PlayerInput(move=Vec2(1.0, 0.0), fire_down=True),
            PlayerInput(move=Vec2(-1.0, 0.0), reload_pressed=True),
            PlayerInput(move=Vec2(0.0, 1.0), fire_pressed=True),
        ],
        player_count=2,
    )

    assert len(frame.players) == 2
    assert_float_close(frame.players[0].move.x, 1.0)
    assert frame.players[0].fire_down is True
    assert_float_close(frame.players[1].move.x, -1.0)
    assert frame.players[1].reload_pressed is True

    padded = normalize_input_frame([PlayerInput(fire_pressed=True)], player_count=3)
    assert len(padded.players) == 3
    assert padded.players[0].fire_pressed is True
    assert padded.players[1] == PlayerInput()
    assert padded.players[2] == PlayerInput()


def test_world_step_applies_per_player_inputs_by_index() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(300.0, 300.0)))
    world.players.append(PlayerState(index=1, pos=Vec2(700.0, 300.0)))

    before = [(player.pos.x, player.pos.y) for player in world.players]

    world.step(
        0.2,
        inputs=[
            PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 300.0)),
            PlayerInput(move=Vec2(-1.0, 0.0), aim=Vec2(400.0, 300.0)),
        ],
        world_size=1024.0,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert world.players[0].pos.x > before[0][0]
    assert world.players[1].pos.x < before[1][0]


def test_survival_runner_multiplayer_input_contract_is_deterministic() -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0x1234,
        tick_rate=60,
        player_count=2,
    )
    recorder = ReplayRecorder(header)
    for tick in range(5):
        recorder.record_tick(
            [
                PlayerInput(
                    move=Vec2(1.0, 0.0),
                    aim=Vec2(512.0 + float(tick), 512.0),
                    fire_down=bool(tick % 2 == 0),
                ),
                PlayerInput(
                    move=Vec2(-1.0, 0.0),
                    aim=Vec2(512.0 - float(tick), 512.0),
                    reload_pressed=bool(tick % 3 == 0),
                ),
            ],
        )
    replay = recorder.finish()
    checkpoints0 = []
    checkpoints1 = []

    result0 = _run_verify_playback(
        replay,
        checkpoints_out=checkpoints0,
        checkpoint_ticks=set(range(5)),
    )
    result1 = _run_verify_playback(
        replay,
        checkpoints_out=checkpoints1,
        checkpoint_ticks=set(range(5)),
    )

    assert result0 == result1
    assert [len(ck.players) for ck in checkpoints0] == [2, 2, 2, 2, 2]
    diff = compare_checkpoints(checkpoints0, checkpoints1)
    assert diff.ok
