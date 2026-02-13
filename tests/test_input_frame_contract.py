from __future__ import annotations

import pytest
from grim.geom import Vec2

from crimson.game_modes import GameMode
from crimson.net.lockstep import HostLockstepState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.replay import ReplayGameVersionWarning, ReplayHeader, ReplayRecorder
from crimson.sim.input_frame import normalize_input_frame
from crimson.sim.runners import run_survival_replay
from crimson.sim.world_state import WorldState
from crimson.effects import FxQueue, FxQueueRotated


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
    assert frame.players[0].move.x == pytest.approx(1.0)
    assert frame.players[0].fire_down is True
    assert frame.players[1].move.x == pytest.approx(-1.0)
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
        difficulty_level=0,
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
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert world.players[0].pos.x > before[0][0]
    assert world.players[1].pos.x < before[1][0]


def test_survival_runner_multiplayer_input_contract_is_deterministic() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=0x1234,
        tick_rate=60,
        player_count=2,
        game_version="0.0.0",
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
            ]
        )
    replay = recorder.finish()
    checkpoints0 = []
    checkpoints1 = []

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_survival_replay(
            replay,
            strict_events=True,
            checkpoints_out=checkpoints0,
            checkpoint_ticks=set(range(5)),
        )
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_survival_replay(
            replay,
            strict_events=True,
            checkpoints_out=checkpoints1,
            checkpoint_ticks=set(range(5)),
        )

    assert result0 == result1
    assert [len(ck.players) for ck in checkpoints0] == [2, 2, 2, 2, 2]
    assert [ck.state_hash for ck in checkpoints0] == [ck.state_hash for ck in checkpoints1]
    assert [ck.command_hash for ck in checkpoints0] == [ck.command_hash for ck in checkpoints1]


def test_host_lockstep_canonical_frame_is_one_input_per_peer_in_slot_order() -> None:
    host = HostLockstepState(player_count=3)
    host.submit_input_sample(slot_index=2, tick_index=0, packed_input=[2.0, 0.0, [2.0, 2.0], 2])
    host.submit_input_sample(slot_index=0, tick_index=0, packed_input=[0.0, 0.0, [0.0, 0.0], 0])
    host.submit_input_sample(slot_index=1, tick_index=0, packed_input=[1.0, 0.0, [1.0, 1.0], 1])

    frames = host.pop_ready_frames(now_ms=10)

    assert len(frames) == 1
    frame = frames[0]
    assert frame.tick_index == 0
    assert len(frame.frame_inputs) == 3
    assert frame.frame_inputs[0] == [0.0, 0.0, [0.0, 0.0], 0]
    assert frame.frame_inputs[1] == [1.0, 0.0, [1.0, 1.0], 1]
    assert frame.frame_inputs[2] == [2.0, 0.0, [2.0, 2.0], 2]


def test_host_lockstep_emits_tick_frames_in_order_under_reordered_arrival() -> None:
    host = HostLockstepState(player_count=2)
    host.submit_input_sample(slot_index=0, tick_index=1, packed_input=[0.0, 1.0, [0.0, 1.0], 0])
    host.submit_input_sample(slot_index=1, tick_index=1, packed_input=[1.0, 1.0, [1.0, 1.0], 0])
    host.submit_input_sample(slot_index=0, tick_index=0, packed_input=[0.0, 0.0, [0.0, 0.0], 0])
    host.submit_input_sample(slot_index=1, tick_index=0, packed_input=[1.0, 0.0, [1.0, 0.0], 0])

    frames = host.pop_ready_frames(now_ms=11)

    assert [frame.tick_index for frame in frames] == [0, 1]
