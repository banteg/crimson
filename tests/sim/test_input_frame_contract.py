from __future__ import annotations

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.replay import ReplayRecorder
from crimson.replay.checkpoint_diff import compare_checkpoints
from crimson.replay.input_codec import pack_tick
from crimson.sim.run_spec import RunSpec
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import _run_verify_playback, unverified_replay


def test_world_step_applies_per_player_inputs_by_index() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(300.0, 300.0)))
    world.players.append(PlayerState(index=1, pos=Vec2(700.0, 300.0)))

    before = [(player.pos.x, player.pos.y) for player in world.players]

    world.step(
        0.2,
        inputs=[
            player_input(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 300.0)),
            player_input(move=Vec2(-1.0, 0.0), aim=Vec2(400.0, 300.0)),
        ],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert world.players[0].pos.x > before[0][0]
    assert world.players[1].pos.x < before[1][0]


def test_survival_runner_multiplayer_input_contract_is_deterministic() -> None:
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0x1234, player_count=2))
    for tick in range(5):
        recorder.record(pack_tick([
                player_input(
                    move=Vec2(1.0, 0.0),
                    aim=Vec2(512.0 + float(tick), 512.0),
                    fire_down=bool(tick % 2 == 0),
                ),
                player_input(
                    move=Vec2(-1.0, 0.0),
                    aim=Vec2(512.0 - float(tick), 512.0),
                    reload_pressed=bool(tick % 3 == 0),
                ),
            ]))
    replay = unverified_replay(recorder)
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
