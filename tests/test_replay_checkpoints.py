from __future__ import annotations

from crimson.gameplay import PlayerState
from crimson.replay.checkpoints import FORMAT_VERSION, ReplayCheckpoints, build_checkpoint, dump_checkpoints, load_checkpoints
from crimson.sim.world_state import WorldState


def test_checkpoints_codec_roundtrip_is_stable() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    world.players.append(PlayerState(index=0, pos_x=512.0, pos_y=512.0))
    ckpt = build_checkpoint(tick_index=0, world=world, elapsed_ms=0.0)
    checkpoints = ReplayCheckpoints(version=FORMAT_VERSION, replay_sha256="0" * 64, sample_rate=60, checkpoints=[ckpt])

    data0 = dump_checkpoints(checkpoints)
    data1 = dump_checkpoints(checkpoints)
    assert data0 == data1

    decoded = load_checkpoints(data0)
    assert decoded == checkpoints

