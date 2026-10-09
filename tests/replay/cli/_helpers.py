from __future__ import annotations

from pathlib import Path

import msgspec
import zstandard as zstd

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.replay import (
    Replay,
    ReplayRecorder,
    dump_replay,
)
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    default_checkpoints_path,
    dump_checkpoints_file,
)
from crimson.replay.input_codec import pack_tick
from crimson.sim.commands import GameCommand, TypoCharCommand, TypoSubmitCommand
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import _run_verify_playback, finish_replay


def build_replay(
    *,
    mode: GameMode,
    ticks: int,
    seed: int = 0xBEEF,
    player_count: int = 1,
    quest_level: str = "",
) -> Replay:
    parsed_level = QuestLevel.parse(quest_level) if str(quest_level).strip() else None
    recorder = ReplayRecorder(
        RunSpec(game_mode_id=mode, seed=int(seed), player_count=int(player_count), quest_level=parsed_level),
    )
    for _ in range(int(ticks)):
        recorder.record(pack_tick([player_input(aim=Vec2(512.0, 512.0)) for _ in range(int(player_count))]))
    return finish_replay(recorder)


def build_typo_submit_replay(*, word: str = "reload", seed: int = 0xBEEF) -> Replay:
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.TYPO, seed=int(seed)))
    baseline = player_input(aim=Vec2(512.0, 512.0))
    for ch in str(word):
        recorder.record(pack_tick([baseline], [TypoCharCommand(player_index=0, ch=ch)]))
    recorder.record(pack_tick([baseline], [TypoSubmitCommand(player_index=0)]))
    return finish_replay(recorder)


def inject_tick_commands(replay: Replay, tick_index: int, commands: list[GameCommand]) -> None:
    old_tick = replay.ticks[tick_index]
    replay.ticks[tick_index] = msgspec.structs.replace(old_tick, commands=[*old_tick.commands, *commands])


def write_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(dump_replay(replay))
    return replay_path


def write_checkpoint_sidecar(
    replay_path: Path,
    replay: Replay,
    *,
    mutate_checkpoint: bool = False,
) -> Path:
    checkpoint_ticks = {0}
    checkpoints = []
    _run_verify_playback(replay, checkpoints_out=checkpoints, checkpoint_ticks=checkpoint_ticks)
    if mutate_checkpoint:
        checkpoints[0] = msgspec.structs.replace(
            checkpoints[0],
            score_xp=999999,
        )
    payload = ReplayCheckpoints(
        version=int(FORMAT_VERSION),
        sample_rate=1,
        checkpoints=list(checkpoints),
    )
    sidecar_path = default_checkpoints_path(replay_path)
    dump_checkpoints_file(sidecar_path, payload)
    return sidecar_path


def write_payload_bytes(tmp_path: Path, *, payload: bytes, name: str) -> Path:
    """Write raw msgpack payload bytes in the replay zstd envelope."""

    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(zstd.ZstdCompressor(level=19).compress(payload))
    return replay_path
