from __future__ import annotations

from pathlib import Path

import msgspec
import zstandard as zstd

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.replay import (
    Replay,
    ReplayClaimedStatsSnapshot,
    ReplayHeader,
    ReplayRecorder,
    dump_replay,
)
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    default_checkpoints_path,
    dump_checkpoints_file,
)
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    PerkMenuOpenCommand,
    PerkPickCommand,
    ReplayPreludeOperation,
    ReplayTickCommand,
    RngBurnOperation,
    TypoCharCommand,
    TypoSubmitCommand,
)
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.replay_runner_helpers import _run_verify_playback


def build_replay(
    *,
    mode: GameMode,
    ticks: int,
    seed: int = 0xBEEF,
    player_count: int = 1,
    quest_level: str = "",
) -> Replay:
    parsed_level = QuestLevel.parse(quest_level) if str(quest_level).strip() else None
    header = ReplayHeader(
        game_mode_id=mode,
        seed=int(seed),
        tick_rate=60,
        player_count=int(player_count),
        quest_level=parsed_level,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick(
            [PlayerInput(aim=Vec2(512.0, 512.0)) for _ in range(int(player_count))],
        )
    return claim_replay_stats(recorder.finish())


def build_typo_submit_replay(*, word: str = "reload", seed: int = 0xBEEF) -> Replay:
    header = ReplayHeader(
        game_mode_id=GameMode.TYPO,
        seed=int(seed),
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    baseline = PlayerInput(aim=Vec2(512.0, 512.0))
    for ch in str(word):
        recorder.record_tick([baseline], commands=[TypoCharCommand(player_index=0, ch=ch)])
    recorder.record_tick([baseline], commands=[TypoSubmitCommand(player_index=0)])
    return claim_replay_stats(recorder.finish())


def claim_replay_stats(replay: Replay) -> Replay:
    result = _run_verify_playback(replay)
    return msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=int(result.ticks),
                elapsed_ms=int(result.elapsed_ms),
                score_xp=int(result.score_xp),
                kills=int(result.creature_kill_count),
                most_used_weapon_id=WeaponId(result.most_used_weapon_id),
                shots_fired=int(result.shots_fired),
                shots_hit=int(result.shots_hit),
            ),
        ),
    )


def inject_tick_commands(
    replay: Replay,
    tick_index: int,
    commands: list[ReplayPreludeOperation | ReplayTickCommand],
) -> None:
    old_tick = replay.ticks[tick_index]
    prelude = list(old_tick.prelude)
    tick_commands = list(old_tick.commands)
    for command in commands:
        if isinstance(command, (RngBurnOperation, PerkMenuOpenCommand, PerkPickCommand)):
            prelude.append(command)
        else:
            tick_commands.append(command)
    replay.ticks[tick_index] = msgspec.structs.replace(
        old_tick,
        prelude=prelude,
        commands=tick_commands,
    )


def write_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(dump_replay(replay))
    return replay_path


def _write_current_payload(tmp_path: Path, *, payload: object, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    raw = msgspec.msgpack.encode(payload)
    replay_path.write_bytes(zstd.ZstdCompressor(level=19).compress(raw))
    return replay_path


def write_current_typo_event_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "typo_char", "player_index": 0, "ch": "x"}]

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_unknown_command_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "network_ping", "player_index": 0}]

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_bad_event_player_index_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["prelude"] = [
        {"type": "perk_menu_open", "player_index": payload["header"]["player_count"]},
    ]

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_missing_quest_level_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["header"]["game_mode_id"] = int(GameMode.QUESTS)
    payload["header"]["quest_level"] = None

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_string_quest_level_replay(tmp_path: Path, *, replay: Replay, name: str, quest_level: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["header"]["game_mode_id"] = int(GameMode.QUESTS)
    payload["header"]["quest_level"] = str(quest_level)

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_mode_player_count_replay(
    tmp_path: Path,
    *,
    replay: Replay,
    name: str,
    mode: GameMode,
    player_count: int,
) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["header"]["game_mode_id"] = int(mode)
    payload["header"]["player_count"] = int(player_count)

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_bad_claimed_stats_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["header"]["claimed_stats"]["shots_fired"] = 1
    payload["header"]["claimed_stats"]["shots_hit"] = 2

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_bad_bootstrap_seed_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["header"]["bootstrap_kind"] = "terrain_v1"
    payload["header"]["bootstrap_seed"] = 1

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_bad_tick_player_count_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["inputs"] = []

    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_missing_perk_choice_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["prelude"] = [{"type": "perk_pick", "player_index": 0}]

    return _write_current_payload(tmp_path, payload=payload, name=name)


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


run_verify_playback = _run_verify_playback
