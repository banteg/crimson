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
from crimson.sim.input_providers import GameCommand, TypoCharCommand, TypoSubmitCommand
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


def inject_tick_commands(replay: Replay, tick_index: int, commands: list[GameCommand]) -> None:
    old_tick = replay.ticks[tick_index]
    existing = list(old_tick.commands) + commands
    replay.ticks[tick_index] = msgspec.structs.replace(old_tick, commands=existing)


def write_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(dump_replay(replay))
    return replay_path


def write_legacy_out_of_order_event_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    header = payload["header"]

    legacy_payload = {
        "header": {
            "game_mode_id": header["game_mode_id"],
            "seed": header["seed"],
            "replay_format_version": header["replay_format_version"],
            "quest_level": "",
            "bootstrap_kind": "none",
            "bootstrap_seed": 0,
            "game_version": header["game_version"],
            "tick_rate": header["tick_rate"],
            "difficulty_level": 0,
            "hardcore": header["hardcore"],
            "preserve_bugs": header["preserve_bugs"],
            "detail_preset": header["detail_preset"],
            "gore_disabled": header["violence_disabled"],
            "world_size": header["world_size"],
            "player_count": header["player_count"],
            "status": {
                "quest_unlock_index": header["status"]["quest_unlock_index"],
                "quest_unlock_index_full": header["status"]["quest_unlock_index_full"],
                "weapon_usage_counts": header["status"]["weapon_usage_counts"],
            },
            "claimed_stats": header["claimed_stats"],
            "input_quantization": header["input_quantization"],
        },
        "inputs": [tick["inputs"] for tick in payload["ticks"]],
        "dt": [tick["dt"] for tick in payload["ticks"]],
        "events": [
            {"type": "perk_menu_open", "tick_index": 2, "player_index": 0},
            {"type": "perk_menu_open", "tick_index": 1, "player_index": 0},
        ],
    }

    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(msgspec.msgpack.encode(legacy_payload))
    return replay_path


def write_current_typo_event_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "typo_char", "player_index": 0, "ch": "x"}]

    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(msgspec.msgpack.encode(payload))
    return replay_path


def write_current_unknown_command_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "network_ping", "player_index": 0}]

    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(msgspec.msgpack.encode(payload))
    return replay_path


def write_current_missing_quest_level_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["header"]["game_mode_id"] = int(GameMode.QUESTS)
    payload["header"]["quest_level"] = None

    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(msgspec.msgpack.encode(payload))
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


run_verify_playback = _run_verify_playback
