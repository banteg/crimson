from __future__ import annotations

import io
import math
from pathlib import Path

import msgspec
import zstandard as zstd

from ..game_modes import GameMode
from ..math_parity import f32
from .types import (
    REPLAY_FORMAT_VERSION,
    WEAPON_USAGE_COUNT,
    PackedPlayerInput,
    PackedTickInputs,
    Replay,
    ReplayClaimedStatsSnapshot,
    ReplayHeader,
    ReplayTick,
)

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES = 256 * 1024 * 1024
_REPLAY_ZSTD_LEVEL = 19

_REPLAY_DECODER = msgspec.msgpack.Decoder(type=Replay)


class ReplayCodecError(ValueError):
    pass


def _is_zstd(data: bytes) -> bool:
    return data.startswith(_ZSTD_MAGIC)


def _decompress_zstd_replay(data: bytes, *, max_output_bytes: int) -> bytes:
    try:
        with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as stream:
            payload = stream.read(int(max_output_bytes) + 1)
    except zstd.ZstdError as exc:
        raise ReplayCodecError("invalid replay zstd payload") from exc
    if len(payload) > int(max_output_bytes):
        raise ReplayCodecError(
            f"replay payload too large after zstd decompression (> {int(max_output_bytes)} bytes)",
        )
    return payload


def _quantize_f32(value: float) -> float:
    # Canonicalize via shared math-parity float32 helper.
    return float(f32(float(value)))


def _validate_usage_counts(counts: tuple[int, ...] | list[int]) -> None:
    if len(counts) != int(WEAPON_USAGE_COUNT):
        raise ReplayCodecError(
            f"replay header status.weapon_usage_counts must have {int(WEAPON_USAGE_COUNT)} entries",
        )


def _validate_claimed_stats(stats: ReplayClaimedStatsSnapshot) -> None:
    if int(stats.ticks) < 0:
        raise ReplayCodecError(f"replay header claimed_stats.ticks must be non-negative, got {int(stats.ticks)}")
    if int(stats.elapsed_ms) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.elapsed_ms must be non-negative, got {int(stats.elapsed_ms)}",
        )
    if int(stats.score_xp) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.score_xp must be non-negative, got {int(stats.score_xp)}",
        )
    if int(stats.kills) < 0:
        raise ReplayCodecError(f"replay header claimed_stats.kills must be non-negative, got {int(stats.kills)}")
    if int(stats.shots_fired) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.shots_fired must be non-negative, got {int(stats.shots_fired)}",
        )
    if int(stats.shots_hit) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.shots_hit must be non-negative, got {int(stats.shots_hit)}",
        )
    if int(stats.shots_hit) > int(stats.shots_fired):
        raise ReplayCodecError(
            "replay header claimed_stats.shots_hit must be <= claimed_stats.shots_fired",
        )


def _validate_header(header: ReplayHeader, *, from_load: bool) -> None:
    if int(header.replay_format_version) != int(REPLAY_FORMAT_VERSION):
        if from_load:
            raise ReplayCodecError(f"unsupported replay format version: {int(header.replay_format_version)}")
        raise ReplayCodecError(
            f"unsupported replay format version in header: {int(header.replay_format_version)}",
        )
    if int(header.player_count) <= 0:
        raise ReplayCodecError(f"replay header player_count must be positive, got {int(header.player_count)}")
    if str(header.input_quantization) != "f32":
        raise ReplayCodecError(f"unsupported input_quantization: {header.input_quantization!r}; expected 'f32'")
    _validate_usage_counts(header.status.weapon_usage_counts)
    _validate_claimed_stats(header.claimed_stats)
    if int(header.game_mode_id) == int(GameMode.QUESTS) and header.quest_level_value is None:
        raise ReplayCodecError("quest replays require a valid header.quest_level")


def _normalize_packed_input(
    packed: PackedPlayerInput,
    *,
    tick_idx: int,
    player_idx: int,
) -> PackedPlayerInput:
    if len(packed) != 5:
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} must have 5 fields")
    move_x_raw, move_y_raw, aim_x_raw, aim_y_raw, flags_raw = packed
    if not isinstance(move_x_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} move_x must be numeric")
    if not isinstance(move_y_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} move_y must be numeric")
    if not isinstance(aim_x_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} aim_x must be numeric")
    if not isinstance(aim_y_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} aim_y must be numeric")
    if not isinstance(flags_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} flags must be numeric")
    return [
        float(move_x_raw),
        float(move_y_raw),
        float(aim_x_raw),
        float(aim_y_raw),
        int(flags_raw),
    ]


def _validate_tick_dt(dt: float, *, tick_idx: int) -> float:
    if isinstance(dt, bool) or not isinstance(dt, (int, float)):
        raise ReplayCodecError(f"replay tick {tick_idx} dt must be numeric")
    dt_value = float(dt)
    if not math.isfinite(dt_value) or dt_value < 0.0:
        raise ReplayCodecError(f"replay tick {tick_idx} dt must be finite and >= 0, got {dt_value!r}")
    return _quantize_f32(dt_value)


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a zstd-compressed msgpack blob."""

    _validate_header(replay.header, from_load=False)

    expected_players = int(replay.header.player_count)
    normalized_ticks: list[ReplayTick] = []
    for tick_idx, tick in enumerate(replay.ticks):
        inputs = tick.inputs
        if len(inputs) != expected_players:
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(inputs)} players, expected {expected_players}",
            )
        normalized_inputs = [
            _normalize_packed_input(packed, tick_idx=int(tick_idx), player_idx=int(player_idx))
            for player_idx, packed in enumerate(inputs)
        ]
        dt = _validate_tick_dt(tick.dt, tick_idx=tick_idx)
        normalized_ticks.append(ReplayTick(dt=dt, inputs=normalized_inputs, commands=tick.commands))

    raw = msgspec.msgpack.encode(
        Replay(
            header=replay.header,
            ticks=normalized_ticks,
        ),
    )
    return zstd.ZstdCompressor(level=_REPLAY_ZSTD_LEVEL).compress(raw)


def load_replay(data: bytes) -> Replay:
    max_payload_bytes = int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    if _is_zstd(data):
        data = _decompress_zstd_replay(data, max_output_bytes=max_payload_bytes)
    if len(data) > int(max_payload_bytes):
        raise ReplayCodecError(f"replay payload too large (> {int(max_payload_bytes)} bytes)")

    stripped = data.lstrip()
    if stripped.startswith((b"{", b"[")):
        raise ReplayCodecError("legacy JSON replay format is unsupported; regenerate the replay")

    try:
        replay = _REPLAY_DECODER.decode(data)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError("invalid replay msgpack payload") from exc

    _validate_header(replay.header, from_load=True)

    expected_players = int(replay.header.player_count)
    normalized_ticks: list[ReplayTick] = []
    for tick_idx, tick in enumerate(replay.ticks):
        inputs = tick.inputs
        if len(inputs) != expected_players:
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(inputs)} players, expected {expected_players}",
            )
        normalized_inputs: PackedTickInputs = []
        for player_idx, packed in enumerate(inputs):
            normalized = _normalize_packed_input(
                packed,
                tick_idx=int(tick_idx),
                player_idx=int(player_idx),
            )
            normalized_inputs.append(
                [
                    _quantize_f32(float(normalized[0])),
                    _quantize_f32(float(normalized[1])),
                    _quantize_f32(float(normalized[2])),
                    _quantize_f32(float(normalized[3])),
                    int(normalized[4]),
                ],
            )
        dt = _validate_tick_dt(tick.dt, tick_idx=tick_idx)
        normalized_ticks.append(ReplayTick(dt=dt, inputs=normalized_inputs, commands=tick.commands))

    return Replay(header=replay.header, ticks=normalized_ticks)


def dump_replay_file(path: Path, replay: Replay) -> None:
    path = Path(path)
    path.write_bytes(dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    path = Path(path)
    return load_replay(path.read_bytes())
