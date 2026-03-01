from __future__ import annotations

import gzip
import io
import os
from pathlib import Path

import msgspec

from ..math_parity import f32
from .types import (
    REPLAY_FORMAT_VERSION,
    WEAPON_USAGE_COUNT,
    PackedPlayerInput,
    PackedTickInputs,
    PerkMenuOpenEvent,
    PerkPickEvent,
    Replay,
    ReplayClaimedStatsSnapshot,
    ReplayEvent,
    ReplayHeader,
)

_GZIP_MAGIC = b"\x1f\x8b"
_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES = 64 * 1024 * 1024
_MAX_REPLAY_PAYLOAD_ENV = "CRIMSON_REPLAY_MAX_DECOMPRESSED_BYTES"

_REPLAY_DECODER = msgspec.msgpack.Decoder(type=Replay)
_REPLAY_EVENT_TYPES = (
    PerkPickEvent,
    PerkMenuOpenEvent,
)


class ReplayCodecError(ValueError):
    pass


def _is_gzip(data: bytes) -> bool:
    return data.startswith(_GZIP_MAGIC)


def _max_replay_payload_bytes() -> int:
    raw = os.environ.get(_MAX_REPLAY_PAYLOAD_ENV)
    if raw is None:
        return int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    try:
        parsed = int(raw)
    except ValueError:
        return int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    if parsed <= 0:
        return int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    return int(parsed)


def _decompress_gzip_replay(data: bytes, *, max_output_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            payload = stream.read(int(max_output_bytes) + 1)
    except OSError as exc:
        raise ReplayCodecError("invalid replay gzip payload") from exc
    if len(payload) > int(max_output_bytes):
        raise ReplayCodecError(
            f"replay payload too large after gzip decompression (> {int(max_output_bytes)} bytes)",
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
    if str(header.bootstrap_kind) not in ("none", "terrain_v1"):
        raise ReplayCodecError(f"unknown bootstrap_kind: {header.bootstrap_kind!r}")
    _validate_usage_counts(header.status.weapon_usage_counts)
    _validate_claimed_stats(header.claimed_stats)


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


def _validate_event(event: ReplayEvent) -> None:
    if not isinstance(event, _REPLAY_EVENT_TYPES):
        raise ReplayCodecError(f"unsupported event type: {type(event).__name__}")
    if isinstance(event, PerkPickEvent):
        if int(event.player_index) < 0 or int(event.choice_index) < 0:
            raise ReplayCodecError("perk_pick must have non-negative player/choice indexes")
    if isinstance(event, PerkMenuOpenEvent) and int(event.player_index) < 0:
        raise ReplayCodecError(f"perk_menu_open must have non-negative player index: {event.player_index}")


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a gzipped msgpack blob.

    The gzip header is written with mtime=0 for stable content hashing.
    """

    _validate_header(replay.header, from_load=False)

    expected_players = int(replay.header.player_count)
    inputs: list[PackedTickInputs] = []
    for tick_idx, tick in enumerate(replay.inputs):
        if len(tick) != expected_players:
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(tick)} players, expected {expected_players}",
            )
        normalized_tick = [
            _normalize_packed_input(packed, tick_idx=int(tick_idx), player_idx=int(player_idx))
            for player_idx, packed in enumerate(tick)
        ]
        inputs.append(normalized_tick)

    dt_ms_i32: list[int] = []
    if replay.dt_ms_i32:
        if len(replay.dt_ms_i32) != len(inputs):
            raise ReplayCodecError(
                f"replay dt_ms_i32 length {len(replay.dt_ms_i32)} must match input ticks {len(inputs)}",
            )
        for tick_idx, dt_row in enumerate(replay.dt_ms_i32):
            if isinstance(dt_row, bool) or not isinstance(dt_row, (int, float)):
                raise ReplayCodecError(f"replay dt_ms_i32[{tick_idx}] must be numeric")
            dt_ms = int(dt_row)
            if dt_ms <= 0:
                raise ReplayCodecError(f"replay dt_ms_i32[{tick_idx}] must be > 0, got {dt_ms}")
            dt_ms_i32.append(int(dt_ms))

    for event in replay.events:
        _validate_event(event)

    raw = msgspec.msgpack.encode(
        Replay(
            header=replay.header,
            inputs=inputs,
            dt_ms_i32=dt_ms_i32,
            events=list(replay.events),
        ),
    )
    return gzip.compress(raw, compresslevel=9, mtime=0)


def load_replay(data: bytes) -> Replay:
    max_payload_bytes = int(_max_replay_payload_bytes())
    if _is_gzip(data):
        data = _decompress_gzip_replay(data, max_output_bytes=max_payload_bytes)
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
    inputs: list[PackedTickInputs] = []
    for tick_idx, tick in enumerate(replay.inputs):
        if len(tick) != expected_players:
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(tick)} players, expected {expected_players}",
            )
        normalized_tick: PackedTickInputs = []
        for player_idx, packed in enumerate(tick):
            normalized = _normalize_packed_input(
                packed,
                tick_idx=int(tick_idx),
                player_idx=int(player_idx),
            )
            normalized_tick.append(
                [
                    _quantize_f32(float(normalized[0])),
                    _quantize_f32(float(normalized[1])),
                    _quantize_f32(float(normalized[2])),
                    _quantize_f32(float(normalized[3])),
                    int(normalized[4]),
                ],
            )
        inputs.append(normalized_tick)

    dt_ms_i32: list[int] = []
    if replay.dt_ms_i32:
        if len(replay.dt_ms_i32) != len(inputs):
            raise ReplayCodecError(
                f"replay dt_ms_i32 length {len(replay.dt_ms_i32)} must match input ticks {len(inputs)}",
            )
        for tick_idx, dt_row in enumerate(replay.dt_ms_i32):
            if isinstance(dt_row, bool) or not isinstance(dt_row, (int, float)):
                raise ReplayCodecError(f"replay dt_ms_i32[{tick_idx}] must be numeric")
            dt_ms = int(dt_row)
            if dt_ms <= 0:
                raise ReplayCodecError(f"replay dt_ms_i32[{tick_idx}] must be > 0, got {dt_ms}")
            dt_ms_i32.append(int(dt_ms))

    events = list(replay.events)
    input_len = len(inputs)
    for event in events:
        _validate_event(event)
        tick_index = int(event.tick_index)
        if tick_index < 0:
            raise ReplayCodecError(f"replay event tick_index must be non-negative, got {tick_index}")
        if tick_index > input_len:
            raise ReplayCodecError(f"replay event tick_index out of bounds: {tick_index} > {input_len}")

    return Replay(header=replay.header, inputs=inputs, dt_ms_i32=dt_ms_i32, events=events)


def dump_replay_file(path: Path, replay: Replay) -> None:
    path = Path(path)
    path.write_bytes(dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    path = Path(path)
    return load_replay(path.read_bytes())
