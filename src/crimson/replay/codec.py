from __future__ import annotations

import gzip
import json
import struct
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .types import (
    PerkMenuOpenEvent,
    PerkPickEvent,
    Replay,
    ReplayEvent,
    ReplayHeader,
    ReplayStatusSnapshot,
    WEAPON_USAGE_COUNT,
    UnknownEvent,
)

_GZIP_MAGIC = b"\x1f\x8b"
_FORMAT_VERSION = 1


class ReplayCodecError(ValueError):
    pass


def _is_gzip(data: bytes) -> bool:
    return data.startswith(_GZIP_MAGIC)


def _quantize_f32(value: float) -> float:
    # Convert via IEEE754 float32. This is useful for matching the original input
    # precision, but may produce "f32 artifact" decimals in JSON.
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _validate_header_dict(header: dict[str, Any]) -> None:
    required = ("game_mode_id", "seed")
    missing = [key for key in required if key not in header]
    if missing:
        raise ReplayCodecError(f"replay header missing fields: {', '.join(missing)}")


def _header_from_dict(data: dict[str, Any]) -> ReplayHeader:
    _validate_header_dict(data)
    status_in = data.get("status") or {}
    weapon_usage_counts = [0] * WEAPON_USAGE_COUNT
    raw_weapon_usage_counts = status_in.get("weapon_usage_counts")
    if isinstance(raw_weapon_usage_counts, list):
        for idx, value in enumerate(raw_weapon_usage_counts[:WEAPON_USAGE_COUNT]):
            try:
                weapon_usage_counts[idx] = int(value)
            except Exception:
                weapon_usage_counts[idx] = 0
    status = ReplayStatusSnapshot(
        quest_unlock_index=int(status_in.get("quest_unlock_index", 0)),
        quest_unlock_index_full=int(status_in.get("quest_unlock_index_full", 0)),
        weapon_usage_counts=tuple(weapon_usage_counts),
    )
    game_version = data.get("game_version")
    if game_version is None:
        game_version_str = ""
    else:
        game_version_str = str(game_version)
    input_quant = data.get("input_quantization", "raw")
    if input_quant not in ("raw", "f32"):
        raise ReplayCodecError(f"unknown input_quantization: {input_quant!r}")
    return ReplayHeader(
        game_mode_id=int(data["game_mode_id"]),
        seed=int(data["seed"]),
        game_version=game_version_str,
        tick_rate=int(data.get("tick_rate", 60)),
        difficulty_level=int(data.get("difficulty_level", 0)),
        hardcore=bool(data.get("hardcore", False)),
        preserve_bugs=bool(data.get("preserve_bugs", False)),
        world_size=float(data.get("world_size", 1024.0)),
        player_count=int(data.get("player_count", 1)),
        status=status,
        input_quantization=input_quant,  # type: ignore[arg-type]
    )


def _event_from_array(value: list[Any]) -> ReplayEvent:
    if len(value) < 2:
        raise ReplayCodecError(f"replay event must have at least 2 fields: {value!r}")
    tick_index = int(value[0])
    kind = str(value[1])
    if kind == "perk_pick":
        if len(value) < 4:
            raise ReplayCodecError(f"perk_pick must have [tick, kind, player, choice]: {value!r}")
        return PerkPickEvent(
            tick_index=tick_index,
            player_index=int(value[2]),
            choice_index=int(value[3]),
        )
    if kind == "perk_menu_open":
        if len(value) < 3:
            raise ReplayCodecError(f"perk_menu_open must have [tick, kind, player]: {value!r}")
        return PerkMenuOpenEvent(
            tick_index=tick_index,
            player_index=int(value[2]),
        )
    return UnknownEvent(tick_index=tick_index, kind=kind, payload=list(value[2:]))


def _events_to_arrays(events: Iterable[ReplayEvent]) -> list[list[object]]:
    out: list[list[object]] = []
    for event in events:
        if isinstance(event, PerkPickEvent):
            out.append(
                [
                    int(event.tick_index),
                    "perk_pick",
                    int(event.player_index),
                    int(event.choice_index),
                ]
            )
        elif isinstance(event, PerkMenuOpenEvent):
            out.append(
                [
                    int(event.tick_index),
                    "perk_menu_open",
                    int(event.player_index),
                ]
            )
        elif isinstance(event, UnknownEvent):
            out.append([int(event.tick_index), str(event.kind), *event.payload])
        else:  # pragma: no cover
            raise ReplayCodecError(f"unsupported event type: {type(event).__name__}")
    return out


def replay_to_obj(replay: Replay) -> dict[str, Any]:
    header = asdict(replay.header)
    # Normalize nested dataclass keys.
    header["status"] = asdict(replay.header.status)
    header["input_quantization"] = str(replay.header.input_quantization)
    return {
        "v": int(replay.version),
        "header": header,
        "inputs": replay.inputs,
        "events": _events_to_arrays(replay.events),
    }


def replay_from_obj(obj: dict[str, Any]) -> Replay:
    version = int(obj.get("v", 0))
    if version != _FORMAT_VERSION:
        raise ReplayCodecError(f"unsupported replay version: {version}")

    header_in = obj.get("header")
    if not isinstance(header_in, dict):
        raise ReplayCodecError("replay header must be an object")
    header = _header_from_dict(header_in)

    inputs_in = obj.get("inputs")
    if not isinstance(inputs_in, list):
        raise ReplayCodecError("replay inputs must be a list")

    # Keep inputs in compact array form:
    # inputs[tick][player] == [move_x, move_y, [aim_x, aim_y], flags]
    inputs: list[list[list[float | int]]] = []
    for tick_idx, tick in enumerate(inputs_in):
        if not isinstance(tick, list):
            raise ReplayCodecError(f"replay inputs tick {tick_idx} must be a list")
        if len(tick) != int(header.player_count):
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(tick)} players, expected {int(header.player_count)}"
            )
        packed_tick: list[list[float | int]] = []
        for player_idx, packed in enumerate(tick):
            if not isinstance(packed, list):
                raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} must be a list")
            if len(packed) < 4:
                raise ReplayCodecError(
                    f"replay input tick {tick_idx} player {player_idx} must have 4 fields"
                )
            mx, my, aim_vec, flags = packed[:4]
            if not isinstance(aim_vec, list) or len(aim_vec) < 2:
                raise ReplayCodecError(
                    f"replay input tick {tick_idx} player {player_idx} must encode aim as [x, y]"
                )
            ax, ay = aim_vec[:2]
            mx_f = float(mx)
            my_f = float(my)
            ax_f = float(ax)
            ay_f = float(ay)
            flags_i = int(flags)
            if header.input_quantization == "f32":
                mx_f = _quantize_f32(mx_f)
                my_f = _quantize_f32(my_f)
                ax_f = _quantize_f32(ax_f)
                ay_f = _quantize_f32(ay_f)
            packed_tick.append([mx_f, my_f, [ax_f, ay_f], flags_i])
        inputs.append(packed_tick)

    events_in = obj.get("events") or []
    if not isinstance(events_in, list):
        raise ReplayCodecError("replay events must be a list")
    events: list[ReplayEvent] = []
    for raw in events_in:
        if not isinstance(raw, list):
            raise ReplayCodecError(f"replay event must be a list: {raw!r}")
        events.append(_event_from_array(raw))

    input_len = len(inputs)
    for event in events:
        tick_index = int(getattr(event, "tick_index", 0))
        if tick_index < 0:
            raise ReplayCodecError(f"replay event tick_index must be non-negative, got {tick_index}")
        if tick_index > input_len:
            raise ReplayCodecError(f"replay event tick_index out of bounds: {tick_index} > {input_len}")

    return Replay(version=version, header=header, inputs=inputs, events=events)


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a gzipped JSON blob.

    The gzip header is written with mtime=0 for stable content hashing.
    """

    obj = replay_to_obj(replay)
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def load_replay(data: bytes) -> Replay:
    if _is_gzip(data):
        data = gzip.decompress(data)
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ReplayCodecError("replay root must be an object")
    return replay_from_obj(obj)


def dump_replay_file(path: Path, replay: Replay) -> None:
    path = Path(path)
    path.write_bytes(dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    path = Path(path)
    return load_replay(path.read_bytes())
