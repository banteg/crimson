from __future__ import annotations

import hashlib
import io
import math
import os
import struct
import tempfile
import types
import typing
from collections.abc import Iterable, Iterator, Mapping, Sequence
from enum import Enum
from pathlib import Path

import msgspec

from ..game_modes import GameMode
from ..math_parity import f32
from ..replay.types import input_flags_validation_error
from ..sim.input_providers import GameFrameRngAdvanceOperation, PerkMenuOpenCommand, PerkPickCommand
from .canonical_channels import entity_uid
from .schema import (
    CHUNK_KIND_FOOTER,
    CHUNK_KIND_META,
    CHUNK_KIND_TICK,
    CHUNK_KINDS,
    DEFAULT_CHUNK_FLAGS,
    TRACE_FORMAT_VERSION,
    TRACE_MAGIC,
    TRACE_SCHEMA_VERSION,
    TRAILER_MAGIC,
    TickBlock,
    TickBlockIndexEntry,
    TickRecord,
    TraceFooter,
    TraceMeta,
)

_FILE_HEADER_STRUCT = struct.Struct("<I")
_CHUNK_HEADER_STRUCT = struct.Struct("<4siiIIIQ")
_TRAILER_STRUCT = struct.Struct("<8sQ")
_META_MAGIC_LEN = len(TRACE_MAGIC)

_ENCODER = msgspec.msgpack.Encoder()
_RAW_DECODER = msgspec.msgpack.Decoder()
_META_DECODER = msgspec.msgpack.Decoder(type=TraceMeta)
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_REPLAY_BLOCK_DECODER = msgspec.msgpack.Decoder(type=TickBlock)
_FOOTER_DECODER = msgspec.msgpack.Decoder(type=TraceFooter)


class TraceError(ValueError):
    pass


class TraceSummary(msgspec.Struct, frozen=True):
    meta: TraceMeta
    footer: TraceFooter


def _wire_type_name(annotation: object) -> str:
    if isinstance(annotation, type):
        return annotation.__name__
    return str(annotation)


def _validate_wire_struct(value: object, annotation: type[msgspec.Struct], *, path: str) -> None:
    config = annotation.__struct_config__
    if config.array_like:
        raise TraceError(f"{path}: array-like structs are unsupported in the CDT wire schema")
    if not isinstance(value, dict):
        raise TraceError(f"{path} must be encoded as a msgpack map")
    wire_map = typing.cast(dict[object, object], value)

    fields = msgspec.structs.fields(annotation)
    expected_keys = {field.encode_name for field in fields}
    tag_field = config.tag_field
    if config.tag is not None:
        if tag_field is None:
            raise TraceError(f"{path}: tagged struct is missing its schema tag field")
        expected_keys.add(tag_field)
    actual_keys = set(wire_map)
    missing = sorted(expected_keys - actual_keys)
    if missing:
        raise TraceError(f"{path} is missing field(s): {', '.join(missing)}")
    unknown = sorted((repr(key) for key in actual_keys - expected_keys))
    if unknown:
        raise TraceError(f"{path} has unknown field(s): {', '.join(unknown)}")

    if config.tag is not None and tag_field is not None and wire_map[tag_field] != config.tag:
        raise TraceError(
            f"{path}.{tag_field} must be {config.tag!r}, got {wire_map[tag_field]!r}",
        )
    for field in fields:
        _validate_wire_value(
            wire_map[field.encode_name],
            field.type,
            path=f"{path}.{field.encode_name}",
        )


def _validate_wire_union(value: object, args: tuple[object, ...], *, path: str) -> None:
    if value is None and type(None) in args:
        return
    candidates = tuple(arg for arg in args if arg is not type(None))
    tagged = tuple(
        arg
        for arg in candidates
        if isinstance(arg, type) and issubclass(arg, msgspec.Struct) and arg.__struct_config__.tag is not None
    )
    if tagged and len(tagged) == len(candidates):
        if not isinstance(value, dict):
            raise TraceError(f"{path} must be encoded as a tagged msgpack map")
        wire_map = typing.cast(dict[object, object], value)
        tag_field = tagged[0].__struct_config__.tag_field
        if tag_field is None:
            raise TraceError(f"{path}: tagged union is missing its schema tag field")
        if tag_field not in wire_map:
            raise TraceError(f"{path} is missing field(s): {tag_field}")
        tag = wire_map[tag_field]
        for candidate in tagged:
            if candidate.__struct_config__.tag == tag:
                _validate_wire_struct(value, candidate, path=path)
                return
        expected = ", ".join(repr(candidate.__struct_config__.tag) for candidate in tagged)
        raise TraceError(f"{path}.{tag_field} has unsupported tag {tag!r}; expected one of {expected}")

    errors: list[TraceError] = []
    for candidate in candidates:
        try:
            _validate_wire_value(value, candidate, path=path)
        except TraceError as exc:
            errors.append(exc)
        else:
            return
    if errors:
        raise errors[0]
    raise TraceError(f"{path} does not match {_wire_type_name(args)}")


def _validate_wire_value(value: object, annotation: object, *, path: str) -> None:
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Annotated:
        _validate_wire_value(value, args[0], path=path)
        return
    if origin in (typing.Union, types.UnionType):
        _validate_wire_union(value, args, path=path)
        return
    if annotation is typing.Any:
        return
    if annotation is type(None):
        if value is not None:
            raise TraceError(f"{path} must be null")
        return
    if annotation is float:
        if type(value) is not float:
            raise TraceError(f"{path} must be encoded as a msgpack float")
        return
    if annotation is int:
        if type(value) is not int:
            raise TraceError(f"{path} must be encoded as a msgpack integer")
        return
    if annotation is bool:
        if type(value) is not bool:
            raise TraceError(f"{path} must be encoded as a msgpack bool")
        return
    if annotation is str:
        if type(value) is not str:
            raise TraceError(f"{path} must be encoded as a msgpack string")
        return
    if annotation is bytes:
        if type(value) is not bytes:
            raise TraceError(f"{path} must be encoded as msgpack bytes")
        return
    if isinstance(annotation, type) and issubclass(annotation, msgspec.Struct):
        _validate_wire_struct(value, annotation, path=path)
        return
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        # The typed decoder performs enum membership validation. Its underlying
        # msgpack scalar kind is still validated by msgspec during that pass.
        return
    if origin is typing.Literal:
        if value not in args:
            raise TraceError(f"{path} must be one of {args!r}")
        return
    if origin in (list, set, frozenset, Sequence):
        if not isinstance(value, list):
            raise TraceError(f"{path} must be encoded as a msgpack array")
        item_type = args[0] if args else typing.Any
        for index, item in enumerate(value):
            _validate_wire_value(item, item_type, path=f"{path}[{index}]")
        return
    if origin is tuple:
        if not isinstance(value, list):
            raise TraceError(f"{path} must be encoded as a msgpack array")
        if len(args) == 2 and args[1] is Ellipsis:
            for index, item in enumerate(value):
                _validate_wire_value(item, args[0], path=f"{path}[{index}]")
            return
        if len(value) != len(args):
            raise TraceError(f"{path} must contain exactly {len(args)} item(s)")
        for index, (item, item_type) in enumerate(zip(value, args, strict=True)):
            _validate_wire_value(item, item_type, path=f"{path}[{index}]")
        return
    if origin in (dict, Mapping):
        if not isinstance(value, dict):
            raise TraceError(f"{path} must be encoded as a msgpack map")
        key_type, item_type = args if args else (typing.Any, typing.Any)
        for key, item in value.items():
            _validate_wire_value(key, key_type, path=f"{path}.<key>")
            _validate_wire_value(item, item_type, path=f"{path}[{key!r}]")


def _validate_wire_payload(payload: bytes, annotation: object, *, path: str) -> None:
    try:
        raw = _RAW_DECODER.decode(payload)
    except msgspec.DecodeError as exc:
        raise TraceError(f"invalid {path} msgpack payload") from exc
    _validate_wire_value(raw, annotation, path=path)


def _validate_f32_tree(value: object, *, path: str) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TraceError(f"{path} must be finite")
        try:
            if float(f32(value)) != value:
                raise TraceError(f"{path} must be canonical f32")
        except OverflowError as exc:
            raise TraceError(f"{path} is outside the f32 range") from exc
        return
    fields = getattr(type(value), "__struct_fields__", None)
    if isinstance(fields, tuple):
        for field in fields:
            _validate_f32_tree(getattr(value, field), path=f"{path}.{field}")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _validate_f32_tree(item, path=f"{path}[{key!r}]")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        for index, item in enumerate(value):
            _validate_f32_tree(item, path=f"{path}[{index}]")


def _checksum64(data: bytes) -> int:
    digest = hashlib.blake2b(data, digest_size=8).digest()
    return int.from_bytes(digest, byteorder="little", signed=False)


def _chunk_kind_bytes(kind: str) -> bytes:
    kind_bytes = kind.encode("ascii")
    if kind_bytes not in CHUNK_KINDS:
        raise TraceError(f"unsupported chunk kind: {kind!r}")
    return kind_bytes


def _write_chunk(
    stream: io.BufferedWriter,
    *,
    kind: str,
    start_tick: int,
    end_tick: int,
    payload: bytes,
) -> TickBlockIndexEntry:
    kind_bytes = _chunk_kind_bytes(kind)
    checksum = _checksum64(payload)
    offset = stream.tell()
    header = _CHUNK_HEADER_STRUCT.pack(
        kind_bytes,
        start_tick,
        end_tick,
        DEFAULT_CHUNK_FLAGS,
        len(payload),
        len(payload),
        checksum,
    )
    stream.write(header)
    stream.write(payload)
    return TickBlockIndexEntry(
        start_tick=start_tick,
        end_tick=end_tick,
        file_offset=offset,
        compressed_len=len(payload),
        uncompressed_len=len(payload),
        checksum=checksum,
    )


def validate_tick_record(row: TickRecord, *, meta: TraceMeta | None = None) -> None:
    tick = int(row.tick_index)
    if tick < 0:
        raise TraceError(f"tick_index must be >= 0, got {tick}")
    if int(row.elapsed_ms) < 0:
        raise TraceError(f"tick {tick}: elapsed_ms must be >= 0")
    if int(row.dt_ms_i32) < 0:
        raise TraceError(f"tick {tick}: dt_ms_i32 must be >= 0")
    if int(row.mode_id) < 0:
        raise TraceError(f"tick {tick}: mode_id must be >= 0")

    channels = row.channels
    step = channels.replay_step
    if not math.isfinite(float(step.dt)) or float(step.dt) < 0.0:
        raise TraceError(f"tick {tick}: replay_step.dt must be finite and >= 0")
    try:
        if float(f32(float(step.dt))) != float(step.dt):
            raise TraceError(f"tick {tick}: replay_step.dt must be canonical f32")
    except OverflowError as exc:
        raise TraceError(f"tick {tick}: replay_step.dt is outside the f32 range") from exc
    if not step.inputs:
        raise TraceError(f"tick {tick}: replay_step.inputs must be non-empty")
    for player_index, player_input in enumerate(step.inputs):
        for name in ("move_x", "move_y", "aim_x", "aim_y"):
            value = float(getattr(player_input, name))
            if not math.isfinite(value):
                raise TraceError(f"tick {tick}: replay_step.inputs[{player_index}].{name} must be finite")
            try:
                if float(f32(value)) != value:
                    raise TraceError(
                        f"tick {tick}: replay_step.inputs[{player_index}].{name} must be canonical f32",
                    )
            except OverflowError as exc:
                raise TraceError(
                    f"tick {tick}: replay_step.inputs[{player_index}].{name} is outside the f32 range",
                ) from exc
        flags = int(player_input.flags)
        flags_error = input_flags_validation_error(flags)
        if flags_error is not None:
            raise TraceError(f"tick {tick}: replay_step.inputs[{player_index}].flags {flags_error}")
    for operation_index, operation in enumerate(step.prelude):
        if isinstance(operation, GameFrameRngAdvanceOperation):
            if int(operation.frames) <= 0:
                raise TraceError(f"tick {tick}: replay_step.prelude[{operation_index}].frames must be > 0")
            continue
        player_index = int(operation.player_index)
        if not (0 <= player_index < len(step.inputs)):
            raise TraceError(
                f"tick {tick}: replay_step.prelude[{operation_index}].player_index={player_index} is out of range",
            )
        if isinstance(operation, PerkPickCommand) and not (0 <= int(operation.choice_index) < 7):
            raise TraceError(f"tick {tick}: replay_step.prelude[{operation_index}].choice_index must be in 0..6")

    for operation_index, operation in enumerate(step.postlude):
        if not isinstance(operation, PerkMenuOpenCommand):
            raise TraceError(f"tick {tick}: replay_step.postlude[{operation_index}] has unsupported operation")
        player_index = int(operation.player_index)
        if not (0 <= player_index < len(step.inputs)):
            raise TraceError(
                f"tick {tick}: replay_step.postlude[{operation_index}].player_index={player_index} is out of range",
            )

    for command_index, command in enumerate(step.commands):
        player_index = int(command.player_index)
        if not (0 <= player_index < len(step.inputs)):
            raise TraceError(
                f"tick {tick}: replay_step.commands[{command_index}].player_index={player_index} is out of range",
            )
    if step.commands and int(row.mode_id) != int(GameMode.TYPO):
        raise TraceError(f"tick {tick}: replay_step.commands require Typ-o mode")

    checkpoint = channels.checkpoint
    if int(checkpoint.tick_index) != tick:
        raise TraceError(
            f"tick {tick}: checkpoint.tick_index={int(checkpoint.tick_index)} does not match tick_index",
        )
    if int(checkpoint.elapsed_ms) != int(row.elapsed_ms):
        raise TraceError(
            f"tick {tick}: checkpoint.elapsed_ms={int(checkpoint.elapsed_ms)} "
            f"does not match elapsed_ms={int(row.elapsed_ms)}",
        )
    if len(checkpoint.players) != len(step.inputs):
        raise TraceError(
            f"tick {tick}: checkpoint.players has {len(checkpoint.players)} rows, "
            f"replay_step.inputs has {len(step.inputs)}",
        )
    if len(checkpoint.perk.choices) != 7:
        raise TraceError(f"tick {tick}: checkpoint.perk.choices must contain exactly 7 slots")
    perk_pending = int(checkpoint.perk_pending)
    perk_snapshot_pending = int(checkpoint.perk.pending_count)
    sim_pending = int(channels.sim_state.gameplay.perk_pending_count)
    if not (perk_pending == perk_snapshot_pending == sim_pending):
        raise TraceError(
            f"tick {tick}: perk pending mismatch: checkpoint={perk_pending} "
            f"perk={perk_snapshot_pending} sim_state={sim_pending}",
        )
    if bool(checkpoint.perk.choices_dirty) != bool(channels.sim_state.gameplay.perk_choices_dirty):
        raise TraceError(
            f"tick {tick}: perk choices_dirty mismatch: checkpoint={bool(checkpoint.perk.choices_dirty)} "
            f"sim_state={bool(channels.sim_state.gameplay.perk_choices_dirty)}",
        )
    if checkpoint.deaths:
        raise TraceError(f"tick {tick}: checkpoint.deaths must be empty; detailed rows belong in evidence")
    if checkpoint.events.sfx_head:
        raise TraceError(f"tick {tick}: checkpoint.events.sfx_head must be empty; detailed rows belong in evidence")
    if int(checkpoint.events.sfx_count) != 0:
        raise TraceError(f"tick {tick}: checkpoint.events.sfx_count must be zero; audio details belong in evidence")
    if checkpoint.events.hit_head:
        raise TraceError(f"tick {tick}: checkpoint.events.hit_head must be empty; detailed rows belong in evidence")
    if len(channels.sim_state.players) != len(step.inputs):
        raise TraceError(
            f"tick {tick}: sim_state.players has {len(channels.sim_state.players)} rows, "
            f"replay_step.inputs has {len(step.inputs)}",
        )
    player_indices = [int(player.index) for player in channels.sim_state.players]
    if player_indices != list(range(len(step.inputs))):
        raise TraceError(
            f"tick {tick}: sim_state.players indices must be contiguous slots 0..{len(step.inputs) - 1}",
        )
    if int(channels.sim_state.gameplay.mode_id) != int(row.mode_id):
        raise TraceError(
            f"tick {tick}: sim_state.gameplay.mode_id={int(channels.sim_state.gameplay.mode_id)} "
            f"does not match mode_id={int(row.mode_id)}",
        )
    if meta is not None:
        source = meta.source
        source_mode_id = source.mode_id
        source_player_count = source.player_count
        if source_mode_id is None or source_player_count is None:
            raise TraceError("trace source must include mode_id and player_count")
        if int(source_mode_id) != int(row.mode_id):
            raise TraceError(
                f"tick {tick}: mode_id={int(row.mode_id)} does not match trace source.mode_id={int(source_mode_id)}",
            )
        if int(source_player_count) != len(step.inputs):
            raise TraceError(
                f"tick {tick}: player count {len(step.inputs)} "
                f"does not match trace source.player_count={int(source_player_count)}",
            )

    if not channels.timing_samples:
        raise TraceError(f"tick {tick}: timing_samples must be non-empty")
    gpur_rows = []
    for index, sample in enumerate(channels.timing_samples):
        if int(sample.tick_index) != tick:
            raise TraceError(
                f"tick {tick}: timing_samples[{index}].tick_index={int(sample.tick_index)} does not match tick_index",
            )
        if not sample.phase:
            raise TraceError(f"tick {tick}: timing_samples[{index}].phase must be non-empty")
        if sample.phase == "gpur_enter":
            gpur_rows.append(sample)
    if len(gpur_rows) != 1:
        raise TraceError(f"tick {tick}: timing_samples must contain exactly one gpur_enter row")
    gpur = gpur_rows[0]
    if gpur.frame_dt_f32 is None or float(gpur.frame_dt_f32) != float(step.dt):
        raise TraceError(f"tick {tick}: gpur_enter.frame_dt_f32 must match replay_step.dt")
    if gpur.frame_dt_ms_i32 is None or int(gpur.frame_dt_ms_i32) != int(row.dt_ms_i32):
        raise TraceError(f"tick {tick}: gpur_enter.frame_dt_ms_i32 must match dt_ms_i32")

    previous_after: int | None = None
    for index, rng_row in enumerate(channels.rng_stream, start=1):
        if int(rng_row.tick_call_index) != index:
            raise TraceError(
                f"tick {tick}: rng_stream[{index - 1}].tick_call_index="
                f"{int(rng_row.tick_call_index)} must equal {index}",
            )
        before = int(rng_row.state_before_u32)
        after = int(rng_row.state_after_u32)
        value = int(rng_row.value_15)
        if not (0 <= before <= 0xFFFFFFFF and 0 <= after <= 0xFFFFFFFF):
            raise TraceError(f"tick {tick}: rng_stream[{index - 1}] states must be uint32")
        expected_after = (before * 214013 + 2531011) & 0xFFFFFFFF
        if after != expected_after:
            raise TraceError(f"tick {tick}: rng_stream[{index - 1}] has an invalid CRT state transition")
        if value != ((after >> 16) & 0x7FFF):
            raise TraceError(f"tick {tick}: rng_stream[{index - 1}] value_15 does not match state_after_u32")
        if previous_after is not None and before != previous_after:
            raise TraceError(
                f"tick {tick}: rng_stream[{index - 1}].state_before_u32={before} "
                f"does not continue prior state {previous_after}",
            )
        previous_after = after

    all_entity_uids: set[int] = set()
    pool_kinds = {
        "creatures": "creature",
        "projectiles": "projectile",
        "secondary_projectiles": "secondary_projectile",
        "bonuses": "bonus",
    }
    for kind, pool_kind in pool_kinds.items():
        rows = getattr(channels.entity_samples, kind)
        uids = [int(entity.uid) for entity in rows]
        if len(uids) != len(set(uids)):
            raise TraceError(f"tick {tick}: entity_samples.{kind} contains duplicate uids")
        overlapping = sorted(all_entity_uids & set(uids))
        if overlapping:
            raise TraceError(
                f"tick {tick}: entity_samples contains cross-pool duplicate uids: {overlapping}",
            )
        all_entity_uids.update(uids)
        for row_index, entity in enumerate(rows):
            if str(entity.pool_kind) != pool_kind:
                raise TraceError(
                    f"tick {tick}: entity_samples.{kind}[{row_index}].pool_kind={entity.pool_kind!r} "
                    f"must be {pool_kind!r}",
                )
            if not bool(entity.active):
                raise TraceError(f"tick {tick}: entity_samples.{kind}[{row_index}] must be active")
            try:
                expected_uid = entity_uid(
                    pool_kind=pool_kind,
                    index=int(entity.index),
                    generation=int(entity.generation),
                )
            except ValueError as exc:
                raise TraceError(f"tick {tick}: entity_samples.{kind}[{row_index}] has invalid identity") from exc
            if int(entity.uid) != int(expected_uid):
                raise TraceError(
                    f"tick {tick}: entity_samples.{kind}[{row_index}].uid={int(entity.uid)} "
                    f"does not match encoded identity {int(expected_uid)}",
                )
    _validate_f32_tree(channels, path=f"tick[{tick}].channels")


def _validate_meta(meta: TraceMeta) -> None:
    if int(meta.trace_format_version) != int(TRACE_FORMAT_VERSION):
        raise TraceError(
            f"unsupported trace format version in metadata: {int(meta.trace_format_version)} "
            f"(expected: {int(TRACE_FORMAT_VERSION)})",
        )
    if int(meta.trace_schema_version) != int(TRACE_SCHEMA_VERSION):
        raise TraceError(
            f"unsupported trace schema version in metadata: {int(meta.trace_schema_version)} "
            f"(expected: {int(TRACE_SCHEMA_VERSION)})",
        )
    if not str(meta.created_utc):
        raise TraceError("trace created_utc must be non-empty")
    for field in ("impl", "impl_version", "platform", "arch"):
        if not str(getattr(meta.producer, field)):
            raise TraceError(f"trace producer.{field} must be non-empty")
    source = meta.source
    if str(source.kind) not in {"capture", "replay"}:
        raise TraceError("trace source.kind must be 'capture' or 'replay'")
    for field in ("sha256", "replay_sha256"):
        value = getattr(source, field)
        if not isinstance(value, str) or len(value) != 64:
            raise TraceError(f"trace source.{field} must be a sha256 hex digest")
        try:
            int(value, 16)
        except ValueError as exc:
            raise TraceError(f"trace source.{field} must be a sha256 hex digest") from exc
    for field in ("tick_rate", "player_count"):
        value = getattr(source, field)
        if value is None or int(value) <= 0:
            raise TraceError(f"trace source.{field} must be positive")
    if source.seed is None or not (0 <= int(source.seed) <= 0xFFFFFFFF):
        raise TraceError("trace source.seed must be a uint32")
    if source.mode_id is None or int(source.mode_id) < 0:
        raise TraceError("trace source.mode_id must be non-negative")
    if source.quest_level is None:
        if source.quest_stage_major is not None or source.quest_stage_minor is not None:
            raise TraceError("trace source quest stage fields require quest_level")
        if int(source.mode_id) == int(GameMode.QUESTS):
            raise TraceError("quest trace source requires quest_level")
    else:
        if int(source.mode_id) != int(GameMode.QUESTS):
            raise TraceError("non-quest trace source must not set quest_level")
        try:
            major_text, minor_text = str(source.quest_level).split(".", 1)
            major = int(major_text)
            minor = int(minor_text)
        except ValueError as exc:
            raise TraceError("trace source.quest_level must use M.m form") from exc
        if source.quest_stage_major != major or source.quest_stage_minor != minor:
            raise TraceError("trace source quest stage fields must match quest_level")


def _write_trace_from_iter(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Iterable[TickRecord],
    chunk_ticks: int,
) -> TraceSummary:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        meta = _META_DECODER.decode(_ENCODER.encode(meta))
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise TraceError("invalid trace metadata for the current schema") from exc
    _validate_meta(meta)
    chunk_size = max(1, int(chunk_ticks))
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temp_path = Path(temp_name)

    try:
        with temp_path.open("wb") as handle:
            handle.write(TRACE_MAGIC)
            handle.write(_FILE_HEADER_STRUCT.pack(TRACE_FORMAT_VERSION))

            _write_chunk(
                handle,
                kind=CHUNK_KIND_META,
                start_tick=-1,
                end_tick=-1,
                payload=_ENCODER.encode(meta),
            )

            tick_indices: list[TickBlockIndexEntry] = []
            first_tick: int | None = None
            last_tick: int | None = None
            tick_count = 0
            current_block: list[TickRecord] = []

            def flush_block() -> None:
                nonlocal first_tick, last_tick, tick_count
                if not current_block:
                    return
                block = TickBlock(
                    start_tick=int(current_block[0].tick_index),
                    end_tick=int(current_block[-1].tick_index),
                    ticks=list(current_block),
                )
                tick_indices.append(
                    _write_chunk(
                        handle,
                        kind=CHUNK_KIND_TICK,
                        start_tick=int(block.start_tick),
                        end_tick=int(block.end_tick),
                        payload=_ENCODER.encode(block),
                    ),
                )
                current_block.clear()

            for source_tick in ticks:
                try:
                    tick = _TICK_DECODER.decode(_ENCODER.encode(source_tick))
                except (msgspec.DecodeError, msgspec.ValidationError) as exc:
                    raise TraceError("invalid tick record for the current schema") from exc
                validate_tick_record(tick, meta=meta)
                row_tick = int(tick.tick_index)
                if first_tick is None:
                    first_tick = row_tick
                if last_tick is not None and row_tick != int(last_tick) + 1:
                    raise TraceError(
                        f"tick rows must be contiguous, got {row_tick} after {int(last_tick)}",
                    )
                last_tick = row_tick
                tick_count += 1
                current_block.append(tick)
                if len(current_block) >= int(chunk_size):
                    flush_block()
            flush_block()

            if int(tick_count) <= 0:
                raise TraceError("trace must contain at least one tick")
            if first_tick is None or last_tick is None:
                raise TraceError("trace footer tick bounds are missing")
            expected_range = meta.tick_range
            if (
                int(expected_range.start_tick) != int(first_tick)
                or int(expected_range.end_tick) != int(last_tick)
                or int(expected_range.tick_count) != int(tick_count)
            ):
                raise TraceError(
                    "trace metadata tick_range does not match written ticks: "
                    f"meta={int(expected_range.start_tick)}..{int(expected_range.end_tick)} "
                    f"count={int(expected_range.tick_count)}, actual={int(first_tick)}..{int(last_tick)} "
                    f"count={int(tick_count)}",
                )
            footer = TraceFooter(
                tick_blocks=tick_indices,
                tick_count=int(tick_count),
                first_tick=int(first_tick),
                last_tick=int(last_tick),
            )
            footer_payload = _ENCODER.encode(footer)
            footer_index = _write_chunk(
                handle,
                kind=CHUNK_KIND_FOOTER,
                start_tick=-1,
                end_tick=-1,
                payload=footer_payload,
            )
            handle.write(
                _TRAILER_STRUCT.pack(
                    TRAILER_MAGIC,
                    footer_index.file_offset,
                ),
            )
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return TraceSummary(meta=meta, footer=footer)


def write_trace_iter(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Iterable[TickRecord],
    chunk_ticks: int = 256,
) -> TraceSummary:
    return _write_trace_from_iter(
        path,
        meta=meta,
        ticks=ticks,
        chunk_ticks=max(1, int(chunk_ticks)),
    )


def _chunk_payload_from_file(
    stream: io.BufferedReader,
    *,
    offset: int,
    expected_entry: TickBlockIndexEntry | None = None,
) -> tuple[str, int, int, bytes]:
    stream.seek(offset)
    header = stream.read(_CHUNK_HEADER_STRUCT.size)
    if len(header) != _CHUNK_HEADER_STRUCT.size:
        raise TraceError("truncated chunk header")
    kind_bytes, start_tick, end_tick, flags, compressed_len, raw_len, checksum = _CHUNK_HEADER_STRUCT.unpack(header)
    if kind_bytes not in CHUNK_KINDS:
        raise TraceError(f"unknown chunk kind: {kind_bytes!r}")
    payload_compressed = stream.read(compressed_len)
    if len(payload_compressed) != compressed_len:
        raise TraceError("truncated chunk payload")
    if flags != DEFAULT_CHUNK_FLAGS:
        raise TraceError(
            f"unsupported chunk flags: 0x{int(flags):08x} (expected: 0x{int(DEFAULT_CHUNK_FLAGS):08x})",
        )
    payload = payload_compressed
    if len(payload) != raw_len:
        raise TraceError("chunk size mismatch")
    if _checksum64(payload) != checksum:
        raise TraceError("chunk checksum mismatch")
    if expected_entry is not None:
        if int(expected_entry.file_offset) != int(offset):
            raise TraceError("trace footer file_offset does not match chunk offset")
        if int(expected_entry.compressed_len) != int(compressed_len):
            raise TraceError("trace footer compressed_len does not match chunk header")
        if int(expected_entry.uncompressed_len) != int(raw_len):
            raise TraceError("trace footer uncompressed_len does not match chunk header")
        if int(expected_entry.checksum) != int(checksum):
            raise TraceError("trace footer checksum does not match chunk header")
    return kind_bytes.decode("ascii"), start_tick, end_tick, payload


def write_trace(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Sequence[TickRecord],
    chunk_ticks: int = 256,
) -> TraceSummary:
    return _write_trace_from_iter(
        path,
        meta=meta,
        ticks=ticks,
        chunk_ticks=max(1, int(chunk_ticks)),
    )


def _load_meta_at_offset(stream: io.BufferedReader, *, offset: int) -> TraceMeta:
    kind, start, end, payload = _chunk_payload_from_file(stream, offset=offset)
    if kind != CHUNK_KIND_META:
        raise TraceError("invalid trace meta chunk")
    if int(start) != -1 or int(end) != -1:
        raise TraceError("trace meta chunk must use range -1..-1")
    _validate_wire_payload(payload, TraceMeta, path="meta")
    try:
        meta = _META_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise TraceError("invalid trace metadata payload") from exc
    _validate_meta(meta)
    return meta


def _load_footer_and_meta_offsets(path: Path) -> tuple[int, int]:
    path = Path(path)
    with path.open("rb") as handle:
        file_header = handle.read(_META_MAGIC_LEN + _FILE_HEADER_STRUCT.size)
        if len(file_header) != _META_MAGIC_LEN + _FILE_HEADER_STRUCT.size:
            raise TraceError(f"invalid trace file: {path}")
        magic = file_header[:_META_MAGIC_LEN]
        if magic != TRACE_MAGIC:
            raise TraceError(f"unsupported trace magic: {path}")
        (format_version,) = _FILE_HEADER_STRUCT.unpack(file_header[_META_MAGIC_LEN:])
        if format_version != TRACE_FORMAT_VERSION:
            raise TraceError(f"unsupported trace format version: {format_version}")

        handle.seek(0, io.SEEK_END)
        end_pos = handle.tell()
        if end_pos < (_META_MAGIC_LEN + _FILE_HEADER_STRUCT.size + _TRAILER_STRUCT.size):
            raise TraceError("invalid trace size")
        handle.seek(end_pos - _TRAILER_STRUCT.size)
        trailer_raw = handle.read(_TRAILER_STRUCT.size)
        trailer_magic, footer_offset = _TRAILER_STRUCT.unpack(trailer_raw)
        if trailer_magic != TRAILER_MAGIC:
            raise TraceError("missing trace trailer")
        return footer_offset, _META_MAGIC_LEN + _FILE_HEADER_STRUCT.size


def load_trace_meta(path: Path) -> TraceMeta:
    path = Path(path)
    footer_offset, meta_offset = _load_footer_and_meta_offsets(path)
    _ = footer_offset
    with path.open("rb") as handle:
        return _load_meta_at_offset(handle, offset=meta_offset)


class TraceReader:
    def __init__(self, path: Path, *, strict: bool = True) -> None:
        self.path = Path(path)
        footer_offset, meta_offset = _load_footer_and_meta_offsets(self.path)
        self._handle = self.path.open("rb")
        try:
            self._initialize(footer_offset=footer_offset, meta_offset=meta_offset, strict=bool(strict))
        except Exception:
            self._handle.close()
            raise

    def _initialize(self, *, footer_offset: int, meta_offset: int, strict: bool) -> None:
        self.meta = _load_meta_at_offset(self._handle, offset=meta_offset)
        meta_end_offset = self._handle.tell()
        footer_kind, footer_start, footer_end, footer_payload = _chunk_payload_from_file(
            self._handle,
            offset=footer_offset,
        )
        footer_end_offset = self._handle.tell()
        if footer_kind != CHUNK_KIND_FOOTER:
            raise TraceError("invalid trace footer chunk")
        if int(footer_start) != -1 or int(footer_end) != -1:
            raise TraceError("trace footer chunk must use range -1..-1")
        _validate_wire_payload(footer_payload, TraceFooter, path="footer")
        try:
            self.footer = _FOOTER_DECODER.decode(footer_payload)
        except (msgspec.DecodeError, msgspec.ValidationError) as exc:
            raise TraceError("invalid trace footer payload") from exc
        self._handle.seek(0, io.SEEK_END)
        trailer_offset = self._handle.tell() - _TRAILER_STRUCT.size
        if int(footer_end_offset) != int(trailer_offset):
            raise TraceError("trace footer chunk must immediately precede the trailer")
        if int(self.footer.tick_count) <= 0:
            raise TraceError("invalid trace footer tick_count")
        if int(self.footer.first_tick) < 0 or int(self.footer.last_tick) < 0:
            raise TraceError("invalid trace footer tick bounds")
        if int(self.footer.first_tick) > int(self.footer.last_tick):
            raise TraceError("invalid trace footer tick order")
        if bool(strict) and int(self.footer.tick_count) != int(self.footer.last_tick) - int(self.footer.first_tick) + 1:
            raise TraceError("trace footer must describe one contiguous tick range")
        if len(self.footer.tick_blocks) <= 0:
            raise TraceError("invalid trace footer block index")
        meta_range = self.meta.tick_range
        if bool(strict) and (
            int(meta_range.start_tick) != int(self.footer.first_tick)
            or int(meta_range.end_tick) != int(self.footer.last_tick)
            or int(meta_range.tick_count) != int(self.footer.tick_count)
        ):
            raise TraceError("trace metadata tick_range does not match footer")
        previous_end: int | None = None
        expected_offset = meta_end_offset
        for index, entry in enumerate(self.footer.tick_blocks):
            if int(entry.start_tick) < 0 or int(entry.end_tick) < int(entry.start_tick):
                raise TraceError(f"invalid trace footer block range at index {index}")
            if bool(strict) and previous_end is not None and int(entry.start_tick) != previous_end + 1:
                raise TraceError(f"non-contiguous trace footer block at index {index}")
            if int(entry.file_offset) != int(expected_offset):
                raise TraceError(f"trace contains an unindexed gap before block {index}")
            if int(entry.file_offset) >= int(footer_offset):
                raise TraceError(f"trace footer block offset overlaps footer at index {index}")
            if int(entry.compressed_len) <= 0 or int(entry.uncompressed_len) <= 0:
                raise TraceError(f"invalid trace footer block size at index {index}")
            if int(entry.compressed_len) != int(entry.uncompressed_len):
                raise TraceError(f"raw CDT block lengths differ at index {index}")
            previous_end = int(entry.end_tick)
            expected_offset = int(entry.file_offset) + _CHUNK_HEADER_STRUCT.size + int(entry.compressed_len)
        if int(expected_offset) != int(footer_offset):
            raise TraceError("trace contains an unindexed gap before the footer")
        if bool(strict) and int(self.footer.tick_blocks[0].start_tick) != int(self.footer.first_tick):
            raise TraceError("trace footer first_tick does not match first block")
        if bool(strict) and int(self.footer.tick_blocks[-1].end_tick) != int(self.footer.last_tick):
            raise TraceError("trace footer last_tick does not match last block")
        self._block_cache: dict[int, TickBlock] = {}

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "TraceReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _load_block(self, entry: TickBlockIndexEntry) -> TickBlock:
        cache_key = entry.file_offset
        cached = self._block_cache.get(cache_key)
        if cached is not None:
            return cached
        kind, chunk_start, chunk_end, payload = _chunk_payload_from_file(
            self._handle,
            offset=cache_key,
            expected_entry=entry,
        )
        if kind != CHUNK_KIND_TICK:
            raise TraceError("trace index points at non-tick chunk")
        if int(chunk_start) != int(entry.start_tick) or int(chunk_end) != int(entry.end_tick):
            raise TraceError("trace tick chunk range does not match footer index")
        _validate_wire_payload(payload, TickBlock, path="tick_block")
        try:
            block = _REPLAY_BLOCK_DECODER.decode(payload)
        except (msgspec.DecodeError, msgspec.ValidationError) as exc:
            raise TraceError("invalid replay trace tick payload") from exc
        if int(block.start_tick) != int(entry.start_tick) or int(block.end_tick) != int(entry.end_tick):
            raise TraceError("trace tick block range does not match footer index")
        if not block.ticks:
            raise TraceError("trace tick block must not be empty")
        previous_tick: int | None = None
        for row in block.ticks:
            validate_tick_record(row, meta=self.meta)
            row_tick = int(row.tick_index)
            if previous_tick is not None and row_tick != previous_tick + 1:
                raise TraceError("trace tick block rows must be contiguous")
            previous_tick = row_tick
        if int(block.ticks[0].tick_index) != int(block.start_tick):
            raise TraceError("trace tick block start does not match first row")
        if int(block.ticks[-1].tick_index) != int(block.end_tick):
            raise TraceError("trace tick block end does not match last row")
        self._block_cache[cache_key] = block
        return block

    def tick(self, tick_index: int) -> TickRecord | None:
        tick = tick_index
        for entry in self.footer.tick_blocks:
            if entry.start_tick <= tick <= entry.end_tick:
                block = self._load_block(entry)
                for row in block.ticks:
                    if row.tick_index == tick:
                        return row
                return None
        return None

    def iter_ticks(self, *, tick_start: int | None = None, tick_end: int | None = None) -> Iterator[TickRecord]:
        start = tick_start
        end = tick_end
        for entry in self.footer.tick_blocks:
            if start is not None and entry.end_tick < start:
                continue
            if end is not None and entry.start_tick > end:
                continue
            block = self._load_block(entry)
            for row in block.ticks:
                tick = row.tick_index
                if start is not None and tick < start:
                    continue
                if end is not None and tick > end:
                    continue
                yield row

    def all_ticks(self) -> list[TickRecord]:
        return list(self.iter_ticks())


def load_trace(path: Path) -> tuple[TraceMeta, list[TickRecord], TraceFooter]:
    with TraceReader(Path(path)) as trace:
        return trace.meta, trace.all_ticks(), trace.footer


def iter_trace_ticks(path: Path, *, tick_start: int | None = None, tick_end: int | None = None) -> Iterable[TickRecord]:
    with TraceReader(Path(path)) as trace:
        yield from trace.iter_ticks(tick_start=tick_start, tick_end=tick_end)
