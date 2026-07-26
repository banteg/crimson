from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import msgspec
import zstandard as zstd

from ..game_modes import GameMode
from ..math_parity import f32
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..sim.input_providers import (
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from .types import (
    REPLAY_FORMAT_VERSION,
    PackedPlayerInput,
    PackedTickInputs,
    Replay,
    ReplayClaimedStatsSnapshot,
    ReplayCreatureSlotResidue,
    ReplayHeader,
    ReplayTick,
    ReplayVec2,
    input_flags_validation_error,
)

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
MAX_REPLAY_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_REPLAY_FILE_BYTES = 65 * 1024 * 1024
_REPLAY_ZSTD_LEVEL = 19
_SUPPORTED_REPLAY_MODE_IDS = frozenset(
    {
        int(GameMode.SURVIVAL),
        int(GameMode.RUSH),
        int(GameMode.QUESTS),
        int(GameMode.TYPO),
        int(GameMode.TUTORIAL),
    },
)

_REPLAY_DECODER = msgspec.msgpack.Decoder(type=Replay)
_HEADER_DECODER = msgspec.msgpack.Decoder(type=ReplayHeader)

_PRELUDE_TYPES = {
    "game_frame_rng_advance": GameFrameRngAdvanceOperation,
    "perk_menu_open": PerkMenuOpenCommand,
    "perk_pick": PerkPickCommand,
}

_POSTLUDE_TYPES = {
    "perk_menu_open": PerkMenuOpenCommand,
}

_COMMAND_TYPES = {
    "typo_char": TypoCharCommand,
    "typo_backspace": TypoBackspaceCommand,
    "typo_submit": TypoSubmitCommand,
}

_RESIDUE_F32_FIELDS = (
    "collision_timer",
    "lifecycle_stage",
    "hp",
    "max_hp",
    "heading",
    "target_heading",
    "size",
    "hit_flash_timer",
    "tint_r",
    "tint_g",
    "tint_b",
    "tint_a",
    "contact_damage",
    "move_speed",
    "attack_cooldown",
    "reward_value",
    "orbit_angle",
    "anim_phase",
)

_RESIDUE_I32_FIELDS = (
    "index",
    "phase_seed",
    "type_id",
    "target_player",
    "link_index",
    "flags",
    "ai_mode",
)

_RESIDUE_U8_FIELDS = (
    "state_flag",
    "collision_flag",
    "force_target",
)


class ReplayCodecError(ValueError):
    pass


def _require_exact_keys(value: object, *, expected: tuple[str, ...], field: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReplayCodecError(f"{field} must be a msgpack map with string keys")
    row = dict(value)
    expected_set = set(expected)
    actual_set = set(row)
    missing = sorted(expected_set - actual_set)
    unknown = sorted(actual_set - expected_set)
    if missing or unknown:
        detail: list[str] = []
        if missing:
            detail.append(f"missing={missing!r}")
        if unknown:
            detail.append(f"unknown={unknown!r}")
        raise ReplayCodecError(f"{field} fields do not match the current replay schema: " + " ".join(detail))
    return row


def _require_wire_float(value: object, *, field: str) -> None:
    if type(value) is not float:
        raise ReplayCodecError(f"{field} must be encoded as a msgpack float")


def _validate_wire_operations(
    value: object,
    *,
    field: str,
    operation_types: Mapping[str, type[msgspec.Struct]],
) -> None:
    if not isinstance(value, list):
        raise ReplayCodecError(f"{field} must be an array")
    for operation_index, operation in enumerate(value):
        operation_field = f"{field}[{operation_index}]"
        if not isinstance(operation, dict):
            raise ReplayCodecError(f"{operation_field} must be a msgpack map")
        operation_row = cast("dict[object, object]", operation)
        tag = operation_row.get("type")
        operation_type = operation_types.get(str(tag))
        if operation_type is None:
            raise ReplayCodecError(f"{operation_field} has unsupported type {tag!r}")
        _require_exact_keys(
            operation_row,
            expected=("type", *operation_type.__struct_fields__),
            field=operation_field,
        )


def _validate_replay_wire_shape(data: bytes) -> None:
    try:
        raw = msgspec.msgpack.decode(data)
    except msgspec.DecodeError as exc:
        raise ReplayCodecError("invalid replay msgpack payload") from exc
    replay = _require_exact_keys(raw, expected=Replay.__struct_fields__, field="replay")
    header = _require_exact_keys(replay["header"], expected=ReplayHeader.__struct_fields__, field="replay.header")
    _require_wire_float(header["world_size"], field="replay.header.world_size")
    _require_exact_keys(
        header["status"],
        expected=GameStatusData.__struct_fields__,
        field="replay.header.status",
    )
    _require_exact_keys(
        header["claimed_stats"],
        expected=ReplayClaimedStatsSnapshot.__struct_fields__,
        field="replay.header.claimed_stats",
    )
    quest_level = header["quest_level"]
    if quest_level is not None:
        _require_exact_keys(
            quest_level,
            expected=QuestLevel.__struct_fields__,
            field="replay.header.quest_level",
        )
    initial_pool = header["initial_creature_pool"]
    if initial_pool is not None:
        if not isinstance(initial_pool, list):
            raise ReplayCodecError("replay.header.initial_creature_pool must be an array or null")
        for index, residue in enumerate(initial_pool):
            residue_row = _require_exact_keys(
                residue,
                expected=ReplayCreatureSlotResidue.__struct_fields__,
                field=f"replay.header.initial_creature_pool[{index}]",
            )
            for vec_field in ("pos", "vel", "target", "target_offset"):
                vec_row = _require_exact_keys(
                    residue_row[vec_field],
                    expected=ReplayVec2.__struct_fields__,
                    field=f"replay.header.initial_creature_pool[{index}].{vec_field}",
                )
                _require_wire_float(
                    vec_row["x"],
                    field=f"replay.header.initial_creature_pool[{index}].{vec_field}.x",
                )
                _require_wire_float(
                    vec_row["y"],
                    field=f"replay.header.initial_creature_pool[{index}].{vec_field}.y",
                )
            for scalar_field in _RESIDUE_F32_FIELDS:
                _require_wire_float(
                    residue_row[scalar_field],
                    field=f"replay.header.initial_creature_pool[{index}].{scalar_field}",
                )
    ticks = replay["ticks"]
    if not isinstance(ticks, list):
        raise ReplayCodecError("replay.ticks must be an array")
    for tick_index, tick in enumerate(ticks):
        tick_row = _require_exact_keys(tick, expected=ReplayTick.__struct_fields__, field=f"replay.ticks[{tick_index}]")
        _require_wire_float(tick_row["dt"], field=f"replay.ticks[{tick_index}].dt")
        inputs = tick_row["inputs"]
        if not isinstance(inputs, list):
            raise ReplayCodecError(f"replay.ticks[{tick_index}].inputs must be an array")
        for player_index, packed in enumerate(inputs):
            input_field = f"replay.ticks[{tick_index}].inputs[{player_index}]"
            if not isinstance(packed, list) or len(packed) != 5:
                raise ReplayCodecError(f"{input_field} must be an array with 5 fields")
            for axis_index, axis_name in enumerate(("move_x", "move_y", "aim_x", "aim_y")):
                _require_wire_float(packed[axis_index], field=f"{input_field}.{axis_name}")
        _validate_wire_operations(
            tick_row["prelude"],
            field=f"replay.ticks[{tick_index}].prelude",
            operation_types=_PRELUDE_TYPES,
        )
        _validate_wire_operations(
            tick_row["postlude"],
            field=f"replay.ticks[{tick_index}].postlude",
            operation_types=_POSTLUDE_TYPES,
        )
        _validate_wire_operations(
            tick_row["commands"],
            field=f"replay.ticks[{tick_index}].commands",
            operation_types=_COMMAND_TYPES,
        )


def _is_zstd(data: bytes) -> bool:
    return data.startswith(_ZSTD_MAGIC)


def _decompress_zstd_replay(data: bytes, *, max_output_bytes: int) -> bytes:
    try:
        content_size = int(zstd.frame_content_size(data))
        if content_size not in (zstd.CONTENTSIZE_UNKNOWN, zstd.CONTENTSIZE_ERROR) and content_size > int(
            max_output_bytes,
        ):
            raise ReplayCodecError(
                f"replay payload too large after zstd decompression (> {int(max_output_bytes)} bytes)",
            )
        payload = zstd.ZstdDecompressor().decompress(
            data,
            max_output_size=int(max_output_bytes),
            allow_extra_data=False,
        )
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


def _canonical_f32(value: float, *, field: str, require_canonical: bool = False) -> float:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ReplayCodecError(f"{field} must be finite")
    try:
        canonical = _quantize_f32(numeric)
    except OverflowError as exc:
        raise ReplayCodecError(f"{field} is outside the f32 range") from exc
    if require_canonical and canonical != numeric:
        raise ReplayCodecError(f"{field} must be canonical f32")
    return canonical


def _canonical_vec2(value: ReplayVec2, *, field: str, require_canonical: bool = False) -> ReplayVec2:
    return ReplayVec2(
        x=_canonical_f32(value.x, field=f"{field}.x", require_canonical=require_canonical),
        y=_canonical_f32(value.y, field=f"{field}.y", require_canonical=require_canonical),
    )


def _require_int_range(value: int, *, low: int, high: int, field: str) -> int:
    integer = int(value)
    if not (int(low) <= integer <= int(high)):
        raise ReplayCodecError(f"{field} must be in {int(low)}..{int(high)}")
    return integer


def _canonical_residue(
    value: ReplayCreatureSlotResidue,
    *,
    field: str,
    require_canonical: bool = False,
) -> ReplayCreatureSlotResidue:
    replacements: dict[str, object] = {}
    for name in _RESIDUE_F32_FIELDS:
        replacements[name] = _canonical_f32(
            getattr(value, name),
            field=f"{field}.{name}",
            require_canonical=require_canonical,
        )
    for name in _RESIDUE_I32_FIELDS:
        replacements[name] = _require_int_range(
            getattr(value, name),
            low=-(1 << 31),
            high=(1 << 31) - 1,
            field=f"{field}.{name}",
        )
    for name in _RESIDUE_U8_FIELDS:
        replacements[name] = _require_int_range(
            getattr(value, name),
            low=0,
            high=0xFF,
            field=f"{field}.{name}",
        )
    replacements["orbit_radius_u32"] = _require_int_range(
        value.orbit_radius_u32,
        low=0,
        high=0xFFFFFFFF,
        field=f"{field}.orbit_radius_u32",
    )
    for name in ("pos", "vel", "target", "target_offset"):
        replacements[name] = _canonical_vec2(
            getattr(value, name),
            field=f"{field}.{name}",
            require_canonical=require_canonical,
        )
    return msgspec.structs.replace(value, **replacements)


def _canonical_header(header: ReplayHeader, *, require_canonical: bool = False) -> ReplayHeader:
    try:
        decoded = _HEADER_DECODER.decode(msgspec.msgpack.encode(header))
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError("invalid replay header") from exc
    _validate_header(decoded, from_load=False)

    world_size = _canonical_f32(
        decoded.world_size,
        field="replay.header.world_size",
        require_canonical=require_canonical,
    )
    if world_size <= 0.0 or world_size > float(f32((1 << 31) - 1)):
        raise ReplayCodecError("replay.header.world_size must be in the positive i32 range")

    pool = decoded.initial_creature_pool
    canonical_pool: tuple[ReplayCreatureSlotResidue, ...] | None = None
    if pool is not None:
        canonical_pool = tuple(
            _canonical_residue(
                row,
                field=f"replay.header.initial_creature_pool[{index}]",
                require_canonical=require_canonical,
            )
            for index, row in enumerate(pool)
        )
        indices = [int(row.index) for row in canonical_pool]
        if indices != sorted(indices) or len(indices) != len(set(indices)):
            raise ReplayCodecError("replay.header.initial_creature_pool indices must be unique and sorted")
    return msgspec.structs.replace(
        decoded,
        world_size=world_size,
        initial_creature_pool=canonical_pool,
    )


def _validate_claimed_stats(stats: ReplayClaimedStatsSnapshot) -> None:
    if int(stats.shots_hit) > int(stats.shots_fired):
        raise ReplayCodecError(
            "replay header claimed_stats.shots_hit must be <= claimed_stats.shots_fired",
        )
    for field in ("ticks", "kills", "most_used_weapon_id", "shots_fired", "shots_hit"):
        _require_int_range(
            getattr(stats, field),
            low=0,
            high=(1 << 31) - 1,
            field=f"replay.header.claimed_stats.{field}",
        )
    for field in ("elapsed_ms", "score_xp"):
        _require_int_range(
            getattr(stats, field),
            low=0,
            high=(1 << 63) - 1,
            field=f"replay.header.claimed_stats.{field}",
        )


def _validate_status(status: GameStatusData) -> None:
    for field in (
        "quest_unlock_index",
        "quest_unlock_index_full",
        "mode_play_survival",
        "mode_play_rush",
        "mode_play_typo",
        "mode_play_other",
        "game_sequence_id",
    ):
        _require_int_range(
            getattr(status, field),
            low=-(1 << 31),
            high=(1 << 31) - 1,
            field=f"replay.header.status.{field}",
        )
    for field, values in (
        ("weapon_usage_counts", status.weapon_usage_counts),
        ("quest_play_counts", status.quest_play_counts),
    ):
        for index, value in enumerate(values):
            _require_int_range(
                value,
                low=0,
                high=0xFFFFFFFF,
                field=f"replay.header.status.{field}[{index}]",
            )
    if len(status.unknown_tail) != 0x10:
        raise ReplayCodecError("replay.header.status.unknown_tail must contain exactly 16 bytes")


def _validate_header(header: ReplayHeader, *, from_load: bool) -> None:
    if int(header.replay_format_version) != int(REPLAY_FORMAT_VERSION):
        if from_load:
            raise ReplayCodecError(f"unsupported replay format version: {int(header.replay_format_version)}")
        raise ReplayCodecError(
            f"unsupported replay format version in header: {int(header.replay_format_version)}",
        )
    if not (0 <= int(header.seed) <= 0xFFFFFFFF):
        raise ReplayCodecError("replay header seed must be a uint32")
    if int(header.game_mode_id) not in _SUPPORTED_REPLAY_MODE_IDS:
        raise ReplayCodecError(f"unsupported replay game_mode_id: {int(header.game_mode_id)}")
    for field in ("tick_rate", "quest_fail_retry_count", "detail_preset", "violence_disabled"):
        low = 1 if field == "tick_rate" else 0
        _require_int_range(
            getattr(header, field),
            low=low,
            high=(1 << 31) - 1,
            field=f"replay.header.{field}",
        )
    _validate_claimed_stats(header.claimed_stats)
    _validate_status(header.status)
    if not str(header.game_version):
        raise ReplayCodecError("replay header game_version must be non-empty")
    if str(header.input_quantization) != "f32":
        raise ReplayCodecError("replay header input_quantization must be 'f32'")
    if int(header.game_mode_id) == int(GameMode.QUESTS):
        if header.quest_level is None:
            raise ReplayCodecError("quest replays require a valid header.quest_level")
    elif header.quest_level is not None:
        raise ReplayCodecError("non-quest replays require header.quest_level to be null")
    if int(header.game_mode_id) == int(GameMode.TYPO) and int(header.player_count) != 1:
        raise ReplayCodecError("Typ-o replays require player_count == 1")
    if int(header.game_mode_id) == int(GameMode.TUTORIAL) and int(header.player_count) != 1:
        raise ReplayCodecError("tutorial replays require player_count == 1")


def _normalize_packed_input(
    packed: PackedPlayerInput,
    *,
    tick_idx: int,
    player_idx: int,
    require_canonical: bool = False,
) -> PackedPlayerInput:
    if len(packed) != 5:
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} must have 5 fields")
    move_x_raw, move_y_raw, aim_x_raw, aim_y_raw, flags_raw = packed
    if isinstance(move_x_raw, bool) or not isinstance(move_x_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} move_x must be numeric")
    if isinstance(move_y_raw, bool) or not isinstance(move_y_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} move_y must be numeric")
    if isinstance(aim_x_raw, bool) or not isinstance(aim_x_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} aim_x must be numeric")
    if isinstance(aim_y_raw, bool) or not isinstance(aim_y_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} aim_y must be numeric")
    if isinstance(flags_raw, bool) or not isinstance(flags_raw, int):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} flags must be an integer")
    flags = int(flags_raw)
    flags_error = input_flags_validation_error(flags)
    if flags_error is not None:
        raise ReplayCodecError(
            f"replay input tick {tick_idx} player {player_idx} flags {flags_error}: 0x{flags:x}",
        )
    values = [float(move_x_raw), float(move_y_raw), float(aim_x_raw), float(aim_y_raw)]
    names = ("move_x", "move_y", "aim_x", "aim_y")
    normalized: list[float | int] = []
    for name, value in zip(names, values, strict=True):
        if not math.isfinite(value):
            raise ReplayCodecError(
                f"replay input tick {tick_idx} player {player_idx} {name} must be finite",
            )
        try:
            canonical = _quantize_f32(value)
        except OverflowError as exc:
            raise ReplayCodecError(
                f"replay input tick {tick_idx} player {player_idx} {name} is outside the f32 range",
            ) from exc
        if require_canonical and canonical != value:
            raise ReplayCodecError(
                f"replay input tick {tick_idx} player {player_idx} {name} must be canonical f32",
            )
        normalized.append(canonical)
    normalized.append(flags)
    return normalized


def _validate_tick_dt(dt: float, *, tick_idx: int, require_canonical: bool = False) -> float:
    if isinstance(dt, bool) or not isinstance(dt, (int, float)):
        raise ReplayCodecError(f"replay tick {tick_idx} dt must be numeric")
    dt_value = float(dt)
    if not math.isfinite(dt_value) or dt_value < 0.0:
        raise ReplayCodecError(f"replay tick {tick_idx} dt must be finite and >= 0, got {dt_value!r}")
    try:
        canonical = _quantize_f32(dt_value)
    except OverflowError as exc:
        raise ReplayCodecError(f"replay tick {tick_idx} dt is outside the f32 range") from exc
    if require_canonical and canonical != dt_value:
        raise ReplayCodecError(f"replay tick {tick_idx} dt must be canonical f32")
    return canonical


def _validate_tick_operations(
    tick: ReplayTick,
    *,
    tick_idx: int,
    player_count: int,
    game_mode: GameMode,
) -> None:
    for operation_index, operation in enumerate(tick.prelude):
        if isinstance(operation, GameFrameRngAdvanceOperation):
            _require_int_range(
                operation.frames,
                low=1,
                high=(1 << 31) - 1,
                field=f"replay tick {tick_idx} prelude {operation_index} frames",
            )
            continue
        player_index = int(operation.player_index)
        if not (0 <= player_index < int(player_count)):
            raise ReplayCodecError(
                f"replay tick {tick_idx} prelude {operation_index} player_index={player_index} "
                f"is outside 0..{int(player_count) - 1}",
            )
        if isinstance(operation, PerkPickCommand) and not (0 <= int(operation.choice_index) < 7):
            raise ReplayCodecError(
                f"replay tick {tick_idx} prelude {operation_index} choice_index must be in 0..6",
            )

    for operation_index, operation in enumerate(tick.postlude):
        player_index = int(operation.player_index)
        if not (0 <= player_index < int(player_count)):
            raise ReplayCodecError(
                f"replay tick {tick_idx} postlude {operation_index} player_index={player_index} "
                f"is outside 0..{int(player_count) - 1}",
            )

    if tick.commands and game_mode != GameMode.TYPO:
        raise ReplayCodecError(f"replay tick {tick_idx} Typ-o commands require game_mode_id=TYPO")
    for command_index, command in enumerate(tick.commands):
        player_index = int(command.player_index)
        if not (0 <= player_index < int(player_count)):
            raise ReplayCodecError(
                f"replay tick {tick_idx} command {command_index} player_index={player_index} "
                f"is outside 0..{int(player_count) - 1}",
            )


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a zstd-compressed msgpack blob."""

    header = _canonical_header(replay.header)
    if not replay.ticks:
        raise ReplayCodecError("replay must contain at least one tick")

    expected_players = int(header.player_count)
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
        normalized_ticks.append(
            ReplayTick(
                dt=dt,
                inputs=normalized_inputs,
                prelude=tick.prelude,
                postlude=tick.postlude,
                commands=tick.commands,
            ),
        )

    raw = msgspec.msgpack.encode(Replay(header=header, ticks=normalized_ticks))
    _validate_replay_wire_shape(raw)
    try:
        validated = _REPLAY_DECODER.decode(raw)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError("invalid replay payload for the current schema") from exc
    for tick_idx, tick in enumerate(validated.ticks):
        _validate_tick_operations(
            tick,
            tick_idx=tick_idx,
            player_count=expected_players,
            game_mode=header.game_mode_id,
        )
    raw = msgspec.msgpack.encode(validated)
    return zstd.ZstdCompressor(level=_REPLAY_ZSTD_LEVEL).compress(raw)


def load_replay(data: bytes) -> Replay:
    if len(data) > int(MAX_REPLAY_FILE_BYTES):
        raise ReplayCodecError(f"replay file too large (> {int(MAX_REPLAY_FILE_BYTES)} bytes)")
    max_payload_bytes = int(MAX_REPLAY_PAYLOAD_BYTES)
    if not _is_zstd(data):
        raise ReplayCodecError("replay must use the canonical zstd envelope")
    data = _decompress_zstd_replay(data, max_output_bytes=max_payload_bytes)
    if len(data) > int(max_payload_bytes):
        raise ReplayCodecError(f"replay payload too large (> {int(max_payload_bytes)} bytes)")

    _validate_replay_wire_shape(data)

    try:
        replay = _REPLAY_DECODER.decode(data)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError("invalid replay msgpack payload") from exc

    _validate_header(replay.header, from_load=True)
    header = _canonical_header(replay.header, require_canonical=True)
    if not replay.ticks:
        raise ReplayCodecError("replay must contain at least one tick")

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
                require_canonical=True,
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
        dt = _validate_tick_dt(tick.dt, tick_idx=tick_idx, require_canonical=True)
        _validate_tick_operations(
            tick,
            tick_idx=tick_idx,
            player_count=expected_players,
            game_mode=header.game_mode_id,
        )
        normalized_ticks.append(
            ReplayTick(
                dt=dt,
                inputs=normalized_inputs,
                prelude=tick.prelude,
                postlude=tick.postlude,
                commands=tick.commands,
            ),
        )

    return Replay(header=header, ticks=normalized_ticks)


def dump_replay_file(path: Path, replay: Replay) -> None:
    path = Path(path)
    path.write_bytes(dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    path = Path(path)
    return load_replay(path.read_bytes())
