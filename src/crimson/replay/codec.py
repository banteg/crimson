from __future__ import annotations

import math
from pathlib import Path

import msgspec
import zstandard as zstd

from grim.atomic_write import atomic_write_bytes

from ..game_modes import GameMode
from ..game_version import REPLAY_FORMAT_VERSION
from ..math_parity import f32
from ..sim.commands import PerkPickCommand, TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from ..sim.run_result import RunOutcome, RunResult
from ..sim.run_spec import RunSpec
from ..typo.names import (
    HIGHSCORE_NAME_MAX_CHARS,
    MAX_TYPO_DICTIONARY_WORDS,
    MAX_TYPO_HIGHSCORE_NAMES,
    NAME_MAX_CHARS,
    is_typo_dictionary_word,
    is_typo_highscore_name,
)
from ..typo.state import TypoCarry
from .types import Pilot, Recorder, Replay, ReplayTick, input_flags_validation_error

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
# Level 9 writes a long survival replay in ~16 ms and its checkpoint sidecar in ~95 ms; 19 took 0.4 s and
# 4.4 s for files only 5-20% smaller.
_ZSTD_LEVEL = 9
# zstd frames may not ask for a larger decompression window than this.
MAX_ZSTD_WINDOW_BYTES = 8 * 1024 * 1024
MAX_REPLAY_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_REPLAY_FILE_BYTES = 65 * 1024 * 1024

_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_U32_MAX = 0xFFFFFFFF

_REPLAY_MODES = frozenset({GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS, GameMode.TYPO, GameMode.TUTORIAL})
_SINGLE_PLAYER_MODES = frozenset({GameMode.TYPO, GameMode.TUTORIAL})
_MODE_OUTCOMES = {
    GameMode.SURVIVAL: frozenset({RunOutcome.DEATH, RunOutcome.INCOMPLETE}),
    GameMode.RUSH: frozenset({RunOutcome.DEATH, RunOutcome.INCOMPLETE}),
    GameMode.QUESTS: frozenset({RunOutcome.DEATH, RunOutcome.QUEST_COMPLETED, RunOutcome.INCOMPLETE}),
    GameMode.TYPO: frozenset({RunOutcome.DEATH, RunOutcome.INCOMPLETE}),
    GameMode.TUTORIAL: frozenset({RunOutcome.TUTORIAL_COMPLETED, RunOutcome.INCOMPLETE}),
}
_TYPO_COMMANDS = (TypoCharCommand, TypoBackspaceCommand, TypoSubmitCommand)



class _ReplayV30(msgspec.Struct, forbid_unknown_fields=True):
    """Format 30, which had no `rules`: no change since makes its replays play differently, so they play under rules 1."""

    format_version: int
    game_version: str
    recorder: Recorder
    run: RunSpec
    result: RunResult
    ticks: list[ReplayTick]


class _ReplayV31(msgspec.Struct, forbid_unknown_fields=True):
    """Format 31, which had no `pilot`: its runs declare none."""

    format_version: int
    game_version: str
    rules: int
    recorder: Recorder
    run: RunSpec
    result: RunResult
    ticks: list[ReplayTick]


class _FormatVersion(msgspec.Struct):
    format_version: int | None = None


_V30_RULES = 1
_ENCODER = msgspec.msgpack.Encoder()
_DECODERS: dict[int, msgspec.msgpack.Decoder] = {
    REPLAY_FORMAT_VERSION: msgspec.msgpack.Decoder(type=Replay),
    31: msgspec.msgpack.Decoder(type=_ReplayV31),
    30: msgspec.msgpack.Decoder(type=_ReplayV30),
}


def _upgrade(decoded: Replay | _ReplayV31 | _ReplayV30) -> Replay:
    """A replay read from an earlier format, with what that format left out."""

    match decoded:
        case _ReplayV30():
            return Replay(**msgspec.structs.asdict(decoded), rules=_V30_RULES, pilot=None)
        case _ReplayV31():
            return Replay(**msgspec.structs.asdict(decoded), pilot=None)
        case _:
            return decoded
_FORMAT_PROBE = msgspec.msgpack.Decoder(type=_FormatVersion)


class ReplayCodecError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayCodecError(message)


def zstd_pack(payload: bytes) -> bytes:
    """The zstd envelope replays and their checkpoint sidecars are stored in."""

    return zstd.ZstdCompressor(level=_ZSTD_LEVEL).compress(payload)


def zstd_unpack(
    data: bytes,
    *,
    what: str,
    max_file_bytes: int,
    max_payload_bytes: int,
    error: type[ValueError],
) -> bytes:
    """The payload of a zstd envelope, enforcing the file, window and payload size ceilings."""

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise error(message)

    require(len(data) <= max_file_bytes, f"{what} file too large (> {max_file_bytes} bytes)")
    require(data.startswith(_ZSTD_MAGIC), f"{what} must use the zstd envelope")
    try:
        require(
            zstd.get_frame_parameters(data).window_size <= MAX_ZSTD_WINDOW_BYTES,
            f"{what} zstd frame window exceeds {MAX_ZSTD_WINDOW_BYTES // (1024 * 1024)} MiB",
        )
        content_size = zstd.frame_content_size(data)
        require(
            content_size in (zstd.CONTENTSIZE_UNKNOWN, zstd.CONTENTSIZE_ERROR) or content_size <= max_payload_bytes,
            f"{what} payload too large (> {max_payload_bytes} bytes)",
        )
        payload = zstd.ZstdDecompressor().decompress(data, max_output_size=max_payload_bytes, allow_extra_data=False)
    except zstd.ZstdError as exc:
        raise error(f"invalid {what} zstd payload") from exc
    require(len(payload) <= max_payload_bytes, f"{what} payload too large (> {max_payload_bytes} bytes)")
    return payload


def _require_int(value: int, *, low: int, high: int, field: str) -> None:
    _require(low <= int(value) <= high, f"{field} must be in {low}..{high}")


def _require_f32(value: float, *, field: str) -> None:
    _require(math.isfinite(value), f"{field} must be finite")
    try:
        canonical = f32(value)
    except OverflowError as exc:
        raise ReplayCodecError(f"{field} is outside the f32 range") from exc
    _require(canonical == value, f"{field} must be a canonical f32")


def _validate_run(run: RunSpec) -> None:
    mode = run.game_mode_id
    _require(mode in _REPLAY_MODES, f"run.game_mode_id {int(mode)} is not a replayable mode")
    _require_int(run.seed, low=0, high=_U32_MAX, field="run.seed")
    _require(
        (run.quest_level is not None) == (mode == GameMode.QUESTS),
        "run.quest_level must be set for quests and only for quests",
    )
    _require(
        mode not in _SINGLE_PLAYER_MODES or run.player_count == 1,
        f"{mode.name.lower()} replays require player_count == 1",
    )
    _require_int(run.quest_fail_retry_count, low=0, high=_I32_MAX, field="run.quest_fail_retry_count")
    _require_int(run.detail_preset, low=1, high=5, field="run.detail_preset")
    _require_int(run.violence_disabled, low=0, high=0xFF, field="run.violence_disabled")
    for field in ("quest_unlock_index", "quest_unlock_index_hardcore"):
        _require_int(getattr(run.status, field), low=_I32_MIN, high=_I32_MAX, field=f"run.status.{field}")
    for index, count in enumerate(run.status.weapon_usage_counts):
        _require_int(count, low=0, high=_U32_MAX, field=f"run.status.weapon_usage_counts[{index}]")
    _require(
        len(run.typo_dictionary_words) <= MAX_TYPO_DICTIONARY_WORDS,
        f"run.typo_dictionary_words has {len(run.typo_dictionary_words)} entries, "
        f"expected at most {MAX_TYPO_DICTIONARY_WORDS}",
    )
    for index, word in enumerate(run.typo_dictionary_words):
        _require(
            is_typo_dictionary_word(word),
            f"run.typo_dictionary_words[{index}] must be 1..{NAME_MAX_CHARS - 1} printable ASCII characters",
        )
    _require(
        len(run.typo_highscore_names) <= MAX_TYPO_HIGHSCORE_NAMES,
        f"run.typo_highscore_names has {len(run.typo_highscore_names)} entries, "
        f"expected at most {MAX_TYPO_HIGHSCORE_NAMES}",
    )
    for index, name in enumerate(run.typo_highscore_names):
        _require(
            is_typo_highscore_name(name),
            f"run.typo_highscore_names[{index}] must be 1..{HIGHSCORE_NAME_MAX_CHARS} ASCII letters or '.'",
        )
    carry = run.typo_carry
    _require(mode == GameMode.TYPO or carry == TypoCarry(), "run.typo_carry is set only for typo")
    if carry.target_world is not None:
        _require_f32(carry.target_world.x, field="run.typo_carry.target_world.x")
        _require_f32(carry.target_world.y, field="run.typo_carry.target_world.y")
    _require_int(carry.submit_count, low=0, high=_I32_MAX, field="run.typo_carry.submit_count")
    _require_int(carry.match_count, low=0, high=carry.submit_count, field="run.typo_carry.match_count")


def _validate_result(result: RunResult, run: RunSpec) -> None:
    mode = run.game_mode_id
    _require(result.outcome in _MODE_OUTCOMES[mode], f"result.outcome {result.outcome.value!r} is invalid for {mode.name.lower()}")
    _require(
        (result.quest_final_ms is not None) == (result.outcome == RunOutcome.QUEST_COMPLETED),
        "result.quest_final_ms must be set only for completed quests",
    )
    _require_int(result.rng_state, low=0, high=_U32_MAX, field="result.rng_state")
    _require(
        len(result.players) == run.player_count,
        f"result.players has {len(result.players)} entries, expected {run.player_count}",
    )
    for index, player in enumerate(result.players):
        _require_f32(player.health, field=f"result.players[{index}].health")


def _validate_tick(tick: ReplayTick, *, tick_index: int, run: RunSpec) -> None:
    field = f"ticks[{tick_index}]"
    _require(
        len(tick.inputs) == run.player_count,
        f"{field} has {len(tick.inputs)} player inputs, expected {run.player_count}",
    )
    for player_index, packed in enumerate(tick.inputs):
        input_field = f"{field}.inputs[{player_index}]"
        for axis, name in zip(packed[:4], ("move_x", "move_y", "aim_x", "aim_y"), strict=True):
            _require_f32(axis, field=f"{input_field}.{name}")
        flags_error = input_flags_validation_error(packed[4])
        _require(flags_error is None, f"{input_field}.flags {flags_error}: 0x{packed[4]:x}")
    for command_index, command in enumerate(tick.commands):
        command_field = f"{field}.commands[{command_index}]"
        _require(
            0 <= command.player_index < run.player_count,
            f"{command_field}.player_index {command.player_index} is outside 0..{run.player_count - 1}",
        )
        if isinstance(command, PerkPickCommand):
            _require(0 <= command.choice_index < 7, f"{command_field}.choice_index must be in 0..6")
        _require(
            not isinstance(command, _TYPO_COMMANDS) or run.game_mode_id == GameMode.TYPO,
            f"{command_field} Typ-o commands require game_mode_id=TYPO",
        )


def _unsupported_format(version: object) -> str:
    readable = ", ".join(str(v) for v in sorted(_DECODERS))
    return f"unsupported replay format version: {version} (this build reads versions {readable})"


def _format_version(payload: bytes) -> object:
    """The payload's format version, also in the header map formats before v20 kept it in."""

    try:
        version = _FORMAT_PROBE.decode(payload).format_version
        if version is not None:
            return version
        header = msgspec.msgpack.decode(payload).get("header")
    except (msgspec.DecodeError, msgspec.ValidationError, AttributeError):
        return None
    return header.get("replay_format_version") if isinstance(header, dict) else None


RECORDER_FIELD_MAX_CHARS = 64
PILOT_NAME_MAX_CHARS = 31
PILOT_FIELD_MAX_CHARS = 64
PILOT_URL_MAX_CHARS = 200


def _validate_recorder(recorder: Recorder) -> None:
    for field in ("client", "version", "platform"):
        value = getattr(recorder, field)
        _require(
            0 < len(value) <= RECORDER_FIELD_MAX_CHARS and all(" " <= ch <= "~" for ch in value),
            f"recorder.{field} must be 1..{RECORDER_FIELD_MAX_CHARS} printable ASCII characters",
        )


def _printable(value: str) -> bool:
    return all(" " <= ch <= "~" for ch in value)


def _validate_pilot(pilot: Pilot) -> None:
    _require(
        0 < len(pilot.name) <= PILOT_NAME_MAX_CHARS and _printable(pilot.name),
        f"pilot.name must be 1..{PILOT_NAME_MAX_CHARS} printable ASCII characters",
    )
    _require(
        len(pilot.model) <= PILOT_FIELD_MAX_CHARS and _printable(pilot.model),
        f"pilot.model must be at most {PILOT_FIELD_MAX_CHARS} printable ASCII characters",
    )
    _require(
        not pilot.url or (pilot.url.startswith("https://") and len(pilot.url) <= PILOT_URL_MAX_CHARS and _printable(pilot.url)),
        f"pilot.url must be empty or an https:// URL of at most {PILOT_URL_MAX_CHARS} printable ASCII characters",
    )


def validate_replay(replay: Replay) -> None:
    _require(replay.format_version in _DECODERS, _unsupported_format(replay.format_version))
    _require(replay.rules >= 1, "rules must be at least 1")
    _require(bool(replay.game_version), "game_version must be non-empty")
    _validate_recorder(replay.recorder)
    if replay.pilot is not None:
        _validate_pilot(replay.pilot)
    _validate_run(replay.run)
    _validate_result(replay.result, replay.run)
    _require(bool(replay.ticks), "replay must contain at least one tick")
    for tick_index, tick in enumerate(replay.ticks):
        _validate_tick(tick, tick_index=tick_index, run=replay.run)


def encode_replay_payload(replay: Replay) -> bytes:
    """Validate and encode the canonical msgpack payload, always in the current format: a replay read from an
    earlier one is written with the rules it was read with."""

    replay = msgspec.structs.replace(replay, format_version=REPLAY_FORMAT_VERSION)
    validate_replay(replay)
    payload = _ENCODER.encode(replay)
    _require(len(payload) <= MAX_REPLAY_PAYLOAD_BYTES, f"replay payload too large (> {MAX_REPLAY_PAYLOAD_BYTES} bytes)")
    return payload


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a zstd-compressed msgpack blob."""

    data = zstd_pack(encode_replay_payload(replay))
    _require(len(data) <= MAX_REPLAY_FILE_BYTES, f"replay file too large (> {MAX_REPLAY_FILE_BYTES} bytes)")
    return data


def inflate_replay_payload(data: bytes) -> bytes:
    """Return the msgpack payload of a replay file, enforcing size ceilings."""

    return zstd_unpack(
        data,
        what="replay",
        max_file_bytes=MAX_REPLAY_FILE_BYTES,
        max_payload_bytes=MAX_REPLAY_PAYLOAD_BYTES,
        error=ReplayCodecError,
    )


def decode_replay_payload(payload: bytes) -> Replay:
    """Decode a canonical payload.

    Re-encoding must reproduce the input byte for byte. That single check
    rejects duplicate or reordered keys, omitted fields, integers standing in
    for floats and non-minimal encodings, so every accepted replay has exactly
    one byte representation.
    """

    version = _format_version(payload)
    decoder = _DECODERS.get(version) if isinstance(version, int) else None
    if decoder is None and version is not None:
        raise ReplayCodecError(_unsupported_format(version))
    try:
        decoded = (decoder or _DECODERS[REPLAY_FORMAT_VERSION]).decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError(f"invalid replay payload: {exc}") from exc
    _require(_ENCODER.encode(decoded) == payload, "replay payload is not canonically encoded")
    replay = _upgrade(decoded)
    validate_replay(replay)
    return replay


def load_replay(data: bytes) -> Replay:
    return decode_replay_payload(inflate_replay_payload(data))


def dump_replay_file(path: Path, replay: Replay) -> None:
    atomic_write_bytes(Path(path), dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    return load_replay(Path(path).read_bytes())
