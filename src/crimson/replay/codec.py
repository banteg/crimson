from __future__ import annotations

import math
from pathlib import Path

import msgspec
import zstandard as zstd

from grim.atomic_write import atomic_write_bytes

from ..game_modes import GameMode
from ..math_parity import f32
from ..sim.input_providers import PerkPickCommand, TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
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
from .types import REPLAY_FORMAT_VERSION, Replay, ReplayTick, input_flags_validation_error

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
MAX_REPLAY_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_REPLAY_FILE_BYTES = 65 * 1024 * 1024
_REPLAY_ZSTD_LEVEL = 19

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
# zstd frames may not ask for a larger decompression window than this.
MAX_ZSTD_WINDOW_BYTES = 8 * 1024 * 1024

_ENCODER = msgspec.msgpack.Encoder()
_DECODER = msgspec.msgpack.Decoder(type=Replay)


class ReplayCodecError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayCodecError(message)


def _require_int(value: int, *, low: int, high: int, field: str) -> None:
    _require(low <= int(value) <= high, f"{field} must be in {low}..{high}")


def _require_f32(value: float, *, field: str) -> None:
    _require(math.isfinite(value), f"{field} must be finite")
    try:
        canonical = float(f32(value))
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
    for field in ("quest_unlock_index", "quest_unlock_index_full"):
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


def validate_replay(replay: Replay) -> None:
    _require(
        replay.format_version == REPLAY_FORMAT_VERSION,
        f"unsupported replay format version: {replay.format_version}",
    )
    _require(bool(replay.game_version), "game_version must be non-empty")
    _validate_run(replay.run)
    _validate_result(replay.result, replay.run)
    _require(bool(replay.ticks), "replay must contain at least one tick")
    for tick_index, tick in enumerate(replay.ticks):
        _validate_tick(tick, tick_index=tick_index, run=replay.run)


def encode_replay_payload(replay: Replay) -> bytes:
    """Validate and encode the canonical msgpack payload."""

    validate_replay(replay)
    payload = _ENCODER.encode(replay)
    _require(len(payload) <= MAX_REPLAY_PAYLOAD_BYTES, f"replay payload too large (> {MAX_REPLAY_PAYLOAD_BYTES} bytes)")
    return payload


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a zstd-compressed msgpack blob."""

    data = zstd.ZstdCompressor(level=_REPLAY_ZSTD_LEVEL).compress(encode_replay_payload(replay))
    _require(len(data) <= MAX_REPLAY_FILE_BYTES, f"replay file too large (> {MAX_REPLAY_FILE_BYTES} bytes)")
    return data


def inflate_replay_payload(data: bytes) -> bytes:
    """Return the msgpack payload of a replay file, enforcing size ceilings."""

    _require(len(data) <= MAX_REPLAY_FILE_BYTES, f"replay file too large (> {MAX_REPLAY_FILE_BYTES} bytes)")
    _require(data.startswith(_ZSTD_MAGIC), "replay must use the zstd envelope")
    try:
        _require(
            zstd.get_frame_parameters(data).window_size <= MAX_ZSTD_WINDOW_BYTES,
            f"replay zstd frame window exceeds {MAX_ZSTD_WINDOW_BYTES // (1024 * 1024)} MiB",
        )
        content_size = zstd.frame_content_size(data)
        _require(
            content_size in (zstd.CONTENTSIZE_UNKNOWN, zstd.CONTENTSIZE_ERROR) or content_size <= MAX_REPLAY_PAYLOAD_BYTES,
            f"replay payload too large (> {MAX_REPLAY_PAYLOAD_BYTES} bytes)",
        )
        payload = zstd.ZstdDecompressor().decompress(
            data,
            max_output_size=MAX_REPLAY_PAYLOAD_BYTES,
            allow_extra_data=False,
        )
    except zstd.ZstdError as exc:
        raise ReplayCodecError("invalid replay zstd payload") from exc
    _require(len(payload) <= MAX_REPLAY_PAYLOAD_BYTES, f"replay payload too large (> {MAX_REPLAY_PAYLOAD_BYTES} bytes)")
    return payload


def decode_replay_payload(payload: bytes) -> Replay:
    """Decode a canonical payload.

    Re-encoding must reproduce the input byte for byte. That single check
    rejects duplicate or reordered keys, omitted fields, integers standing in
    for floats and non-minimal encodings, so every accepted replay has exactly
    one byte representation.
    """

    try:
        replay = _DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError(f"invalid replay payload: {exc}") from exc
    _require(_ENCODER.encode(replay) == payload, "replay payload is not canonically encoded")
    validate_replay(replay)
    return replay


def load_replay(data: bytes) -> Replay:
    return decode_replay_payload(inflate_replay_payload(data))


def dump_replay_file(path: Path, replay: Replay) -> None:
    atomic_write_bytes(Path(path), dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    return load_replay(Path(path).read_bytes())
