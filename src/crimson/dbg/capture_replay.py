from __future__ import annotations

import math
from pathlib import Path

import msgspec
import zstandard as zstd

from grim.atomic_write import atomic_write_bytes
from grim.sfx_map import SfxId

from ..game_modes import GameMode
from ..math_parity import f32
from ..persistence.save_status import GameStatusData
from ..replay import PackedTickInputs, inflate_replay_payload
from ..replay.driver.playback_driver import SessionPlaybackDriver
from ..replay.input_codec import unpack_tick_inputs
from ..replay.types import input_flags_validation_error
from ..rng_caller_static import RngCallerStatic
from ..sim.input import PlayerInput
from ..sim.input_providers import GameCommand, PerkPickCommand
from ..sim.run_spec import RunSpec, RunStatus
from ..sim.world_reset import CreatureSlotResidue
from .canonical_channels import GameFrameRngAdvanceOperation, PostludeOperation, PreludeOperation

CAPTURE_REPLAY_FORMAT_VERSION = 1
CAPTURE_REPLAY_SUFFIX = ".ccr"
CAPTURE_MODES = frozenset({GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS})
_CAPTURE_REPLAY_ZSTD_LEVEL = 19


class CaptureTick(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """One native gameplay frame: its captured delta, inputs and menu activity."""

    # Gameplay-entry delta, already transformed by native perk timing.
    dt: float
    inputs: PackedTickInputs
    prelude: list[PreludeOperation] = []
    postlude: list[PostludeOperation] = []


class CaptureReplay(msgspec.Struct, forbid_unknown_fields=True):
    """Debug-only replay of an original-game Frida capture.

    Carries what port play never produces: native frame deltas, between-tick
    RNG draws and menu activity, the full save-status blob and the creature
    slot residue left by earlier runs.
    """

    format_version: int
    capture_format_version: int
    tick_rate: int
    run: RunSpec
    status: GameStatusData
    creature_pool: tuple[CreatureSlotResidue, ...]
    ticks: list[CaptureTick]


class CaptureReplayError(ValueError):
    pass


_ENCODER = msgspec.msgpack.Encoder()
_DECODER = msgspec.msgpack.Decoder(type=CaptureReplay)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureReplayError(message)


def _require_f32(value: float, *, field: str) -> None:
    _require(math.isfinite(value) and float(f32(value)) == value, f"{field} must be a finite canonical f32")


def _validate_tick(tick: CaptureTick, *, field: str, player_count: int) -> None:
    _require_f32(tick.dt, field=f"{field}.dt")
    _require(tick.dt >= 0.0, f"{field}.dt must be >= 0")
    _require(len(tick.inputs) == player_count, f"{field} has {len(tick.inputs)} player inputs, expected {player_count}")
    for player_index, packed in enumerate(tick.inputs):
        for axis, name in zip(packed[:4], ("move_x", "move_y", "aim_x", "aim_y"), strict=True):
            _require_f32(axis, field=f"{field}.inputs[{player_index}].{name}")
        flags_error = input_flags_validation_error(packed[4])
        _require(flags_error is None, f"{field}.inputs[{player_index}].flags {flags_error}")
    for label, operations in (("prelude", tick.prelude), ("postlude", tick.postlude)):
        for index, operation in enumerate(operations):
            operation_field = f"{field}.{label}[{index}]"
            if isinstance(operation, GameFrameRngAdvanceOperation):
                _require(operation.frames > 0, f"{operation_field}.frames must be positive")
                continue
            _require(0 <= operation.player_index < player_count, f"{operation_field}.player_index is out of range")
            if isinstance(operation, PerkPickCommand):
                _require(0 <= operation.choice_index < 7, f"{operation_field}.choice_index must be in 0..6")


def validate_capture_replay(capture: CaptureReplay) -> None:
    _require(
        capture.format_version == CAPTURE_REPLAY_FORMAT_VERSION,
        f"unsupported capture replay format version: {capture.format_version}",
    )
    _require(capture.tick_rate > 0, "tick_rate must be positive")
    run = capture.run
    _require(run.game_mode_id in CAPTURE_MODES, f"run.game_mode_id {int(run.game_mode_id)} is not a capture mode")
    _require(
        (run.quest_level is not None) == (run.game_mode_id == GameMode.QUESTS),
        "run.quest_level must be set for quests and only for quests",
    )
    _require(run.status == RunStatus.from_status_data(capture.status), "run.status must mirror status")
    for slot, residue in enumerate(capture.creature_pool):
        _require(residue.index == slot, f"creature_pool[{slot}].index={residue.index} does not match its slot")
    _require(bool(capture.ticks), "capture replay must contain at least one tick")
    for tick_index, tick in enumerate(capture.ticks):
        _validate_tick(tick, field=f"ticks[{tick_index}]", player_count=run.player_count)


def dump_capture_replay(capture: CaptureReplay) -> bytes:
    validate_capture_replay(capture)
    return zstd.ZstdCompressor(level=_CAPTURE_REPLAY_ZSTD_LEVEL).compress(_ENCODER.encode(capture))


def load_capture_replay(data: bytes) -> CaptureReplay:
    """Decode a capture replay; like replays, the payload must re-encode byte for byte."""

    payload = inflate_replay_payload(data)
    try:
        capture = _DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise CaptureReplayError(f"invalid capture replay payload: {exc}") from exc
    _require(_ENCODER.encode(capture) == payload, "capture replay payload is not canonically encoded")
    validate_capture_replay(capture)
    return capture


def dump_capture_replay_file(path: Path, capture: CaptureReplay) -> None:
    atomic_write_bytes(Path(path), dump_capture_replay(capture))


def load_capture_replay_file(path: Path) -> CaptureReplay:
    return load_capture_replay(Path(path).read_bytes())


class CapturePlaybackDriver(SessionPlaybackDriver):
    """Replay an original capture through the port simulation.

    Prelude operations run between ticks, outside the tick RNG trace, as native
    frame-loop work; postlude menu opens run after simulation, inside it. The
    captured delta is already perk-transformed, and native menu activity is
    replayed verbatim, so neither the world dt steps nor command legality apply.
    """

    def __init__(
        self,
        capture: CaptureReplay,
        *,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        strict_rng_trace: bool = False,
    ) -> None:
        self.capture = capture
        super().__init__(
            capture.run,
            tick_count=len(capture.ticks),
            max_ticks=max_ticks,
            trace_rng=trace_rng,
            strict_rng_trace=strict_rng_trace,
            apply_world_dt_steps=False,
            creature_pool_residue=capture.creature_pool,
            strict_end=False,
            strict_commands=False,
        )

    def tick_dt(self, tick_index: int) -> float:
        return self.capture.ticks[tick_index].dt

    def tick_inputs(self, tick_index: int) -> list[PlayerInput]:
        return unpack_tick_inputs(self.capture.ticks[tick_index].inputs)

    def tick_commands(self, tick_index: int) -> list[GameCommand]:
        _ = tick_index
        return []

    def before_tick(self, tick_index: int) -> list[SfxId]:
        tick = self.capture.ticks[tick_index]
        post_apply_sfx: list[SfxId] = []
        for operation in tick.prelude:
            if isinstance(operation, GameFrameRngAdvanceOperation):
                for _ in range(operation.frames):
                    self.world.state.rng.rand_tagged(RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED)
                continue
            sfx = self.session.apply_command(operation, dt=tick.dt)
            if sfx is not None:
                post_apply_sfx.append(sfx)
        return post_apply_sfx

    def after_step(self, tick_index: int) -> None:
        tick = self.capture.ticks[tick_index]
        for operation in tick.postlude:
            self.session.apply_command(operation, dt=tick.dt)
