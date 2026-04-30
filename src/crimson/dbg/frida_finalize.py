from __future__ import annotations

import hashlib
import math
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO

import msgspec

from ..game_modes import GameMode
from ..net.session_settings import session_settings_for_lockstep
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.codec import dump_replay_file
from ..replay.header_settings import replay_header_from_session_settings
from ..replay.types import Replay, ReplayTick
from .canonical_channels import (
    EntitySamplesSnapshot,
    RngStreamRow,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    TimingSampleRow,
)
from .payloads import BuiltinObject
from .schema import (
    TRACE_FORMAT_VERSION,
    TRACE_REQUIRED_CHANNELS,
    TRACE_SCHEMA_VERSION,
    ReplayTickChannels,
    TickRecord,
    TraceConfig,
    TraceMeta,
    TraceProducer,
    TraceSource,
    TraceTickRange,
    channel_versions_for,
)
from .trace import TraceSummary, write_trace_iter

_FRAME_LEN_BYTES = 4
_TICK_ENCODER = msgspec.msgpack.Encoder()
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_GAME_MODE_QUESTS = 3
_SUPPORTED_CAPTURE_FORMAT_VERSION = 12
_SUPPORTED_JSONL_SCHEMA_VERSION = 1
_RUN_START_REASONS = frozenset(("run_start", "first_tick", "quest_attempt", "mode_or_stage_change"))
_RUN_END_REASONS = frozenset(("run_end", "quest_attempt", "mode_or_stage_change", "shutdown"))
_SEED_SOURCES = frozenset(("unknown", "crt_srand"))
_MODE_LABEL_BY_ID = {
    int(GameMode.DEMO): "demo",
    int(GameMode.SURVIVAL): "survival",
    int(GameMode.RUSH): "rush",
    int(GameMode.QUESTS): "quests",
    int(GameMode.TYPO): "typo",
    int(GameMode.TUTORIAL): "tutorial",
}


class FridaFinalizeError(ValueError):
    pass


class _CaptureRngStreamRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_call_index: int
    value_15: int
    state_before_u32: int
    state_after_u32: int
    caller_static: str | None = None


class _CaptureSnapshotGameplay(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    perk_pending_count: int
    perk_choices_dirty: bool
    bonus_timers: SnapshotBonusTimers
    status: GameStatusData | None = None


class _CaptureSimStateSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    gameplay: _CaptureSnapshotGameplay
    players: list[SnapshotPlayer]


class _TickChannels(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    checkpoint: ReplayCheckpoint
    sim_state: _CaptureSimStateSnapshot
    entity_samples: EntitySamplesSnapshot
    rng_stream: list[_CaptureRngStreamRow]
    timing_samples: list[TimingSampleRow]


class _SessionFingerprintRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    session_id: str
    ptrs_hash: str
    module_hash: str | None = None


class _SessionConfigRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    out_path: str
    jsonl_schema_version: int
    capture_profile: str
    config_env_overrides: list[str]
    log_mode: str
    console_all_events: bool
    console_events: list[str]
    include_caller: bool
    include_backtrace: bool
    emit_ticks_outside_tracked_states: bool
    tracked_states: list[int]
    player_count_override: int
    focus_tick: int
    focus_radius: int
    heartbeat_ms: int
    flush_capture_writes: bool
    max_head_per_kind: int
    max_events_per_tick: int
    max_rng_head_per_tick: int
    max_rng_caller_kinds: int
    enable_rng_roll_log: bool
    max_rng_roll_log_events: int
    max_rng_outside_tick_head: int
    enable_rng_state_mirror: bool
    max_creature_delta_ids: int
    creature_sample_limit: int
    projectile_sample_limit: int
    secondary_projectile_sample_limit: int
    bonus_sample_limit: int
    enable_input_hooks: bool
    enable_rng_hooks: bool
    enable_sfx_hooks: bool
    enable_damage_hooks: bool
    enable_effect_hooks: bool
    creature_damage_projectile_only: bool
    enable_spawn_hooks: bool
    enable_creature_spawn_hook: bool
    enable_creature_death_hook: bool
    enable_bonus_spawn_hook: bool
    enable_creature_lifecycle_digest: bool
    enable_creature_micro_hooks: bool
    creature_micro_slots: list[int]
    creature_micro_tick_start: int
    creature_micro_tick_end: int
    creature_micro_max_head_per_tick: int


class _SessionStartRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="session_start",
):
    capture_format_version: int
    schema_version: int
    session_id: str
    out_path: str
    platform: str
    arch: str
    script_version: str
    config: _SessionConfigRow
    session_fingerprint: _SessionFingerprintRow


class _RunStartRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_start",
):
    run_id: int
    mode_id: int
    seed: int
    player_count: int
    reason: str = "run_start"
    quest_stage_major: int = -1
    quest_stage_minor: int = -1
    seed_source: str = "unknown"
    tick_index_global: int | None = None


class _TickRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="tick",
):
    run_id: int
    elapsed_ms: int
    dt: float
    dt_ms_i32: int
    mode_id: int
    channels: _TickChannels
    tick_index_global: int | None = None
    quest_stage_major: int = -1
    quest_stage_minor: int = -1
    replay_inputs: list[tuple[float, float, float, float, int]] = msgspec.field(default_factory=list)


class _RunEndRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_end",
):
    run_id: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    ticks_written: int
    reason: str = "run_end"
    tick_index_global: int | None = None


class _ErrorRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="error",
):
    error: str
    run_id: int | None = None
    tick_index_global: int | None = None


class _SessionEndRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="session_end",
):
    session_id: str
    ticks_written: int


type _CaptureRow = _SessionStartRow | _RunStartRow | _TickRow | _RunEndRow | _ErrorRow | _SessionEndRow


_CAPTURE_ROW_DECODER = msgspec.json.Decoder(type=_CaptureRow)


class FinalizedTrace(msgspec.Struct, frozen=True):
    run_id: int
    out_path: Path
    replay_path: Path
    tick_count: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    summary: TraceSummary


class FinalizeResult(msgspec.Struct, frozen=True):
    raw_path: Path
    traces: list[FinalizedTrace]
    deleted_raw: bool


class _OpenRun(msgspec.Struct):
    run_id: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    replay_seed: int
    replay_player_count: int
    temp_path: Path
    stream: BinaryIO
    replay_seed_source: str = "unknown"
    tick_count: int = 0
    next_local_tick: int = 0
    replay_inputs: list[list[list[float | int]]] = msgspec.field(default_factory=list)
    replay_dt: list[float] = msgspec.field(default_factory=list)
    status: GameStatusData = msgspec.field(default_factory=GameStatusData)
    channels_seen: set[str] = msgspec.field(default_factory=set)
    global_tick_first: int | None = None
    global_tick_last: int | None = None


def _fingerprint(path: Path) -> BuiltinObject:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def _builtin_text(payload: BuiltinObject, key: str, default: str = "") -> str:
    value = payload.get(key)
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return str(value)
    return default


def _builtin_int(payload: BuiltinObject, key: str, default: int = 0) -> int:
    value = payload.get(key)
    if isinstance(value, (bool, int, float, str)):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _decode_capture_row(line: bytes, *, field: str) -> _CaptureRow:
    try:
        return _CAPTURE_ROW_DECODER.decode(line)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise FridaFinalizeError(f"{field} invalid capture row: {exc}") from exc


def _canonical_channels_payload(
    *,
    channels: _TickChannels,
    local_tick: int,
    field: str,
) -> tuple[ReplayCheckpoint, ReplayTickChannels]:
    checkpoint = msgspec.structs.replace(channels.checkpoint, tick_index=int(local_tick))
    rng_stream = [
        RngStreamRow(
            tick_call_index=int(row.tick_call_index),
            value_15=int(row.value_15),
            state_before_u32=int(row.state_before_u32),
            state_after_u32=int(row.state_after_u32),
            caller=(
                None
                if row.caller_static is None
                else _caller_from_capture(
                    row.caller_static,
                    field=f"{field}.rng_stream[{idx}].caller_static",
                )
            ),
        )
        for idx, row in enumerate(channels.rng_stream)
    ]
    normalized = _TickChannels(
        checkpoint=checkpoint,
        sim_state=channels.sim_state,
        entity_samples=channels.entity_samples,
        rng_stream=list(channels.rng_stream),
        timing_samples=list(channels.timing_samples),
    )
    gameplay = normalized.sim_state.gameplay
    return checkpoint, ReplayTickChannels(
        checkpoint=normalized.checkpoint,
        sim_state=SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=int(gameplay.mode_id),
                quest_stage_major=int(gameplay.quest_stage_major),
                quest_stage_minor=int(gameplay.quest_stage_minor),
                perk_pending_count=int(gameplay.perk_pending_count),
                perk_choices_dirty=bool(gameplay.perk_choices_dirty),
                bonus_timers=gameplay.bonus_timers,
            ),
            players=list(normalized.sim_state.players),
        ),
        entity_samples=normalized.entity_samples,
        rng_stream=rng_stream,
        timing_samples=list(normalized.timing_samples),
    )


def _caller_from_capture(value: str, *, field: str) -> int:
    text = value
    if not text.lower().startswith("0x"):
        raise FridaFinalizeError(f"{field} must be a 0x-prefixed hex string")
    try:
        caller = int(text, 16)
    except ValueError as exc:
        raise FridaFinalizeError(f"{field} invalid hex value: {text!r}") from exc
    if not (0 <= caller <= 0xFFFFFFFF):
        raise FridaFinalizeError(f"{field} must decode to a uint32")
    return caller


def _replay_tick_inputs_from_row(
    replay_inputs: list[tuple[float, float, float, float, int]],
    *,
    expected_players: int,
    field: str,
) -> list[list[float | int]]:
    if len(replay_inputs) != int(expected_players):
        raise FridaFinalizeError(
            f"{field} must contain {int(expected_players)} player rows, got {len(replay_inputs)}",
    )
    out: list[list[float | int]] = []
    for player_index, (move_x, move_y, aim_x, aim_y, flags) in enumerate(replay_inputs):
        player_field = f"{field}[{player_index}]"
        scalars = (
            ("move_x", move_x),
            ("move_y", move_y),
            ("aim_x", aim_x),
            ("aim_y", aim_y),
        )
        for scalar_name, scalar_value in scalars:
            if not math.isfinite(float(scalar_value)):
                raise FridaFinalizeError(f"{player_field}.{scalar_name} must be finite")
        out.append([float(move_x), float(move_y), float(aim_x), float(aim_y), int(flags)])
    return out


def _validate_tick_channels(
    *,
    channels: _TickChannels,
    expected_players: int,
    elapsed_ms: int,
    dt: float,
    dt_ms_i32: int,
    mode_id: int,
    quest_stage_major: int,
    quest_stage_minor: int,
    field: str,
) -> None:
    checkpoint_players = list(channels.checkpoint.players)
    if len(checkpoint_players) <= 0:
        raise FridaFinalizeError(f"{field}.checkpoint.players must be non-empty")
    if len(checkpoint_players) != int(expected_players):
        raise FridaFinalizeError(
            f"{field}.checkpoint.players length {len(checkpoint_players)} "
            f"does not match run_start.player_count {int(expected_players)}",
        )
    if int(channels.checkpoint.elapsed_ms) != int(elapsed_ms):
        raise FridaFinalizeError(
            f"{field}.checkpoint.elapsed_ms={int(channels.checkpoint.elapsed_ms)} "
            f"does not match tick.elapsed_ms {int(elapsed_ms)}",
        )
    rng_state = int(channels.checkpoint.rng_state)
    if rng_state < 0 or rng_state > 0xFFFFFFFF:
        raise FridaFinalizeError(f"{field}.checkpoint.rng_state must be a uint32")
    sim_players = list(channels.sim_state.players)
    if len(sim_players) != len(checkpoint_players):
        raise FridaFinalizeError(
            f"{field}.sim_state.players length {len(sim_players)} "
            f"does not match checkpoint.players length {len(checkpoint_players)}",
        )
    gameplay = channels.sim_state.gameplay
    if int(gameplay.mode_id) != int(mode_id):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.mode_id={int(gameplay.mode_id)} "
            f"does not match tick.mode_id {int(mode_id)}",
        )
    if int(gameplay.quest_stage_major) != int(quest_stage_major):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.quest_stage_major={int(gameplay.quest_stage_major)} "
            f"does not match tick.quest_stage_major {int(quest_stage_major)}",
        )
    if int(gameplay.quest_stage_minor) != int(quest_stage_minor):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.quest_stage_minor={int(gameplay.quest_stage_minor)} "
            f"does not match tick.quest_stage_minor {int(quest_stage_minor)}",
        )
    timing_samples = list(channels.timing_samples)
    if len(timing_samples) <= 0:
        raise FridaFinalizeError(f"{field}.timing_samples must be non-empty")
    for sample_index, sample in enumerate(timing_samples):
        if not str(sample.phase):
            raise FridaFinalizeError(f"{field}.timing_samples[{sample_index}].phase must be non-empty")
        if not str(sample.write_kind):
            raise FridaFinalizeError(f"{field}.timing_samples[{sample_index}].write_kind must be non-empty")
    gpur_enter = next((sample for sample in timing_samples if str(sample.phase) == "gpur_enter"), None)
    if gpur_enter is None:
        raise FridaFinalizeError(f"{field}.timing_samples must include phase `gpur_enter`")
    if gpur_enter.frame_dt_f32 is None or not math.isfinite(float(gpur_enter.frame_dt_f32)):
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_f32 must be finite")
    if gpur_enter.frame_dt_ms_i32 is None:
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32 must be present")
    if int(gpur_enter.frame_dt_ms_i32) < 0:
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32 must be >= 0")
    if float(gpur_enter.frame_dt_f32) != float(dt):
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.frame_dt_f32={float(gpur_enter.frame_dt_f32)} "
            f"does not match tick.dt {float(dt)}",
        )
    if int(gpur_enter.frame_dt_ms_i32) != int(dt_ms_i32):
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32={int(gpur_enter.frame_dt_ms_i32)} "
            f"does not match tick.dt_ms_i32 {int(dt_ms_i32)}",
        )
def _tick_iter_from_spool(path: Path):
    with Path(path).open("rb") as handle:
        while True:
            len_raw = handle.read(_FRAME_LEN_BYTES)
            if not len_raw:
                break
            if len(len_raw) != _FRAME_LEN_BYTES:
                raise FridaFinalizeError(f"truncated tick spool frame length: {path}")
            frame_len = int.from_bytes(len_raw, "little", signed=False)
            if frame_len <= 0:
                raise FridaFinalizeError(f"invalid tick spool frame length: {frame_len}")
            payload = handle.read(frame_len)
            if len(payload) != frame_len:
                raise FridaFinalizeError(f"truncated tick spool payload: {path}")
            try:
                yield _TICK_DECODER.decode(payload)
            except (msgspec.DecodeError, msgspec.ValidationError) as exc:
                raise FridaFinalizeError(f"invalid tick spool payload in {path}") from exc


def _run_output_path(
    *,
    raw_path: Path,
    output_dir: Path,
    mode_id: int,
    quest_stage_major: int,
    quest_stage_minor: int,
    counters: dict[str, int],
) -> Path:
    base = Path(raw_path).stem
    is_quest_run = (
        int(mode_id) == int(_GAME_MODE_QUESTS)
        and int(quest_stage_major) > 0
        and int(quest_stage_minor) > 0
    )
    if is_quest_run:
        key = f"quest_{int(quest_stage_major)}_{int(quest_stage_minor)}"
        idx = counters.get(key, 0) + 1
        counters[key] = idx
        name = f"{base}.quest_{int(quest_stage_major)}_{int(quest_stage_minor)}.run{idx}.cdt"
    else:
        mode_label = str(_MODE_LABEL_BY_ID.get(int(mode_id), f"mode_{int(mode_id)}"))
        key = mode_label
        idx = counters.get(key, 0) + 1
        counters[key] = idx
        name = f"{base}.{mode_label}.run{idx}.cdt"
    return Path(output_dir) / name


def _build_meta(
    *,
    raw_fingerprint: BuiltinObject,
    session_start: _SessionStartRow,
    run: _OpenRun,
    tick_count: int,
    channels_seen: set[str],
) -> TraceMeta:
    producer_platform = str(session_start.platform)
    producer_arch = str(session_start.arch)
    producer_impl_version = str(session_start.script_version)
    config = msgspec.to_builtins(session_start.config)
    if not isinstance(config, dict):
        raise FridaFinalizeError("session_start.config must encode to a mapping")

    sorted_channels = sorted(str(channel) for channel in channels_seen)
    tick_end = int(tick_count) - 1
    return TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer=TraceProducer(
            impl="frida_original",
            impl_version=producer_impl_version,
            platform=producer_platform,
            arch=producer_arch,
        ),
        source=TraceSource(
            path=_builtin_text(raw_fingerprint, "path"),
            sha256=_builtin_text(raw_fingerprint, "sha256"),
            size=_builtin_int(raw_fingerprint, "size"),
            mtime_ns=_builtin_int(raw_fingerprint, "mtime_ns"),
            mode_id=int(run.mode_id),
            seed=int(run.replay_seed),
            run_id=int(run.run_id),
            quest_stage_major=int(run.quest_stage_major),
            quest_stage_minor=int(run.quest_stage_minor),
            global_tick_first=None if run.global_tick_first is None else int(run.global_tick_first),
            global_tick_last=None if run.global_tick_last is None else int(run.global_tick_last),
            run_start_seed_source=str(run.replay_seed_source),
        ),
        channels=sorted_channels,
        channel_versions=channel_versions_for(sorted_channels),
        tick_range=TraceTickRange(
            start_tick=0 if tick_count > 0 else -1,
            end_tick=tick_end if tick_count > 0 else -1,
            tick_count=int(tick_count),
        ),
        config=TraceConfig(frida=config),
        status=run.status,
    )


def _write_run_trace(
    *,
    raw_path: Path,
    output_dir: Path,
    raw_fingerprint: BuiltinObject,
    session_start: _SessionStartRow,
    run: _OpenRun,
    chunk_ticks: int,
    counters: dict[str, int],
) -> FinalizedTrace:
    run.stream.flush()
    run.stream.close()
    if int(run.replay_player_count) <= 0:
        raise FridaFinalizeError(f"run {run.run_id}: invalid replay player_count={run.replay_player_count}")
    if len(run.replay_inputs) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_inputs count {len(run.replay_inputs)} does not match tick_count {run.tick_count}",
        )
    if len(run.replay_dt) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_dt count {len(run.replay_dt)} "
            f"does not match tick_count {run.tick_count}",
        )
    out_path = _run_output_path(
        raw_path=raw_path,
        output_dir=output_dir,
        mode_id=int(run.mode_id),
        quest_stage_major=int(run.quest_stage_major),
        quest_stage_minor=int(run.quest_stage_minor),
        counters=counters,
    )
    meta = _build_meta(
        raw_fingerprint=raw_fingerprint,
        session_start=session_start,
        run=run,
        tick_count=int(run.tick_count),
        channels_seen=set(run.channels_seen),
    )
    summary = write_trace_iter(
        out_path,
        meta=meta,
        ticks=_tick_iter_from_spool(run.temp_path),
        chunk_ticks=max(1, int(chunk_ticks)),
    )
    replay_path = Path(out_path).with_suffix(".crd")
    is_quest_run = (
        int(run.mode_id) == int(_GAME_MODE_QUESTS)
        and int(run.quest_stage_major) > 0
        and int(run.quest_stage_minor) > 0
    )
    settings = session_settings_for_lockstep(
        mode_id=GameMode(int(run.mode_id)),
        player_count=int(run.replay_player_count),
        quest_level=(
            QuestLevel(int(run.quest_stage_major), int(run.quest_stage_minor))
            if is_quest_run
            else None
        ),
        preserve_bugs=False,
    )
    replay_header = replay_header_from_session_settings(
        settings,
        seed=int(run.replay_seed),
        status=run.status,
    )
    replay_ticks = [
        ReplayTick(
            inputs=run.replay_inputs[i],
            dt=run.replay_dt[i],
        )
        for i in range(run.tick_count)
    ]
    dump_replay_file(
        replay_path,
        Replay(header=replay_header, ticks=replay_ticks),
    )
    return FinalizedTrace(
        run_id=int(run.run_id),
        out_path=Path(out_path),
        replay_path=Path(replay_path),
        tick_count=int(run.tick_count),
        mode_id=int(run.mode_id),
        quest_stage_major=int(run.quest_stage_major),
        quest_stage_minor=int(run.quest_stage_minor),
        summary=summary,
    )


def finalize_frida_jsonl_to_traces(
    raw_path: Path,
    *,
    output_dir: Path | None = None,
    chunk_ticks: int = 256,
    delete_raw: bool = True,
) -> FinalizeResult:
    raw_path = Path(raw_path)
    if not raw_path.is_file():
        raise FridaFinalizeError(f"raw frida trace not found: {raw_path}")
    output_root = raw_path.parent if output_dir is None else Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    raw_fingerprint = _fingerprint(raw_path)

    traces: list[FinalizedTrace] = []
    run_counters: dict[str, int] = {}
    session_start: _SessionStartRow | None = None
    session_ended = False
    active_run: _OpenRun | None = None
    captured_tick_count = 0

    temp_dir_obj = TemporaryDirectory(prefix="crimson-frida-finalize-")
    temp_root = Path(temp_dir_obj.name)
    try:
        with raw_path.open("rb") as handle:
            for line_no, raw_line in enumerate(handle, start=1):
                line = bytes(raw_line).strip()
                if not line:
                    continue
                row = _decode_capture_row(line, field=f"{raw_path}.lines[{line_no}]")

                match row:
                    case _SessionStartRow() as session_row:
                        if session_start is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] duplicate session_start")
                        if int(session_row.capture_format_version) != int(_SUPPORTED_CAPTURE_FORMAT_VERSION):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] unsupported capture_format_version="
                                f"{int(session_row.capture_format_version)}; expected {int(_SUPPORTED_CAPTURE_FORMAT_VERSION)}",
                            )
                        if int(session_row.schema_version) != int(_SUPPORTED_JSONL_SCHEMA_VERSION):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] unsupported schema_version="
                                f"{int(session_row.schema_version)}; expected {int(_SUPPORTED_JSONL_SCHEMA_VERSION)}",
                            )
                        if not str(session_row.session_id):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].session_id must be non-empty")
                        if not str(session_row.out_path):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].out_path must be non-empty")
                        if not str(session_row.platform):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].platform must be non-empty")
                        if not str(session_row.arch):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].arch must be non-empty")
                        if not str(session_row.script_version):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].script_version must be non-empty")
                        if int(session_row.config.jsonl_schema_version) != int(session_row.schema_version):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].config.jsonl_schema_version must match schema_version",
                            )
                        if str(session_row.config.out_path) != str(session_row.out_path):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].config.out_path must match out_path",
                            )
                        if str(session_row.session_fingerprint.session_id) != str(session_row.session_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].session_fingerprint.session_id must match session_id",
                            )
                        session_start = session_row
                        continue
                    case _:
                        if session_start is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] must start with session_start")

                match row:
                    case _RunStartRow() as run_start:
                        if active_run is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_start while run is active")
                        if str(run_start.reason) not in _RUN_START_REASONS:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].reason must be one of {sorted(_RUN_START_REASONS)!r}",
                            )
                        if str(run_start.seed_source) not in _SEED_SOURCES:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].seed_source must be one of {sorted(_SEED_SOURCES)!r}",
                            )
                        mode_id = int(run_start.mode_id)
                        if int(run_start.seed) < 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].seed must be >= 0")
                        if int(run_start.player_count) <= 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].player_count must be positive")
                        spool_path = temp_root / f"run_{int(run_start.run_id)}.ticks"
                        active_run = _OpenRun(
                            run_id=int(run_start.run_id),
                            mode_id=mode_id,
                            quest_stage_major=int(run_start.quest_stage_major),
                            quest_stage_minor=int(run_start.quest_stage_minor),
                            replay_seed=int(run_start.seed),
                            replay_player_count=int(run_start.player_count),
                            temp_path=spool_path,
                            stream=spool_path.open("wb"),
                            replay_seed_source=str(run_start.seed_source),
                        )
                        continue
                    case _TickRow() as tick_row:
                        if active_run is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] tick outside run")
                        if int(tick_row.run_id) != int(active_run.run_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick run_id={int(tick_row.run_id)} "
                                f"does not match active run {active_run.run_id}",
                            )
                        if int(tick_row.mode_id) != int(active_run.mode_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick mode_id={int(tick_row.mode_id)} "
                                f"does not match active run {active_run.mode_id}",
                            )
                        if int(tick_row.quest_stage_major) != int(active_run.quest_stage_major):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick quest_stage_major={int(tick_row.quest_stage_major)} "
                                f"does not match active run {active_run.quest_stage_major}",
                            )
                        if int(tick_row.quest_stage_minor) != int(active_run.quest_stage_minor):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick quest_stage_minor={int(tick_row.quest_stage_minor)} "
                                f"does not match active run {active_run.quest_stage_minor}",
                            )
                        if not math.isfinite(float(tick_row.dt)) or float(tick_row.dt) < 0.0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].dt must be finite and >= 0",
                            )
                        if int(tick_row.elapsed_ms) < 0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].elapsed_ms must be >= 0",
                            )
                        if int(tick_row.dt_ms_i32) < 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].dt_ms_i32 must be >= 0")
                        _validate_tick_channels(
                            channels=tick_row.channels,
                            expected_players=int(active_run.replay_player_count),
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt=float(tick_row.dt),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            quest_stage_major=int(tick_row.quest_stage_major),
                            quest_stage_minor=int(tick_row.quest_stage_minor),
                            field=f"{raw_path}.lines[{line_no}].channels",
                        )
                        replay_inputs = _replay_tick_inputs_from_row(
                            tick_row.replay_inputs,
                            expected_players=int(active_run.replay_player_count),
                            field=f"{raw_path}.lines[{line_no}].replay_inputs",
                        )
                        _checkpoint, channels = _canonical_channels_payload(
                            channels=tick_row.channels,
                            local_tick=int(active_run.next_local_tick),
                            field=f"{raw_path}.lines[{line_no}].channels",
                        )
                        if int(active_run.tick_count) == 0 and tick_row.channels.sim_state.gameplay.status is not None:
                            active_run.status = tick_row.channels.sim_state.gameplay.status
                        active_run.replay_inputs.append(list(replay_inputs))
                        active_run.replay_dt.append(float(tick_row.dt))
                        tick = TickRecord(
                            tick_index=int(active_run.next_local_tick),
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            channels=channels,
                        )
                        payload = _TICK_ENCODER.encode(tick)
                        active_run.stream.write(len(payload).to_bytes(_FRAME_LEN_BYTES, "little", signed=False))
                        active_run.stream.write(payload)
                        active_run.next_local_tick += 1
                        active_run.tick_count += 1
                        captured_tick_count += 1
                        active_run.channels_seen.update(TRACE_REQUIRED_CHANNELS)
                        if tick_row.tick_index_global is not None:
                            global_tick = int(tick_row.tick_index_global)
                            if active_run.global_tick_first is None:
                                active_run.global_tick_first = global_tick
                            active_run.global_tick_last = global_tick
                        continue
                    case _RunEndRow() as run_end:
                        if active_run is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_end without active run")
                        if int(run_end.run_id) != int(active_run.run_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end run_id={int(run_end.run_id)} "
                                f"does not match active run {active_run.run_id}",
                            )
                        if str(run_end.reason) not in _RUN_END_REASONS:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].reason must be one of {sorted(_RUN_END_REASONS)!r}",
                            )
                        if int(run_end.mode_id) != int(active_run.mode_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end mode_id={int(run_end.mode_id)} "
                                f"does not match active run {active_run.mode_id}",
                            )
                        if int(run_end.quest_stage_major) != int(active_run.quest_stage_major):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end quest_stage_major={int(run_end.quest_stage_major)} "
                                f"does not match active run {active_run.quest_stage_major}",
                            )
                        if int(run_end.quest_stage_minor) != int(active_run.quest_stage_minor):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end quest_stage_minor={int(run_end.quest_stage_minor)} "
                                f"does not match active run {active_run.quest_stage_minor}",
                            )
                        if int(run_end.ticks_written) != int(active_run.tick_count):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end.ticks_written={int(run_end.ticks_written)} "
                                f"does not match active run tick_count {int(active_run.tick_count)}",
                            )
                        traces.append(
                            _write_run_trace(
                                raw_path=raw_path,
                                output_dir=output_root,
                                raw_fingerprint=raw_fingerprint,
                                session_start=session_start,
                                run=active_run,
                                chunk_ticks=max(1, int(chunk_ticks)),
                                counters=run_counters,
                            ),
                        )
                        active_run = None
                        continue
                    case _ErrorRow() as error_row:
                        location = f"{raw_path}.lines[{line_no}]"
                        if error_row.tick_index_global is None:
                            raise FridaFinalizeError(f"{location} capture error={error_row.error!r}")
                        raise FridaFinalizeError(
                            f"{location} capture error={error_row.error!r} "
                            f"tick_index_global={int(error_row.tick_index_global)}",
                        )
                    case _SessionEndRow():
                        if active_run is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] session_end while run is active")
                        if str(row.session_id) != str(session_start.session_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].session_id must match session_start.session_id",
                            )
                        if int(row.ticks_written) != int(captured_tick_count):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].ticks_written={int(row.ticks_written)} "
                                f"does not match parsed tick_count {int(captured_tick_count)}",
                            )
                        session_ended = True
                        continue
                    case _:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] unsupported capture row")

        if session_start is None:
            raise FridaFinalizeError(f"{raw_path} missing session_start")
        if active_run is not None:
            # Allow abrupt host/process shutdown to still produce a usable run.
            # We already validated all parsed rows and can finalize the in-flight spool.
            traces.append(
                _write_run_trace(
                    raw_path=raw_path,
                    output_dir=output_root,
                    raw_fingerprint=raw_fingerprint,
                    session_start=session_start,
                    run=active_run,
                    chunk_ticks=max(1, int(chunk_ticks)),
                    counters=run_counters,
                ),
            )
            active_run = None
        if not session_ended and not traces:
            raise FridaFinalizeError(f"{raw_path} missing session_end")
        if not traces:
            raise FridaFinalizeError(f"{raw_path} had no finalized runs")
    finally:
        if active_run is not None:
            with suppress(Exception):
                active_run.stream.close()
        with suppress(OSError):
            temp_dir_obj.cleanup()

    deleted = False
    if bool(delete_raw):
        raw_path.unlink(missing_ok=False)
        deleted = True

    return FinalizeResult(
        raw_path=raw_path,
        traces=list(traces),
        deleted_raw=bool(deleted),
    )
