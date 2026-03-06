from __future__ import annotations

import hashlib
import math
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, BinaryIO, cast

import msgspec

from grim.rand import CrtRand

from ..game_modes import GameMode
from ..net.session_settings import session_settings_for_lockstep
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.codec import dump_replay_file
from ..replay.header_settings import replay_header_from_session_settings
from ..replay.types import WEAPON_USAGE_COUNT, BootstrapKind, Replay, ReplayStatusSnapshot, ReplayTick
from ..sim.bootstrap import run_terrain_bootstrap
from ..status_snapshot import progress_status_from_debug_snapshot, replay_status_from_progress
from .canonical_channels import EntitySamplesSnapshot, RngStreamRow, SimStateSnapshot, TimingSampleRow
from .payloads import BuiltinObject
from .rng import canonical_rng_marks
from .schema import (
    TRACE_FORMAT_VERSION,
    TRACE_REQUIRED_CHANNELS,
    TRACE_SCHEMA_VERSION,
    ReplayTickChannels,
    TickRecord,
    TraceMeta,
    channel_versions_for,
)
from .trace import TraceSummary, write_trace_iter

_FRAME_LEN_BYTES = 4
_TICK_ENCODER = msgspec.msgpack.Encoder()
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_GAME_MODE_QUESTS = 3
_GAME_MODE_SURVIVAL = int(GameMode.SURVIVAL)
_GAME_MODE_RUSH = int(GameMode.RUSH)
_TERRAIN_BOOTSTRAP_MODES = {_GAME_MODE_SURVIVAL, _GAME_MODE_RUSH}
_BOOTSTRAP_KINDS: set[BootstrapKind] = {"none", "terrain_v1"}
_SUPPORTED_CAPTURE_FORMAT_VERSION = 9
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


class _TickChannels(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    checkpoint: ReplayCheckpoint
    sim_state: SimStateSnapshot
    entity_samples: EntitySamplesSnapshot
    rng_marks: dict[str, int] = msgspec.field(default_factory=dict)
    rng_stream: list[RngStreamRow] = msgspec.field(default_factory=list)
    timing_samples: list[TimingSampleRow] = msgspec.field(default_factory=list)


class _SessionStartRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="session_start",
):
    capture_format_version: int
    schema_version: int = 1
    session_id: str = ""
    out_path: str = ""
    platform: str = "windows"
    arch: str = "x86"
    script_version: str = ""
    config: dict[str, Any] = msgspec.field(default_factory=dict)
    session_fingerprint: dict[str, Any] = msgspec.field(default_factory=dict)


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
    bootstrap_kind: str = "none"
    bootstrap_seed: int = 0
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
    phase_markers: list[str] = msgspec.field(default_factory=list)
    replay_inputs: list[tuple[float, float, float, float, int]] = msgspec.field(default_factory=list)


class _RunEndRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_end",
):
    run_id: int
    reason: str = "run_end"
    mode_id: int = -1
    quest_stage_major: int = -1
    quest_stage_minor: int = -1
    tick_index_global: int | None = None
    ticks_written: int = 0


class _SessionEndRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="session_end",
):
    session_id: str = ""
    ticks_written: int = 0


type _CaptureRow = _SessionStartRow | _RunStartRow | _TickRow | _RunEndRow | _SessionEndRow


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
    replay_bootstrap_kind: BootstrapKind
    replay_bootstrap_seed: int
    replay_player_count: int
    temp_path: Path
    stream: BinaryIO
    replay_seed_source: str = "unknown"
    tick_count: int = 0
    next_local_tick: int = 0
    replay_inputs: list[list[list[float | int]]] = msgspec.field(default_factory=list)
    replay_dt: list[float] = msgspec.field(default_factory=list)
    replay_status: ReplayStatusSnapshot = msgspec.field(default_factory=lambda: ReplayStatusSnapshot())
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


def _decode_capture_row(line: bytes, *, field: str) -> _CaptureRow:
    try:
        return _CAPTURE_ROW_DECODER.decode(line)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise FridaFinalizeError(f"{field} invalid capture row: {exc}") from exc


def _validate_bootstrap_kind(kind: str, *, field: str) -> BootstrapKind:
    if kind not in _BOOTSTRAP_KINDS:
        raise FridaFinalizeError(f"{field} must be one of {sorted(_BOOTSTRAP_KINDS)!r}, got {kind!r}")
    return cast("BootstrapKind", kind)


def _canonical_channels_payload(
    *,
    channels: _TickChannels,
    local_tick: int,
    field: str,
) -> tuple[ReplayCheckpoint, ReplayTickChannels]:
    checkpoint = msgspec.structs.replace(
        channels.checkpoint,
        tick_index=int(local_tick),
    )
    expected_rng_marks = canonical_rng_marks(
        rng_state=int(checkpoint.rng_state),
        rng_stream=channels.rng_stream,
    )
    if dict(checkpoint.rng_marks) != expected_rng_marks:
        raise FridaFinalizeError(
            f"{field}.checkpoint.rng_marks must match canonical rng marks; "
            "recapture with updated gameplay_diff_capture.js",
        )
    if dict(channels.rng_marks) != expected_rng_marks:
        raise FridaFinalizeError(
            f"{field}.rng_marks must match canonical rng marks; "
            "recapture with updated gameplay_diff_capture.js",
        )
    checkpoint = msgspec.structs.replace(checkpoint, rng_marks=dict(expected_rng_marks))
    normalized = _TickChannels(
        checkpoint=checkpoint,
        sim_state=channels.sim_state,
        entity_samples=channels.entity_samples,
        rng_marks=dict(expected_rng_marks),
        rng_stream=list(channels.rng_stream),
        timing_samples=list(channels.timing_samples),
    )
    return checkpoint, ReplayTickChannels(
        checkpoint=normalized.checkpoint,
        sim_state=normalized.sim_state,
        entity_samples=normalized.entity_samples,
        rng_marks=dict(normalized.rng_marks),
        rng_stream=list(normalized.rng_stream),
        timing_samples=list(normalized.timing_samples),
    )


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
    for move_x, move_y, aim_x, aim_y, flags in replay_inputs:
        out.append([float(move_x), float(move_y), float(aim_x), float(aim_y), int(flags)])
    return out


def _replay_status_from_channels(channels: _TickChannels) -> ReplayStatusSnapshot:
    status = channels.sim_state.gameplay.status
    expected_usage_count = int(WEAPON_USAGE_COUNT)
    if len(status.weapon_usage_counts) != expected_usage_count:
        raise FridaFinalizeError(
            "sim_state.gameplay.status.weapon_usage_counts length mismatch: "
            f"expected {expected_usage_count}, got {len(status.weapon_usage_counts)}",
        )
    progress = progress_status_from_debug_snapshot(status)
    return replay_status_from_progress(progress)


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


def _validate_run_seed_for_replay(run: _OpenRun) -> None:
    if int(run.mode_id) not in _TERRAIN_BOOTSTRAP_MODES:
        return
    bootstrap_seed = int(run.replay_bootstrap_seed)
    world_size = 1024
    quest_unlock_index = int(run.replay_status.quest_unlock_index)
    rng = CrtRand(seed=int(bootstrap_seed))
    terrain = run_terrain_bootstrap(
        rng,
        quest_unlock_index=int(quest_unlock_index),
        width=int(world_size),
        height=int(world_size),
        layers=3,
    )
    if int(run.replay_seed) != int(terrain.seed_after):
        raise FridaFinalizeError(
            f"run {run.run_id}: terrain bootstrap seed mismatch "
            f"mode_id={run.mode_id} "
            f"bootstrap_seed={bootstrap_seed} "
            f"quest_unlock_index={quest_unlock_index} "
            f"expected_seed_after={int(terrain.seed_after)} "
            f"run_start.seed={int(run.replay_seed)} "
            f"seed_source={run.replay_seed_source!r}",
        )


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
    config = dict(session_start.config)
    source = dict(raw_fingerprint)
    source["run_id"] = int(run.run_id)
    source["mode_id"] = int(run.mode_id)
    source["quest_stage_major"] = int(run.quest_stage_major)
    source["quest_stage_minor"] = int(run.quest_stage_minor)
    source["global_tick_first"] = None if run.global_tick_first is None else int(run.global_tick_first)
    source["global_tick_last"] = None if run.global_tick_last is None else int(run.global_tick_last)
    source["run_start_seed_source"] = str(run.replay_seed_source)

    sorted_channels = sorted(str(channel) for channel in channels_seen)
    tick_end = int(tick_count) - 1
    return TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer={
            "impl": "frida_original",
            "impl_version": producer_impl_version,
            "platform": producer_platform,
            "arch": producer_arch,
        },
        source=source,
        channels=sorted_channels,
        channel_versions=channel_versions_for(sorted_channels),
        tick_range={
            "start_tick": 0 if tick_count > 0 else -1,
            "end_tick": tick_end if tick_count > 0 else -1,
            "tick_count": int(tick_count),
        },
        config=config,
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
    _validate_run_seed_for_replay(run)
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
        mode_id=int(run.mode_id),
        player_count=int(run.replay_player_count),
        quest_level=(f"{int(run.quest_stage_major)}.{int(run.quest_stage_minor)}" if is_quest_run else ""),
        preserve_bugs=False,
    )
    replay_header = replay_header_from_session_settings(
        settings,
        seed=int(run.replay_seed),
        bootstrap_kind=run.replay_bootstrap_kind,
        bootstrap_seed=int(run.replay_bootstrap_seed),
        status=run.replay_status,
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
                        session_start = session_row
                        continue
                    case _:
                        if session_start is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] must start with session_start")

                match row:
                    case _RunStartRow() as run_start:
                        if active_run is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_start while run is active")
                        bootstrap_kind = _validate_bootstrap_kind(
                            run_start.bootstrap_kind,
                            field=f"{raw_path}.lines[{line_no}].bootstrap_kind",
                        )
                        mode_id = int(run_start.mode_id)
                        if mode_id in _TERRAIN_BOOTSTRAP_MODES:
                            if bootstrap_kind != "terrain_v1":
                                raise FridaFinalizeError(
                                    f"{raw_path}.lines[{line_no}] mode_id={mode_id} requires "
                                    "bootstrap_kind='terrain_v1'; recapture with updated gameplay_diff_capture.js",
                                )
                        elif bootstrap_kind != "none":
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] mode_id={mode_id} requires bootstrap_kind='none'",
                            )
                        if int(run_start.bootstrap_seed) < 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].bootstrap_seed must be >= 0")
                        if int(run_start.player_count) <= 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].player_count must be positive")
                        spool_path = temp_root / f"run_{int(run_start.run_id)}.ticks"
                        active_run = _OpenRun(
                            run_id=int(run_start.run_id),
                            mode_id=mode_id,
                            quest_stage_major=int(run_start.quest_stage_major),
                            quest_stage_minor=int(run_start.quest_stage_minor),
                            replay_seed=int(run_start.seed),
                            replay_bootstrap_kind=bootstrap_kind,
                            replay_bootstrap_seed=int(run_start.bootstrap_seed),
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
                        if not math.isfinite(float(tick_row.dt)) or float(tick_row.dt) < 0.0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].dt must be finite and >= 0",
                            )
                        if int(tick_row.dt_ms_i32) < 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].dt_ms_i32 must be >= 0")
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
                        active_run.replay_status = _replay_status_from_channels(tick_row.channels)
                        active_run.replay_inputs.append(list(replay_inputs))
                        active_run.replay_dt.append(float(tick_row.dt))
                        tick = TickRecord(
                            tick_index=int(active_run.next_local_tick),
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            phase_markers=list(tick_row.phase_markers),
                            channels=channels,
                        )
                        payload = _TICK_ENCODER.encode(tick)
                        active_run.stream.write(len(payload).to_bytes(_FRAME_LEN_BYTES, "little", signed=False))
                        active_run.stream.write(payload)
                        active_run.next_local_tick += 1
                        active_run.tick_count += 1
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
                    case _SessionEndRow():
                        if active_run is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] session_end while run is active")
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
