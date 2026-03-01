from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO

import msgspec

from .schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta, channel_versions_for
from .trace import TraceSummary, write_trace_iter

_FRAME_LEN_BYTES = 4
_TICK_ENCODER = msgspec.msgpack.Encoder()
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_GAME_MODE_QUESTS = 3
_ENTITY_KIND_CODES = {
    "creature": 1,
    "projectile": 2,
    "secondary_projectile": 3,
    "bonus": 4,
}


class FridaFinalizeError(ValueError):
    pass


class FinalizedTrace(msgspec.Struct, frozen=True):
    run_id: int
    out_path: Path
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
    temp_path: Path
    stream: BinaryIO
    tick_count: int = 0
    next_local_tick: int = 0
    channels_seen: set[str] = msgspec.field(default_factory=set)
    global_tick_first: int | None = None
    global_tick_last: int | None = None
    creature_state: _EntityUidState = msgspec.field(default_factory=lambda: _EntityUidState())
    projectile_state: _EntityUidState = msgspec.field(default_factory=lambda: _EntityUidState())
    secondary_state: _EntityUidState = msgspec.field(default_factory=lambda: _EntityUidState())
    bonus_state: _EntityUidState = msgspec.field(default_factory=lambda: _EntityUidState())


class _EntityUidState(msgspec.Struct):
    generation_by_index: dict[int, int] = msgspec.field(default_factory=dict)
    active_indices: set[int] = msgspec.field(default_factory=set)

    def next_uid(self, *, kind: str, index: int, active: bool) -> tuple[int, int]:
        idx = int(index)
        if bool(active) and idx not in self.active_indices:
            self.generation_by_index[idx] = int(self.generation_by_index.get(idx, 0)) + 1
        if bool(active):
            self.active_indices.add(idx)
        else:
            self.active_indices.discard(idx)
        generation = int(self.generation_by_index.get(idx, 0))
        kind_code = int(_ENTITY_KIND_CODES[kind]) & 0xFF
        uid = (kind_code << 56) | ((generation & 0xFFFFFF) << 32) | (idx & 0xFFFFFFFF)
        return int(uid), int(generation)


def _as_dict(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise FridaFinalizeError(f"{field} must be an object")
    out: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise FridaFinalizeError(f"{field} contains non-string key")
        out[key] = item
    return out


def _as_str_list(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list):
        raise FridaFinalizeError(f"{field} must be a list")
    out: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            raise FridaFinalizeError(f"{field}[{idx}] must be a string")
        out.append(str(item))
    return out


def _as_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise FridaFinalizeError(f"{field} must be int, got bool")
    if isinstance(value, int):
        return int(value)
    raise FridaFinalizeError(f"{field} must be int, got {type(value).__name__}")


def _as_optional_int(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    return _as_int(value, field=field)


def _fingerprint(path: Path) -> dict[str, object]:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def _as_int_default(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(default)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return int(value)
    return int(default)


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, float):
        return bool(int(value))
    return False


def _entity_rows_from_raw(
    rows_obj: object,
    *,
    state: _EntityUidState,
    kind: str,
    active_fn,
) -> list[dict[str, object]]:
    rows = rows_obj if isinstance(rows_obj, list) else []
    out: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        payload = _as_dict(row, field=f"entity_samples.{kind}[]")
        idx = _as_int_default(payload.get("index"), default=0)
        active = bool(active_fn(payload))
        uid, generation = state.next_uid(kind=kind, index=int(idx), active=bool(active))
        payload["uid"] = int(uid)
        payload["generation"] = int(generation)
        payload["pool_kind"] = str(kind)
        out.append(payload)
    return out


def _normalize_entity_samples(
    *,
    run: _OpenRun,
    channels: dict[str, object],
) -> None:
    entity_obj = channels.get("entity_samples")
    if not isinstance(entity_obj, dict):
        return
    entity_samples = _as_dict(entity_obj, field="tick.channels.entity_samples")
    channels["entity_samples"] = {
        "creatures": _entity_rows_from_raw(
            entity_samples.get("creatures"),
            state=run.creature_state,
            kind="creature",
            active_fn=lambda payload: _as_bool(payload.get("active")),
        ),
        "projectiles": _entity_rows_from_raw(
            entity_samples.get("projectiles"),
            state=run.projectile_state,
            kind="projectile",
            active_fn=lambda payload: _as_bool(payload.get("active")),
        ),
        "secondary_projectiles": _entity_rows_from_raw(
            entity_samples.get("secondary_projectiles"),
            state=run.secondary_state,
            kind="secondary_projectile",
            active_fn=lambda payload: _as_bool(payload.get("active")),
        ),
        "bonuses": _entity_rows_from_raw(
            entity_samples.get("bonuses"),
            state=run.bonus_state,
            kind="bonus",
            active_fn=lambda payload: _as_int_default(payload.get("state"), default=0) != 0,
        ),
    }


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
        key = f"mode_{int(mode_id)}"
        idx = counters.get(key, 0) + 1
        counters[key] = idx
        name = f"{base}.mode_{int(mode_id)}.run{idx}.cdt"
    return Path(output_dir) / name


def _build_meta(
    *,
    raw_fingerprint: dict[str, object],
    session_meta: dict[str, object],
    run: _OpenRun,
    tick_count: int,
    channels_seen: set[str],
) -> TraceMeta:
    producer_platform = str(session_meta.get("platform", "windows"))
    producer_arch = str(session_meta.get("arch", "x86"))
    producer_impl_version = str(session_meta.get("script_version", ""))
    config_obj = session_meta.get("config")
    config = _as_dict(config_obj, field="session_start.config") if isinstance(config_obj, dict) else {}
    source = dict(raw_fingerprint)
    source["run_id"] = int(run.run_id)
    source["mode_id"] = int(run.mode_id)
    source["quest_stage_major"] = int(run.quest_stage_major)
    source["quest_stage_minor"] = int(run.quest_stage_minor)
    source["global_tick_first"] = None if run.global_tick_first is None else int(run.global_tick_first)
    source["global_tick_last"] = None if run.global_tick_last is None else int(run.global_tick_last)

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
    raw_fingerprint: dict[str, object],
    session_meta: dict[str, object],
    run: _OpenRun,
    chunk_ticks: int,
    counters: dict[str, int],
) -> FinalizedTrace:
    run.stream.flush()
    run.stream.close()
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
        session_meta=session_meta,
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
    return FinalizedTrace(
        run_id=int(run.run_id),
        out_path=Path(out_path),
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
    session_meta: dict[str, object] = {}
    session_started = False
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
                try:
                    decoded = msgspec.json.decode(line)
                except msgspec.DecodeError as exc:
                    raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] must be valid json") from exc
                row = _as_dict(decoded, field=f"{raw_path}.lines[{line_no}]")
                event_obj = row.get("event")
                if not isinstance(event_obj, str):
                    raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].event must be a string")
                event = str(event_obj)

                if event == "session_start":
                    if session_started:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] duplicate session_start")
                    session_started = True
                    session_meta = dict(row)
                    continue

                if not session_started:
                    raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] must start with session_start")

                if event == "run_start":
                    if active_run is not None:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_start while run is active")
                    run_id = _as_int(row.get("run_id"), field=f"{raw_path}.lines[{line_no}].run_id")
                    mode_id = _as_int(row.get("mode_id"), field=f"{raw_path}.lines[{line_no}].mode_id")
                    quest_stage_major = _as_int(
                        row.get("quest_stage_major", -1),
                        field=f"{raw_path}.lines[{line_no}].quest_stage_major",
                    )
                    quest_stage_minor = _as_int(
                        row.get("quest_stage_minor", -1),
                        field=f"{raw_path}.lines[{line_no}].quest_stage_minor",
                    )
                    spool_path = temp_root / f"run_{int(run_id)}.ticks"
                    active_run = _OpenRun(
                        run_id=int(run_id),
                        mode_id=int(mode_id),
                        quest_stage_major=int(quest_stage_major),
                        quest_stage_minor=int(quest_stage_minor),
                        temp_path=spool_path,
                        stream=spool_path.open("wb"),
                    )
                    continue

                if event == "tick":
                    if active_run is None:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] tick outside run")
                    row_run_id = _as_int(row.get("run_id"), field=f"{raw_path}.lines[{line_no}].run_id")
                    if int(row_run_id) != int(active_run.run_id):
                        raise FridaFinalizeError(
                            f"{raw_path}.lines[{line_no}] tick run_id={row_run_id} "
                            f"does not match active run {active_run.run_id}",
                        )
                    elapsed_ms = _as_int(row.get("elapsed_ms"), field=f"{raw_path}.lines[{line_no}].elapsed_ms")
                    dt_ms_i32 = _as_optional_int(row.get("dt_ms_i32"), field=f"{raw_path}.lines[{line_no}].dt_ms_i32")
                    mode_id = _as_int(row.get("mode_id"), field=f"{raw_path}.lines[{line_no}].mode_id")
                    phase_markers_obj = row.get("phase_markers", [])
                    phase_markers = _as_str_list(
                        phase_markers_obj,
                        field=f"{raw_path}.lines[{line_no}].phase_markers",
                    )
                    channels = _as_dict(
                        row.get("channels"),
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    _normalize_entity_samples(run=active_run, channels=channels)
                    tick = TickRecord(
                        tick_index=int(active_run.next_local_tick),
                        elapsed_ms=int(elapsed_ms),
                        dt_ms_i32=(None if dt_ms_i32 is None else int(dt_ms_i32)),
                        mode_id=int(mode_id),
                        phase_markers=list(phase_markers),
                        channels=dict(channels),
                    )
                    payload = _TICK_ENCODER.encode(tick)
                    active_run.stream.write(len(payload).to_bytes(_FRAME_LEN_BYTES, "little", signed=False))
                    active_run.stream.write(payload)
                    active_run.next_local_tick += 1
                    active_run.tick_count += 1
                    active_run.channels_seen.update(str(name) for name in channels.keys())
                    global_tick_obj = row.get("tick_index_global")
                    if isinstance(global_tick_obj, int) and not isinstance(global_tick_obj, bool):
                        global_tick = int(global_tick_obj)
                        if active_run.global_tick_first is None:
                            active_run.global_tick_first = global_tick
                        active_run.global_tick_last = global_tick
                    continue

                if event == "run_end":
                    if active_run is None:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_end without active run")
                    row_run_id = _as_int(row.get("run_id"), field=f"{raw_path}.lines[{line_no}].run_id")
                    if int(row_run_id) != int(active_run.run_id):
                        raise FridaFinalizeError(
                            f"{raw_path}.lines[{line_no}] run_end run_id={row_run_id} "
                            f"does not match active run {active_run.run_id}",
                        )
                    traces.append(
                        _write_run_trace(
                            raw_path=raw_path,
                            output_dir=output_root,
                            raw_fingerprint=raw_fingerprint,
                            session_meta=session_meta,
                            run=active_run,
                            chunk_ticks=max(1, int(chunk_ticks)),
                            counters=run_counters,
                        ),
                    )
                    active_run = None
                    continue

                if event == "session_end":
                    if active_run is not None:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] session_end while run is active")
                    session_ended = True
                    continue

                raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] unsupported event={event!r}")

        if not session_started:
            raise FridaFinalizeError(f"{raw_path} missing session_start")
        if active_run is not None:
            # Allow abrupt host/process shutdown to still produce a usable run.
            # We already validated all parsed rows and can finalize the in-flight spool.
            traces.append(
                _write_run_trace(
                    raw_path=raw_path,
                    output_dir=output_root,
                    raw_fingerprint=raw_fingerprint,
                    session_meta=session_meta,
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
