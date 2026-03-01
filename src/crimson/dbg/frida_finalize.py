from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO

import msgspec

from grim.rand import CrtRand

from ..game_modes import GameMode
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.codec import dump_replay_file
from ..replay.types import WEAPON_USAGE_COUNT, Replay, ReplayHeader, ReplayStatusSnapshot
from ..sim.bootstrap import run_terrain_bootstrap
from .record import _event_heads_from_checkpoint, _micro_traces_from_entities
from .schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta, channel_versions_for
from .trace import TraceSummary, write_trace_iter

_FRAME_LEN_BYTES = 4
_TICK_ENCODER = msgspec.msgpack.Encoder()
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_GAME_MODE_QUESTS = 3
_GAME_MODE_SURVIVAL = int(GameMode.SURVIVAL)
_GAME_MODE_RUSH = int(GameMode.RUSH)
_TERRAIN_BOOTSTRAP_MODES = {_GAME_MODE_SURVIVAL, _GAME_MODE_RUSH}
_BOOTSTRAP_KINDS = {"none", "terrain_v1"}
_FIRST_TICK_MAX_ELAPSED_MULTIPLIER = 8
_FIRST_TICK_MAX_ELAPSED_FLOOR_MS = 1000
_MODE_LABEL_BY_ID = {
    int(GameMode.DEMO): "demo",
    int(GameMode.SURVIVAL): "survival",
    int(GameMode.RUSH): "rush",
    int(GameMode.QUESTS): "quests",
    int(GameMode.TYPO): "typo",
    int(GameMode.TUTORIAL): "tutorial",
}
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
    replay_bootstrap_kind: str
    replay_bootstrap_seed: int
    replay_player_count: int
    temp_path: Path
    stream: BinaryIO
    replay_seed_source: str = "unknown"
    tick_count: int = 0
    next_local_tick: int = 0
    replay_inputs: list[list[list[float | int]]] = msgspec.field(default_factory=list)
    replay_dt_ms_i32: list[int] = msgspec.field(default_factory=list)
    replay_status: ReplayStatusSnapshot = msgspec.field(default_factory=lambda: ReplayStatusSnapshot())
    channels_seen: set[str] = msgspec.field(default_factory=set)
    global_tick_first: int | None = None
    global_tick_last: int | None = None
    previous_entity_samples: dict[str, object] | None = None
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


def _as_bootstrap_kind(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise FridaFinalizeError(f"{field} must be a string")
    kind = str(value)
    if kind not in _BOOTSTRAP_KINDS:
        raise FridaFinalizeError(
            f"{field} must be one of {sorted(_BOOTSTRAP_KINDS)!r}, got {kind!r}",
        )
    return kind


def _as_float(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise FridaFinalizeError(f"{field} must be numeric, got bool")
    if isinstance(value, (int, float)):
        return float(value)
    raise FridaFinalizeError(f"{field} must be numeric")


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


def _validate_checkpoint_channel(
    *,
    channels: dict[str, object],
    field: str,
) -> None:
    checkpoint_obj = channels.get("checkpoint")
    if not isinstance(checkpoint_obj, dict):
        return
    checkpoint = _as_dict(checkpoint_obj, field=f"{field}.checkpoint")
    channels["checkpoint"] = checkpoint
    try:
        msgspec.convert(checkpoint, type=ReplayCheckpoint)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise FridaFinalizeError(f"{field}.checkpoint is not a valid ReplayCheckpoint payload") from exc


def _rebase_checkpoint_tick_index(
    *,
    channels: dict[str, object],
    local_tick: int,
    field: str,
) -> None:
    checkpoint_obj = channels.get("checkpoint")
    if not isinstance(checkpoint_obj, dict):
        return
    checkpoint = _as_dict(checkpoint_obj, field=f"{field}.checkpoint")
    checkpoint["tick_index"] = int(local_tick)
    channels["checkpoint"] = checkpoint


def _canonicalize_checkpoint_creature_count(
    *,
    channels: dict[str, object],
    field: str,
) -> None:
    checkpoint_obj = channels.get("checkpoint")
    if not isinstance(checkpoint_obj, dict):
        return
    checkpoint = _as_dict(checkpoint_obj, field=f"{field}.checkpoint")
    debug_obj = checkpoint.get("debug")
    if not isinstance(debug_obj, dict):
        return
    debug = _as_dict(debug_obj, field=f"{field}.checkpoint.debug")
    lifecycle_obj = debug.get("creature_lifecycle")
    if not isinstance(lifecycle_obj, dict):
        return
    lifecycle = _as_dict(lifecycle_obj, field=f"{field}.checkpoint.debug.creature_lifecycle")
    after_count_obj = lifecycle.get("after_count")
    if isinstance(after_count_obj, bool):
        return
    if not isinstance(after_count_obj, (int, float)):
        return
    after_count = int(after_count_obj)
    if int(after_count) < 0:
        return
    checkpoint["creature_count"] = int(after_count)
    channels["checkpoint"] = checkpoint


def _is_unknown_death_row(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    row = value
    creature_index = row.get("creature_index")
    type_id = row.get("type_id")
    xp_awarded = row.get("xp_awarded")
    owner_id = row.get("owner_id")
    reward_value = row.get("reward_value")
    if any(isinstance(item, bool) for item in (creature_index, type_id, xp_awarded, owner_id, reward_value)):
        return False
    if not all(isinstance(item, (int, float)) for item in (creature_index, type_id, xp_awarded, owner_id, reward_value)):
        return False
    return (
        int(creature_index) == -1
        and int(type_id) == -1
        and int(xp_awarded) == -1
        and int(owner_id) == -1
        and int(reward_value) == 0
    )


def _canonicalize_checkpoint_events_and_deaths(
    *,
    channels: dict[str, object],
    field: str,
) -> None:
    checkpoint_obj = channels.get("checkpoint")
    if not isinstance(checkpoint_obj, dict):
        return
    checkpoint = _as_dict(checkpoint_obj, field=f"{field}.checkpoint")

    deaths_obj = checkpoint.get("deaths")
    if isinstance(deaths_obj, list):
        filtered_deaths: list[object] = []
        for row in deaths_obj:
            if _is_unknown_death_row(row):
                continue
            filtered_deaths.append(row)
        checkpoint["deaths"] = filtered_deaths

    events_obj = checkpoint.get("events")
    if isinstance(events_obj, dict):
        events = _as_dict(events_obj, field=f"{field}.checkpoint.events")
        for key in ("hit_count", "pickup_count", "sfx_count"):
            value = events.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)) and int(value) < 0:
                events[key] = 0
        checkpoint["events"] = events

    channels["checkpoint"] = checkpoint


def _validate_first_tick_elapsed_for_replay(
    *,
    run: _OpenRun,
    channels: dict[str, object],
    dt_ms_i32: int,
    field: str,
) -> None:
    if int(run.tick_count) != 0:
        return
    checkpoint_obj = channels.get("checkpoint")
    if not isinstance(checkpoint_obj, dict):
        return
    checkpoint = _as_dict(checkpoint_obj, field=f"{field}.checkpoint")
    elapsed_obj = checkpoint.get("elapsed_ms")
    if isinstance(elapsed_obj, bool):
        return
    if not isinstance(elapsed_obj, (int, float)):
        return
    elapsed_ms = int(elapsed_obj)
    dt_ms = max(1, int(dt_ms_i32))
    upper_bound = max(int(_FIRST_TICK_MAX_ELAPSED_FLOOR_MS), int(dt_ms) * int(_FIRST_TICK_MAX_ELAPSED_MULTIPLIER))
    if int(elapsed_ms) > int(upper_bound):
        raise FridaFinalizeError(
            f"{field}.checkpoint.elapsed_ms={elapsed_ms} is too large for first replayable tick "
            f"(dt_ms_i32={dt_ms}, max={upper_bound}); run likely started mid-session. "
            "Start capture before entering gameplay mode.",
        )


def _as_replay_tick_inputs(
    value: object,
    *,
    expected_players: int,
    field: str,
) -> list[list[float | int]]:
    if not isinstance(value, list):
        raise FridaFinalizeError(f"{field} must be a list")
    if len(value) != int(expected_players):
        raise FridaFinalizeError(f"{field} must contain {int(expected_players)} player rows, got {len(value)}")
    out: list[list[float | int]] = []
    for player_idx, row in enumerate(value):
        if not isinstance(row, list):
            raise FridaFinalizeError(f"{field}[{player_idx}] must be a list")
        if len(row) != 5:
            raise FridaFinalizeError(f"{field}[{player_idx}] must have 5 fields")
        out.append(
            [
                _as_float(row[0], field=f"{field}[{player_idx}][0]"),
                _as_float(row[1], field=f"{field}[{player_idx}][1]"),
                _as_float(row[2], field=f"{field}[{player_idx}][2]"),
                _as_float(row[3], field=f"{field}[{player_idx}][3]"),
                _as_int(row[4], field=f"{field}[{player_idx}][4]"),
            ],
        )
    return out


def _replay_status_from_checkpoint(checkpoint_obj: object) -> ReplayStatusSnapshot:
    if not isinstance(checkpoint_obj, dict):
        return ReplayStatusSnapshot()
    checkpoint = _as_dict(checkpoint_obj, field="tick.channels.checkpoint")
    status_obj = checkpoint.get("status")
    if not isinstance(status_obj, dict):
        return ReplayStatusSnapshot()
    status = _as_dict(status_obj, field="tick.channels.checkpoint.status")
    quest_unlock_index = _as_int_default(status.get("quest_unlock_index"), default=0)
    quest_unlock_index_full = _as_int_default(status.get("quest_unlock_index_full"), default=0)
    usage_obj = status.get("weapon_usage_counts")
    usage_list = usage_obj if isinstance(usage_obj, list) else []
    counts: list[int] = []
    for item in usage_list[: int(WEAPON_USAGE_COUNT)]:
        counts.append(int(_as_int_default(item, default=0)))
    while len(counts) < int(WEAPON_USAGE_COUNT):
        counts.append(0)
    return ReplayStatusSnapshot(
        quest_unlock_index=int(quest_unlock_index),
        quest_unlock_index_full=int(quest_unlock_index_full),
        weapon_usage_counts=tuple(int(value) for value in counts),
    )


def _canonicalize_event_channels(
    *,
    run: _OpenRun,
    channels: dict[str, object],
    field: str,
) -> None:
    checkpoint_obj = channels.get("checkpoint")
    if not isinstance(checkpoint_obj, dict):
        channels["event_heads"] = []
        channels["event_summary"] = {
            "hit_count": 0,
            "pickup_count": 0,
            "sfx_count": 0,
            "sfx_head": [],
        }
        channels["perk_snapshot"] = {
            "pending_count": 0,
            "choices_dirty": True,
            "choices": [],
            "player_nonzero_counts": [],
        }
        channels["micro_traces"] = []
        run.previous_entity_samples = None
        return

    checkpoint = _as_dict(checkpoint_obj, field=f"{field}.checkpoint")
    try:
        checkpoint_struct = msgspec.convert(checkpoint, type=ReplayCheckpoint)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise FridaFinalizeError(f"{field}.checkpoint is not a valid ReplayCheckpoint payload") from exc

    entity_obj = channels.get("entity_samples")
    current_samples = _as_dict(entity_obj, field=f"{field}.entity_samples") if isinstance(entity_obj, dict) else None
    channels["event_heads"] = _event_heads_from_checkpoint(checkpoint_struct)
    channels["event_summary"] = checkpoint_struct.events
    channels["perk_snapshot"] = checkpoint_struct.perk
    try:
        channels["micro_traces"] = _micro_traces_from_entities(
            previous_samples=run.previous_entity_samples,
            current_samples=current_samples,
        )
    except (TypeError, ValueError):
        channels["micro_traces"] = []
        run.previous_entity_samples = None
        return
    run.previous_entity_samples = None if current_samples is None else dict(current_samples)


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
    raw_fingerprint: dict[str, object],
    session_meta: dict[str, object],
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
    if len(run.replay_dt_ms_i32) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_dt_ms_i32 count {len(run.replay_dt_ms_i32)} "
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
    replay_path = Path(out_path).with_suffix(".crd")
    is_quest_run = (
        int(run.mode_id) == int(_GAME_MODE_QUESTS)
        and int(run.quest_stage_major) > 0
        and int(run.quest_stage_minor) > 0
    )
    replay_header = ReplayHeader(
        game_mode_id=int(run.mode_id),
        seed=int(run.replay_seed),
        quest_level=(
            f"{int(run.quest_stage_major)}.{int(run.quest_stage_minor)}" if is_quest_run else ""
        ),
        bootstrap_kind=str(run.replay_bootstrap_kind),
        bootstrap_seed=int(run.replay_bootstrap_seed),
        player_count=int(run.replay_player_count),
        status=run.replay_status,
    )
    dump_replay_file(
        replay_path,
        Replay(
            header=replay_header,
            inputs=list(run.replay_inputs),
            dt_ms_i32=list(run.replay_dt_ms_i32),
            events=[],
        ),
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
                    seed_obj = row.get("seed")
                    if seed_obj is None:
                        raise FridaFinalizeError(
                            f"{raw_path}.lines[{line_no}].seed is null; update gameplay_diff_capture.js "
                            "to emit a concrete run_start seed and recapture",
                        )
                    seed = _as_int(seed_obj, field=f"{raw_path}.lines[{line_no}].seed")
                    seed_source_obj = row.get("seed_source")
                    seed_source = "unknown"
                    if seed_source_obj is not None:
                        if not isinstance(seed_source_obj, str):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].seed_source must be a string")
                        seed_source = str(seed_source_obj)
                    bootstrap_kind = _as_bootstrap_kind(
                        row.get("bootstrap_kind", "none"),
                        field=f"{raw_path}.lines[{line_no}].bootstrap_kind",
                    )
                    bootstrap_seed = _as_int(
                        row.get("bootstrap_seed", 0),
                        field=f"{raw_path}.lines[{line_no}].bootstrap_seed",
                    )
                    if int(mode_id) in _TERRAIN_BOOTSTRAP_MODES:
                        if str(bootstrap_kind) != "terrain_v1":
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] mode_id={mode_id} requires "
                                "bootstrap_kind='terrain_v1'; recapture with updated gameplay_diff_capture.js",
                            )
                    else:
                        bootstrap_kind = "none"
                    if int(bootstrap_seed) < 0:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].bootstrap_seed must be >= 0")
                    player_count = _as_int(row.get("player_count"), field=f"{raw_path}.lines[{line_no}].player_count")
                    if int(player_count) <= 0:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].player_count must be positive")
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
                        replay_seed=int(seed),
                        replay_bootstrap_kind=str(bootstrap_kind),
                        replay_bootstrap_seed=int(bootstrap_seed),
                        replay_player_count=int(player_count),
                        temp_path=spool_path,
                        stream=spool_path.open("wb"),
                        replay_seed_source=str(seed_source),
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
                    if dt_ms_i32 is None:
                        raise FridaFinalizeError(
                            f"{raw_path}.lines[{line_no}].dt_ms_i32 must be present for replay reconstruction",
                        )
                    if int(dt_ms_i32) <= 0:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].dt_ms_i32 must be > 0")
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
                    replay_inputs = _as_replay_tick_inputs(
                        row.get("replay_inputs"),
                        expected_players=int(active_run.replay_player_count),
                        field=f"{raw_path}.lines[{line_no}].replay_inputs",
                    )
                    _validate_checkpoint_channel(
                        channels=channels,
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    _rebase_checkpoint_tick_index(
                        channels=channels,
                        local_tick=int(active_run.next_local_tick),
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    _canonicalize_checkpoint_creature_count(
                        channels=channels,
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    _canonicalize_checkpoint_events_and_deaths(
                        channels=channels,
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    _validate_first_tick_elapsed_for_replay(
                        run=active_run,
                        channels=channels,
                        dt_ms_i32=int(dt_ms_i32),
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    active_run.replay_status = _replay_status_from_checkpoint(channels.get("checkpoint"))
                    active_run.replay_inputs.append(list(replay_inputs))
                    active_run.replay_dt_ms_i32.append(int(dt_ms_i32))
                    _normalize_entity_samples(run=active_run, channels=channels)
                    _canonicalize_event_channels(
                        run=active_run,
                        channels=channels,
                        field=f"{raw_path}.lines[{line_no}].channels",
                    )
                    tick = TickRecord(
                        tick_index=int(active_run.next_local_tick),
                        elapsed_ms=int(elapsed_ms),
                        dt_ms_i32=int(dt_ms_i32),
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
