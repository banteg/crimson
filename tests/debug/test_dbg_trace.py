from __future__ import annotations

import re
import struct
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import msgspec
import pytest

import crimson.dbg.trace as dbg_trace
from crimson.dbg.canonical_channels import (
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    ReplayInputSample,
    ReplayStepSnapshot,
    RngStreamRow,
    SecondaryProjectileEntitySample,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    SnapshotVec2,
    SnapshotWeapon,
    TimingSampleRow,
    entity_uid,
)
from crimson.dbg.health import summarize_trace_health
from crimson.dbg.schema import (
    CHUNK_KIND_FOOTER,
    CHUNK_KIND_META,
    CHUNK_KIND_TICK,
    DEFAULT_CHUNK_FLAGS,
    TRACE_FORMAT_VERSION,
    TRACE_MAGIC,
    TRACE_SCHEMA_VERSION,
    TRAILER_MAGIC,
    ReplayTickChannels,
    TickBlock,
    TickRecord,
    TraceFooter,
    TraceMeta,
    TraceProducer,
    TraceSource,
    TraceTickRange,
)
from crimson.dbg.trace import TraceError, TraceReader, write_trace
from crimson.math_parity import f32
from crimson.persistence.save_status import GameStatusData
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayCheckpointVec2,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from crimson.sim.input_providers import GameFrameRngAdvanceOperation
from crimson.weapons import WeaponId


def _meta(
    *,
    start_tick: int = 0,
    end_tick: int = 2,
    tick_count: int = 3,
    trace_format_version: int = TRACE_FORMAT_VERSION,
    trace_schema_version: int = TRACE_SCHEMA_VERSION,
) -> TraceMeta:
    return TraceMeta(
        trace_format_version=int(trace_format_version),
        trace_schema_version=int(trace_schema_version),
        created_utc="2026-02-24T00:00:00+00:00",
        producer=TraceProducer(impl="python", impl_version="test", platform="darwin", arch="x86_64"),
        source=TraceSource(
            path="unit-test.crd",
            sha256="0" * 64,
            size=1,
            mtime_ns=1,
            kind="replay",
            replay_sha256="0" * 64,
            tick_rate=60,
            seed=1,
            mode_id=1,
            player_count=1,
            quest_level=None,
            run_id=None,
            quest_stage_major=None,
            quest_stage_minor=None,
            global_tick_first=None,
            global_tick_last=None,
            run_start_seed_source=None,
        ),
        tick_range=TraceTickRange(start_tick=int(start_tick), end_tick=int(end_tick), tick_count=int(tick_count)),
        status=GameStatusData(),
    )


def _channels(*, tick_index: int, elapsed_ms: int, score_xp: int) -> ReplayTickChannels:
    return ReplayTickChannels(
        replay_step=ReplayStepSnapshot(
            dt=float(f32(0.016)),
            inputs=[ReplayInputSample(move_x=0.0, move_y=0.0, aim_x=512.0, aim_y=512.0, flags=0)],
            prelude=[],
            postlude=[],
            commands=[],
        ),
        checkpoint=ReplayCheckpoint(
            tick_index=int(tick_index),
            rng_state=0,
            elapsed_ms=int(elapsed_ms),
            score_xp=int(score_xp),
            kills=0,
            creature_count=0,
            perk_pending=0,
            players=[
                ReplayPlayerCheckpoint(
                    pos=ReplayCheckpointVec2(256.0, 256.0),
                    health=100.0,
                    weapon_id=WeaponId.PISTOL,
                    ammo=10.0,
                    experience=int(score_xp),
                    level=1,
                ),
            ],
            bonus_timers={},
            deaths=[],
            perk=ReplayPerkSnapshot(
                pending_count=0,
                choices_dirty=False,
                choices=[0] * 7,
                player_nonzero_counts=[[]],
            ),
            events=ReplayEventSummary(
                hit_count=0,
                pickup_count=0,
                sfx_count=0,
                sfx_head=[],
                hit_head=[],
            ),
            tutorial=None,
            typo=None,
        ),
        sim_state=SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=1,
                quest_stage_major=-1,
                quest_stage_minor=-1,
                perk_pending_count=0,
                perk_choices_dirty=False,
                bonus_timers=SnapshotBonusTimers(
                    weapon_power_up_ms=0,
                    reflex_boost_ms=0,
                    energizer_ms=0,
                    double_experience_ms=0,
                    freeze_ms=0,
                ),
            ),
            players=[
                SnapshotPlayer(
                    index=0,
                    pos=SnapshotVec2(x=256.0, y=256.0),
                    heading=0.0,
                    move_speed=0.0,
                    move_phase=0.0,
                    aim=SnapshotVec2(x=512.0, y=512.0),
                    aim_heading=0.0,
                    health=100.0,
                    weapon=SnapshotWeapon(
                        weapon_id=int(WeaponId.PISTOL),
                        ammo=10.0,
                        clip_size=10,
                        reload_active=False,
                        reload_timer=0.0,
                        reload_timer_max=1.0,
                        shot_cooldown=0.0,
                    ),
                    experience=int(score_xp),
                    level=1,
                ),
            ],
        ),
        entity_samples=EntitySamplesSnapshot(
            creatures=[],
            projectiles=[
                ProjectileEntitySample(
                    uid=entity_uid(pool_kind="projectile", index=2, generation=1),
                    generation=1,
                    pool_kind="projectile",
                    index=2,
                    active=True,
                    type_id=4,
                    angle=0.25,
                    pos=SnapshotVec2(x=1.0, y=2.0),
                    vel=SnapshotVec2(x=3.0, y=4.0),
                    life_timer=0.5,
                    speed_scale=1.0,
                    damage_pool=8.0,
                    hit_radius=1.5,
                    travel_budget=9.0,
                    owner_id=-100,
                ),
            ],
            secondary_projectiles=[
                SecondaryProjectileEntitySample(
                    uid=entity_uid(pool_kind="secondary_projectile", index=5, generation=1),
                    generation=1,
                    pool_kind="secondary_projectile",
                    index=5,
                    active=True,
                    type_id=7,
                    angle=0.5,
                    pos=SnapshotVec2(x=5.0, y=6.0),
                    vel=SnapshotVec2(x=7.0, y=8.0),
                    speed=3.0,
                    trail_timer=0.25,
                    owner_id=13,
                    target_id=99,
                ),
            ],
            bonuses=[],
        ),
        rng_stream=[
            RngStreamRow(
                tick_call_index=1,
                value_15=28052,
                state_before_u32=2427270273,
                state_after_u32=3985917248,
                caller=0x004281A2,
            ),
        ],
        timing_samples=[
            TimingSampleRow(
                tick_index=int(tick_index),
                gameplay_frame=int(tick_index),
                phase="gpur_enter",
                write_kind="snapshot",
                frame_dt_f32=float(f32(0.016)),
                frame_dt_ms_i32=16,
                frame_dt_ms_f32=16.0,
                time_scale_active_entry=False,
                time_scale_active_current=False,
                time_scale_factor=1.0,
                bonus_reflex_boost_timer=0.0,
                mode_fn="gameplay_update_and_render",
                player_index=None,
            ),
        ],
    )


def _row(*, tick_index: int, elapsed_ms: int, score_xp: int) -> TickRecord:
    return TickRecord(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        dt_ms_i32=16,
        mode_id=1,
        channels=_channels(tick_index=int(tick_index), elapsed_ms=int(elapsed_ms), score_xp=int(score_xp)),
    )


def _write_unchecked_trace(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: list[TickRecord],
    footer_tick_count: int | None = None,
    footer_first_tick: int | None = None,
    footer_last_tick: int | None = None,
) -> None:
    assert ticks
    with path.open("wb") as handle:
        handle.write(TRACE_MAGIC)
        handle.write(struct.pack("<I", TRACE_FORMAT_VERSION))
        dbg_trace._write_chunk(
            handle,
            kind=CHUNK_KIND_META,
            start_tick=-1,
            end_tick=-1,
            payload=msgspec.msgpack.encode(meta),
        )
        block = TickBlock(
            start_tick=int(ticks[0].tick_index),
            end_tick=int(ticks[-1].tick_index),
            ticks=ticks,
        )
        block_index = dbg_trace._write_chunk(
            handle,
            kind=CHUNK_KIND_TICK,
            start_tick=int(block.start_tick),
            end_tick=int(block.end_tick),
            payload=msgspec.msgpack.encode(block),
        )
        footer = TraceFooter(
            tick_blocks=[block_index],
            tick_count=len(ticks) if footer_tick_count is None else int(footer_tick_count),
            first_tick=int(ticks[0].tick_index) if footer_first_tick is None else int(footer_first_tick),
            last_tick=int(ticks[-1].tick_index) if footer_last_tick is None else int(footer_last_tick),
        )
        footer_index = dbg_trace._write_chunk(
            handle,
            kind=CHUNK_KIND_FOOTER,
            start_tick=-1,
            end_tick=-1,
            payload=msgspec.msgpack.encode(footer),
        )
        handle.write(struct.pack("<8sQ", TRAILER_MAGIC, footer_index.file_offset))


def _write_raw_trace(
    path: Path,
    *,
    meta_raw: Any,
    block_raw: Any,
    mutate_footer: Callable[[Any], object] | None = None,
) -> None:
    with path.open("wb") as handle:
        handle.write(TRACE_MAGIC)
        handle.write(struct.pack("<I", TRACE_FORMAT_VERSION))
        dbg_trace._write_chunk(
            handle,
            kind=CHUNK_KIND_META,
            start_tick=-1,
            end_tick=-1,
            payload=msgspec.msgpack.encode(meta_raw),
        )
        block_index = dbg_trace._write_chunk(
            handle,
            kind=CHUNK_KIND_TICK,
            start_tick=int(block_raw["start_tick"]),
            end_tick=int(block_raw["end_tick"]),
            payload=msgspec.msgpack.encode(block_raw),
        )
        footer_raw = msgspec.to_builtins(
            TraceFooter(
                tick_blocks=[block_index],
                tick_count=len(block_raw.get("ticks", [None])),
                first_tick=int(block_raw["start_tick"]),
                last_tick=int(block_raw["end_tick"]),
            ),
        )
        if mutate_footer is not None:
            mutate_footer(footer_raw)
        footer_index = dbg_trace._write_chunk(
            handle,
            kind=CHUNK_KIND_FOOTER,
            start_tick=-1,
            end_tick=-1,
            payload=msgspec.msgpack.encode(footer_raw),
        )
        handle.write(struct.pack("<8sQ", TRAILER_MAGIC, footer_index.file_offset))


def _valid_raw_trace_parts() -> tuple[Any, Any]:
    row = _row(tick_index=0, elapsed_ms=0, score_xp=0)
    return (
        msgspec.msgpack.decode(msgspec.msgpack.encode(_meta(start_tick=0, end_tick=0, tick_count=1))),
        msgspec.msgpack.decode(msgspec.msgpack.encode(TickBlock(start_tick=0, end_tick=0, ticks=[row]))),
    )


def _set_wire_path(root: Any, path: tuple[str | int, ...], value: object) -> None:
    current = root
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value


def _health_issues(health: Mapping[str, object]) -> list[str]:
    value = health.get("issues")
    assert isinstance(value, list)
    return [str(issue) for issue in value]


def test_trace_roundtrip_random_access(tmp_path: Path) -> None:
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=5),
        _row(tick_index=2, elapsed_ms=33, score_xp=9),
    ]
    out_path = tmp_path / "trace.cdt"
    summary = write_trace(out_path, meta=_meta(), ticks=rows, chunk_ticks=2)

    assert summary.footer.tick_count == 3
    assert out_path.exists()

    with TraceReader(out_path) as reader:
        assert reader.meta.trace_format_version == TRACE_FORMAT_VERSION
        tick1 = reader.tick(1)
        assert tick1 is not None
        assert tick1.elapsed_ms == 16
        assert tick1.channels.rng_stream[0].caller == 0x004281A2
        window = list(reader.iter_ticks(tick_start=1, tick_end=2))
        assert [row.tick_index for row in window] == [1, 2]


def test_trace_v2_uses_raw_msgpack_chunks(tmp_path: Path) -> None:
    out_path = tmp_path / "trace.cdt"
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=5),
        _row(tick_index=2, elapsed_ms=33, score_xp=9),
    ]
    write_trace(out_path, meta=_meta(), ticks=rows, chunk_ticks=2)

    raw = out_path.read_bytes()
    assert raw.startswith(TRACE_MAGIC + struct.pack("<I", TRACE_FORMAT_VERSION))
    chunk_offset = len(TRACE_MAGIC) + struct.calcsize("<I")
    kind, _start, _end, flags, payload_len, raw_len, _checksum = struct.unpack_from(
        "<4siiIIIQ",
        raw,
        chunk_offset,
    )
    assert kind == b"META"
    assert flags == DEFAULT_CHUNK_FLAGS
    assert payload_len == raw_len


def test_trace_reader_rejects_unindexed_bytes_before_trailer(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_extra_before_trailer.cdt"
    write_trace(
        out_path,
        meta=_meta(start_tick=0, end_tick=0, tick_count=1),
        ticks=[_row(tick_index=0, elapsed_ms=0, score_xp=0)],
    )
    raw = out_path.read_bytes()
    trailer_size = struct.calcsize("<8sQ")
    out_path.write_bytes(raw[:-trailer_size] + b"extra" + raw[-trailer_size:])

    with pytest.raises(TraceError, match="footer chunk must immediately precede the trailer"):
        TraceReader(out_path)


def test_trace_reader_rejects_unindexed_bytes_before_footer(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_extra_before_footer.cdt"
    write_trace(
        out_path,
        meta=_meta(start_tick=0, end_tick=0, tick_count=1),
        ticks=[_row(tick_index=0, elapsed_ms=0, score_xp=0)],
    )
    raw = out_path.read_bytes()
    trailer_struct = struct.Struct("<8sQ")
    trailer_magic, footer_offset = trailer_struct.unpack(raw[-trailer_struct.size :])
    shifted_footer = int(footer_offset) + 1
    out_path.write_bytes(
        raw[:footer_offset]
        + b"x"
        + raw[footer_offset : -trailer_struct.size]
        + trailer_struct.pack(trailer_magic, shifted_footer),
    )

    with pytest.raises(TraceError, match="unindexed gap before the footer"):
        TraceReader(out_path)


def test_trace_reader_rejects_footer_index_that_disagrees_with_chunk(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_bad_index.cdt"
    rows = [_row(tick_index=0, elapsed_ms=0, score_xp=0)]
    write_trace(out_path, meta=_meta(start_tick=0, end_tick=0, tick_count=1), ticks=rows)

    with TraceReader(out_path) as reader:
        entry = reader.footer.tick_blocks[0]
        bad_entry = msgspec.structs.replace(entry, checksum=int(entry.checksum) ^ 1)
        with pytest.raises(TraceError, match="footer checksum does not match"):
            reader._load_block(bad_entry)


def test_trace_meta_rejects_unknown_fields() -> None:
    payload = msgspec.msgpack.encode(
        {
            "trace_format_version": TRACE_FORMAT_VERSION,
            "trace_schema_version": TRACE_SCHEMA_VERSION,
            "created_utc": "2026-02-24T00:00:00+00:00",
            "producer": {"impl": "python", "impl_version": "", "platform": "darwin", "arch": "x86_64"},
            "source": {"kind": "unit_test", "sha256": "0" * 64},
            "tick_range": {"start_tick": 0, "end_tick": 0, "tick_count": 1},
            "future_field": {"nested": True},
        },
    )
    with pytest.raises(msgspec.ValidationError, match="future_field"):
        msgspec.msgpack.decode(payload, type=TraceMeta)


def test_tick_record_rejects_unknown_fields() -> None:
    payload = msgspec.msgpack.encode(
        {
            "tick_index": 7,
            "elapsed_ms": 112,
            "dt_ms_i32": 16,
            "mode_id": 2,
            "channels": msgspec.to_builtins(_channels(tick_index=7, elapsed_ms=112, score_xp=42)),
            "future_tick_field": "ignored",
        },
    )
    with pytest.raises(msgspec.ValidationError, match="future_tick_field"):
        msgspec.msgpack.decode(payload, type=TickRecord)


@pytest.mark.parametrize(
    ("field", "path"),
    [
        ("replay_step.dt", ("ticks", 0, "channels", "replay_step", "dt")),
        (
            "checkpoint.players[0].health",
            ("ticks", 0, "channels", "checkpoint", "players", 0, "health"),
        ),
        (
            "sim_state.players[0].heading",
            ("ticks", 0, "channels", "sim_state", "players", 0, "heading"),
        ),
        (
            "entity_samples.projectiles[0].angle",
            ("ticks", 0, "channels", "entity_samples", "projectiles", 0, "angle"),
        ),
        (
            "timing_samples[0].frame_dt_f32",
            ("ticks", 0, "channels", "timing_samples", 0, "frame_dt_f32"),
        ),
    ],
)
def test_trace_reader_rejects_integer_tokens_for_wire_f32_fields(
    tmp_path: Path,
    field: str,
    path: tuple[str | int, ...],
) -> None:
    meta_raw, block_raw = _valid_raw_trace_parts()
    _set_wire_path(block_raw, path, 0)
    out_path = tmp_path / f"integer_{field}.cdt"
    _write_raw_trace(out_path, meta_raw=meta_raw, block_raw=block_raw)

    with pytest.raises(TraceError, match=rf"{re.escape(field)} must be encoded as a msgpack float"):
        with TraceReader(out_path) as reader:
            reader.all_ticks()

    health = summarize_trace_health(out_path)
    assert health["ok_for_parity_analysis"] is False
    assert any(f"{field} must be encoded as a msgpack float" in issue for issue in _health_issues(health))


def test_trace_reader_accepts_current_tagged_prelude_wire_map(tmp_path: Path) -> None:
    meta_raw, block_raw = _valid_raw_trace_parts()
    _set_wire_path(
        block_raw,
        ("ticks", 0, "channels", "replay_step", "prelude"),
        [{"type": "game_frame_rng_advance", "frames": 1}],
    )
    out_path = tmp_path / "tagged_prelude.cdt"
    _write_raw_trace(out_path, meta_raw=meta_raw, block_raw=block_raw)

    with TraceReader(out_path) as reader:
        operation = reader.all_ticks()[0].channels.replay_step.prelude[0]
        assert isinstance(operation, GameFrameRngAdvanceOperation)
        assert operation.frames == 1


@pytest.mark.parametrize(
    ("name", "mutate_meta", "mutate_block", "mutate_footer", "error"),
    [
        (
            "meta_missing_nullable",
            lambda raw: raw["source"].pop("run_id"),
            None,
            None,
            r"meta\.source is missing field\(s\): run_id",
        ),
        (
            "meta_unknown",
            lambda raw: raw.__setitem__("future", None),
            None,
            None,
            r"meta has unknown field\(s\): 'future'",
        ),
        (
            "tick_block_missing",
            None,
            lambda raw: raw.pop("ticks"),
            None,
            r"tick_block is missing field\(s\): ticks",
        ),
        (
            "tick_nested_unknown",
            None,
            lambda raw: raw["ticks"][0]["channels"].__setitem__("future", []),
            None,
            r"tick_block\.ticks\[0\]\.channels has unknown field\(s\): 'future'",
        ),
        (
            "tick_missing_nullable",
            None,
            lambda raw: raw["ticks"][0]["channels"]["timing_samples"][0].pop("player_index"),
            None,
            r"timing_samples\[0\] is missing field\(s\): player_index",
        ),
        (
            "prelude_missing_field",
            None,
            lambda raw: raw["ticks"][0]["channels"]["replay_step"].__setitem__(
                "prelude",
                [{"type": "game_frame_rng_advance"}],
            ),
            None,
            r"replay_step\.prelude\[0\] is missing field\(s\): frames",
        ),
        (
            "command_unknown_tag",
            None,
            lambda raw: raw["ticks"][0]["channels"]["replay_step"].__setitem__(
                "commands",
                [{"type": "future", "player_index": 0}],
            ),
            None,
            r"replay_step\.commands\[0\]\.type has unsupported tag 'future'",
        ),
        (
            "footer_missing",
            None,
            None,
            lambda raw: raw.pop("last_tick"),
            r"footer is missing field\(s\): last_tick",
        ),
        (
            "footer_unknown",
            None,
            None,
            lambda raw: raw.__setitem__("future", 0),
            r"footer has unknown field\(s\): 'future'",
        ),
    ],
)
def test_trace_reader_requires_exact_current_wire_maps(
    tmp_path: Path,
    name: str,
    mutate_meta: Callable[[Any], object] | None,
    mutate_block: Callable[[Any], object] | None,
    mutate_footer: Callable[[Any], object] | None,
    error: str,
) -> None:
    meta_raw, block_raw = _valid_raw_trace_parts()
    if mutate_meta is not None:
        mutate_meta(meta_raw)
    if mutate_block is not None:
        mutate_block(block_raw)
    out_path = tmp_path / f"{name}.cdt"
    _write_raw_trace(
        out_path,
        meta_raw=meta_raw,
        block_raw=block_raw,
        mutate_footer=mutate_footer,
    )

    with pytest.raises(TraceError, match=error):
        with TraceReader(out_path) as reader:
            reader.all_ticks()


@pytest.mark.parametrize(
    "meta",
    [
        _meta(trace_format_version=1),
        _meta(trace_schema_version=12),
        _meta(trace_schema_version=99),
    ],
)
def test_write_trace_rejects_noncurrent_contract(tmp_path: Path, meta: TraceMeta) -> None:
    out_path = tmp_path / "trace_bad_contract.cdt"
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=5),
        _row(tick_index=2, elapsed_ms=33, score_xp=9),
    ]

    with pytest.raises(TraceError, match="unsupported trace (?:format|schema) version in metadata"):
        write_trace(out_path, meta=meta, ticks=rows, chunk_ticks=1)


def test_write_trace_rejects_empty_ticks(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_empty.cdt"
    with pytest.raises(TraceError, match="trace must contain at least one tick"):
        write_trace(out_path, meta=_meta(), ticks=[], chunk_ticks=1)


@pytest.mark.parametrize(
    "ticks",
    [
        [
            _row(tick_index=0, elapsed_ms=0, score_xp=0),
            _row(tick_index=0, elapsed_ms=16, score_xp=0),
        ],
        [
            _row(tick_index=1, elapsed_ms=16, score_xp=0),
            _row(tick_index=0, elapsed_ms=0, score_xp=0),
        ],
        [
            _row(tick_index=0, elapsed_ms=0, score_xp=0),
            _row(tick_index=2, elapsed_ms=32, score_xp=0),
        ],
    ],
)
def test_write_trace_rejects_noncontiguous_ticks(tmp_path: Path, ticks: list[TickRecord]) -> None:
    meta = _meta(start_tick=int(ticks[0].tick_index), end_tick=int(ticks[-1].tick_index), tick_count=len(ticks))
    with pytest.raises(TraceError, match="tick rows must be contiguous"):
        write_trace(tmp_path / "invalid.cdt", meta=meta, ticks=ticks, chunk_ticks=2)


def test_write_trace_rejects_meta_tick_range_mismatch(tmp_path: Path) -> None:
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=0),
    ]
    with pytest.raises(TraceError, match="metadata tick_range does not match written ticks"):
        write_trace(tmp_path / "invalid.cdt", meta=_meta(), ticks=rows, chunk_ticks=2)


def test_write_trace_rejects_tick_identity_that_disagrees_with_metadata(tmp_path: Path) -> None:
    row = _row(tick_index=0, elapsed_ms=0, score_xp=0)
    mode_meta = msgspec.structs.replace(
        _meta(start_tick=0, end_tick=0, tick_count=1),
        source=msgspec.structs.replace(_meta().source, mode_id=2),
    )
    with pytest.raises(TraceError, match="source.mode_id"):
        write_trace(tmp_path / "bad_mode.cdt", meta=mode_meta, ticks=[row])

    player_meta = msgspec.structs.replace(
        _meta(start_tick=0, end_tick=0, tick_count=1),
        source=msgspec.structs.replace(_meta().source, player_count=2),
    )
    with pytest.raises(TraceError, match="source.player_count"):
        write_trace(tmp_path / "bad_players.cdt", meta=player_meta, ticks=[row])


def test_write_trace_rejects_noncanonical_player_slots(tmp_path: Path) -> None:
    row = _row(tick_index=0, elapsed_ms=0, score_xp=0)
    player = msgspec.structs.replace(row.channels.sim_state.players[0], index=7)
    row = msgspec.structs.replace(
        row,
        channels=msgspec.structs.replace(
            row.channels,
            sim_state=msgspec.structs.replace(row.channels.sim_state, players=[player]),
        ),
    )

    with pytest.raises(TraceError, match="contiguous slots"):
        write_trace(
            tmp_path / "bad_slots.cdt",
            meta=_meta(start_tick=0, end_tick=0, tick_count=1),
            ticks=[row],
        )


def test_write_trace_rejects_non_f32_state_values(tmp_path: Path) -> None:
    row = _row(tick_index=0, elapsed_ms=0, score_xp=0)
    player = msgspec.structs.replace(
        row.channels.sim_state.players[0],
        heading=1.0000000000000002,
    )
    row = msgspec.structs.replace(
        row,
        channels=msgspec.structs.replace(
            row.channels,
            sim_state=msgspec.structs.replace(row.channels.sim_state, players=[player]),
        ),
    )

    with pytest.raises(TraceError, match="heading must be canonical f32"):
        write_trace(
            tmp_path / "bad_float.cdt",
            meta=_meta(start_tick=0, end_tick=0, tick_count=1),
            ticks=[row],
        )


def test_write_trace_rejects_producer_specific_checkpoint_heads(tmp_path: Path) -> None:
    row = _row(tick_index=0, elapsed_ms=0, score_xp=0)
    events = msgspec.structs.replace(row.channels.checkpoint.events, sfx_head=["native-only"])
    checkpoint = msgspec.structs.replace(row.channels.checkpoint, events=events)
    row = msgspec.structs.replace(
        row,
        channels=msgspec.structs.replace(row.channels, checkpoint=checkpoint),
    )

    with pytest.raises(TraceError, match="sfx_head must be empty"):
        write_trace(
            tmp_path / "bad_checkpoint_heads.cdt",
            meta=_meta(start_tick=0, end_tick=0, tick_count=1),
            ticks=[row],
        )


def test_trace_health_reports_exact_tick_spans_and_gaps(tmp_path: Path) -> None:
    tick_indices = [0, 1, 4, 5, 9]
    rows = [_row(tick_index=tick, elapsed_ms=tick * 16, score_xp=0) for tick in tick_indices]
    out_path = tmp_path / "gapped.cdt"
    _write_unchecked_trace(
        out_path,
        meta=_meta(start_tick=0, end_tick=9, tick_count=len(rows)),
        ticks=rows,
    )

    health = summarize_trace_health(out_path)

    assert health["ok_for_parity_analysis"] is False
    assert health["tick_spans"] == [
        {"start_tick": 0, "end_tick": 1, "tick_count": 2},
        {"start_tick": 4, "end_tick": 5, "tick_count": 2},
        {"start_tick": 9, "end_tick": 9, "tick_count": 1},
    ]
    assert health["tick_gaps"] == [
        {"start_tick": 2, "end_tick": 3, "tick_count": 2},
        {"start_tick": 6, "end_tick": 8, "tick_count": 3},
    ]
    assert "tick gap 2..3" in _health_issues(health)
    assert "tick gap 6..8" in _health_issues(health)


@pytest.mark.parametrize(
    ("ticks", "expected_issue"),
    [
        (
            [
                _row(tick_index=0, elapsed_ms=0, score_xp=0),
                _row(tick_index=0, elapsed_ms=16, score_xp=0),
            ],
            "duplicate tick_index 0",
        ),
        (
            [
                _row(tick_index=0, elapsed_ms=0, score_xp=0),
                _row(tick_index=2, elapsed_ms=32, score_xp=0),
                _row(tick_index=1, elapsed_ms=16, score_xp=0),
            ],
            "out-of-order tick_index 1 after 2",
        ),
    ],
)
def test_trace_health_rejects_duplicate_or_out_of_order_ticks(
    tmp_path: Path,
    ticks: list[TickRecord],
    expected_issue: str,
) -> None:
    out_path = tmp_path / "invalid_order.cdt"
    _write_unchecked_trace(
        out_path,
        meta=_meta(
            start_tick=int(ticks[0].tick_index),
            end_tick=int(ticks[-1].tick_index),
            tick_count=len(ticks),
        ),
        ticks=ticks,
    )

    health = summarize_trace_health(out_path)
    issues = _health_issues(health)

    assert health["ok_for_parity_analysis"] is False
    assert expected_issue in issues


def test_trace_health_rejects_footer_range_mismatch(tmp_path: Path) -> None:
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=0),
    ]
    out_path = tmp_path / "invalid_ranges.cdt"
    _write_unchecked_trace(
        out_path,
        meta=_meta(start_tick=0, end_tick=1, tick_count=8),
        ticks=rows,
        footer_tick_count=8,
    )

    health = summarize_trace_health(out_path)
    issues = _health_issues(health)

    assert health["ok_for_parity_analysis"] is False
    assert "footer.tick_count=8 does not match decoded tick count 2" in issues
    assert "meta.tick_range.tick_count=8 does not match decoded tick count 2" in issues


def test_trace_health_reports_meta_footer_range_mismatch(tmp_path: Path) -> None:
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=0),
    ]
    out_path = tmp_path / "invalid_meta_range.cdt"
    _write_unchecked_trace(
        out_path,
        meta=_meta(start_tick=0, end_tick=7, tick_count=9),
        ticks=rows,
    )

    health = summarize_trace_health(out_path)
    issues = _health_issues(health)

    assert health["ok_for_parity_analysis"] is False
    assert "meta.tick_range.end_tick=7 does not match last decoded tick 1" in issues
    assert "meta.tick_range.tick_count=9 does not match decoded tick count 2" in issues


def test_trace_health_requires_valid_replay_step_and_timing_per_tick(tmp_path: Path) -> None:
    row0 = _row(tick_index=0, elapsed_ms=0, score_xp=0)
    row0 = msgspec.structs.replace(
        row0,
        channels=msgspec.structs.replace(
            row0.channels,
            replay_step=msgspec.structs.replace(row0.channels.replay_step, inputs=[]),
        ),
    )
    row1 = _row(tick_index=1, elapsed_ms=16, score_xp=0)
    row1 = msgspec.structs.replace(
        row1,
        channels=msgspec.structs.replace(row1.channels, timing_samples=[]),
    )
    out_path = tmp_path / "invalid_evidence.cdt"
    _write_unchecked_trace(
        out_path,
        meta=_meta(start_tick=0, end_tick=1, tick_count=2),
        ticks=[row0, row1],
    )

    health = summarize_trace_health(out_path)
    issues = _health_issues(health)

    assert health["ok_for_parity_analysis"] is False
    assert any("replay_step.inputs must be non-empty" in issue for issue in issues)
    assert any("timing_samples must be non-empty" in issue for issue in issues)
    assert "timing_samples missing for 1 tick(s) in trace window" in issues
