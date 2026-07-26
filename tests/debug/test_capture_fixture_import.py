from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Self

import msgspec
import pytest

from crimson.dbg.frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION
from crimson.dbg.schema import (
    TRACE_FORMAT_VERSION,
    TRACE_SCHEMA_VERSION,
    TraceMeta,
    TraceProducer,
    TraceSource,
    TraceTickRange,
)
from crimson.game_modes import GameMode
from crimson.replay.types import Replay, ReplayHeader, ReplayTick
from scripts import import_capture_fixtures


def _meta(*, replay_sha256: str) -> TraceMeta:
    return TraceMeta(
        trace_format_version=TRACE_FORMAT_VERSION,
        trace_schema_version=TRACE_SCHEMA_VERSION,
        created_utc="2026-07-09T00:00:00+00:00",
        producer=TraceProducer(
            impl="frida_original",
            impl_version=str(FRIDA_CAPTURE_FORMAT_VERSION),
            platform="windows",
            arch="ia32",
        ),
        source=TraceSource(
            path="capture.jsonl",
            sha256="a" * 64,
            size=1,
            mtime_ns=1,
            kind="capture",
            replay_sha256=replay_sha256,
            tick_rate=60,
            seed=1,
            mode_id=int(GameMode.SURVIVAL),
            player_count=1,
            quest_level=None,
            run_id=1,
            quest_stage_major=None,
            quest_stage_minor=None,
            global_tick_first=100,
            global_tick_last=101,
            run_start_seed_source="rng_state_before_bootstrap",
        ),
        tick_range=TraceTickRange(start_tick=0, end_tick=1, tick_count=2),
    )


def _replay() -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1),
        ticks=[
            ReplayTick(dt=0.0, inputs=[[0.0, 0.0, 0.0, 0.0, 0]], prelude=[], postlude=[], commands=[]),
            ReplayTick(dt=0.0, inputs=[[0.0, 0.0, 0.0, 0.0, 0]], prelude=[], postlude=[], commands=[]),
        ],
    )


def _reader_type(meta: TraceMeta, *, decoded_ticks: int = 2) -> type:
    class _Reader:
        def __init__(self, _path: Path) -> None:
            self.meta = meta

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_ticks(self) -> Iterator[object]:
            return iter(object() for _ in range(int(decoded_ticks)))

    return _Reader


def test_capture_fixture_import_preserves_full_contiguous_pair(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capture_dir = tmp_path / "captures"
    fixture_dir = tmp_path / "fixtures"
    capture_dir.mkdir()
    cdt_path = capture_dir / "gameplay_diff_capture.survival.run1.cdt"
    crd_path = cdt_path.with_suffix(".crd")
    cdt_bytes = b"full-current-cdt"
    crd_bytes = b"full-current-crd"
    cdt_path.write_bytes(cdt_bytes)
    crd_path.write_bytes(crd_bytes)
    meta = _meta(replay_sha256=hashlib.sha256(crd_bytes).hexdigest())

    monkeypatch.setattr(import_capture_fixtures, "TraceReader", _reader_type(meta))
    monkeypatch.setattr(import_capture_fixtures, "load_replay_file", lambda _path: _replay())
    monkeypatch.setattr(import_capture_fixtures, "_first_rng_draw", lambda _path: None)

    case = import_capture_fixtures.import_run(cdt_path, fixtures_dir=fixture_dir)

    assert (fixture_dir / cdt_path.name).read_bytes() == cdt_bytes
    assert (fixture_dir / crd_path.name).read_bytes() == crd_bytes
    assert case["trace_tick_range"] == {"start_tick": 0, "end_tick": 1, "tick_count": 2}


def test_capture_fixture_import_rejects_mismatched_replay_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cdt_path = tmp_path / "gameplay_diff_capture.survival.run1.cdt"
    cdt_path.write_bytes(b"current-cdt")
    cdt_path.with_suffix(".crd").write_bytes(b"current-crd")
    meta = _meta(replay_sha256="0" * 64)

    monkeypatch.setattr(import_capture_fixtures, "TraceReader", _reader_type(meta))
    monkeypatch.setattr(import_capture_fixtures, "load_replay_file", lambda _path: _replay())

    with pytest.raises(RuntimeError, match="replay_sha256 does not match"):
        import_capture_fixtures.import_run(cdt_path, fixtures_dir=tmp_path / "fixtures")


def test_capture_fixture_import_requires_full_trace_decode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cdt_path = tmp_path / "gameplay_diff_capture.survival.run1.cdt"
    cdt_path.write_bytes(b"current-cdt")
    crd_path = cdt_path.with_suffix(".crd")
    crd_path.write_bytes(b"current-crd")
    meta = _meta(replay_sha256=hashlib.sha256(crd_path.read_bytes()).hexdigest())

    monkeypatch.setattr(import_capture_fixtures, "TraceReader", _reader_type(meta, decoded_ticks=1))
    monkeypatch.setattr(import_capture_fixtures, "load_replay_file", lambda _path: _replay())

    with pytest.raises(RuntimeError, match="decoded trace tick count does not match metadata"):
        import_capture_fixtures.import_run(cdt_path, fixtures_dir=tmp_path / "fixtures")


def test_capture_fixture_import_requires_current_frida_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cdt_path = tmp_path / "gameplay_diff_capture.survival.run1.cdt"
    cdt_path.write_bytes(b"current-cdt")
    crd_path = cdt_path.with_suffix(".crd")
    crd_path.write_bytes(b"current-crd")
    meta = _meta(replay_sha256=hashlib.sha256(crd_path.read_bytes()).hexdigest())
    meta = msgspec.structs.replace(
        meta,
        producer=msgspec.structs.replace(
            meta.producer,
            impl_version=str(FRIDA_CAPTURE_FORMAT_VERSION - 1),
        ),
    )

    monkeypatch.setattr(import_capture_fixtures, "TraceReader", _reader_type(meta))
    monkeypatch.setattr(import_capture_fixtures, "load_replay_file", lambda _path: _replay())

    with pytest.raises(RuntimeError, match=rf"must use Frida format {FRIDA_CAPTURE_FORMAT_VERSION}"):
        import_capture_fixtures.import_run(cdt_path, fixtures_dir=tmp_path / "fixtures")


def test_capture_fixture_import_requires_replay_aligned_seed_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cdt_path = tmp_path / "gameplay_diff_capture.survival.run1.cdt"
    cdt_path.write_bytes(b"current-cdt")
    crd_path = cdt_path.with_suffix(".crd")
    crd_path.write_bytes(b"current-crd")
    meta = _meta(replay_sha256=hashlib.sha256(crd_path.read_bytes()).hexdigest())
    meta = msgspec.structs.replace(
        meta,
        source=msgspec.structs.replace(meta.source, run_start_seed_source="session_srand_seed"),
    )

    monkeypatch.setattr(import_capture_fixtures, "TraceReader", _reader_type(meta))
    monkeypatch.setattr(import_capture_fixtures, "load_replay_file", lambda _path: _replay())
    monkeypatch.setattr(import_capture_fixtures, "_first_rng_draw", lambda _path: None)

    with pytest.raises(RuntimeError, match="seed source must be 'rng_state_before_bootstrap'"):
        import_capture_fixtures.import_run(cdt_path, fixtures_dir=tmp_path / "fixtures")
