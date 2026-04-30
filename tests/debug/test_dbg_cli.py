from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import msgspec
from typer.testing import CliRunner

import crimson.dbg.diff as dbg_diff
from crimson.cli import app
from crimson.dbg.schema import TickRecord
from crimson.dbg.trace import TraceReader, load_trace, write_trace
from crimson.game_modes import GameMode
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def test_dbg_health_on_recorded_trace(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path)],
    )
    assert record_result.exit_code == 0, record_result.output
    assert trace_path.exists()
    assert "channels=" in record_result.output
    assert "entity_samples" in record_result.output

    health_result = runner.invoke(
        app,
        ["dbg", "health", str(trace_path)],
    )
    assert health_result.exit_code == 0, health_result.output
    assert "parity_analysis_ready=" in health_result.output
    assert "timing_samples_rows=" in health_result.output


def test_dbg_health_flags_empty_timing_rows(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_empty_timing.crd")
    trace_path = tmp_path / "sample_empty_timing.cdt"
    empty_timing_trace = tmp_path / "sample_empty_timing_modified.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path)],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(trace_path)
    for tick in ticks:
        tick.channels = msgspec.structs.replace(tick.channels, timing_samples=[])
    write_trace(empty_timing_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    health_result = runner.invoke(
        app,
        ["dbg", "health", str(empty_timing_trace)],
    )
    assert health_result.exit_code == 1, health_result.output
    assert "issue=timing_samples channel has no rows in trace window" in health_result.output


def test_dbg_record_rejects_removed_profile_option(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--profile", "standard"],
    )

    assert result.exit_code == 2
    assert "No such option" in result.output


def test_dbg_record_rejects_removed_max_ticks_option(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--max-ticks", "2"],
    )

    assert result.exit_code == 2
    assert "No such option" in result.output


def test_dbg_bisect_rejects_removed_out_option(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace)],
    )
    assert record_result.exit_code == 0, record_result.output
    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    _with_score_xp_delta(tick1, delta=1)
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    result = runner.invoke(
        app,
        ["dbg", "bisect", str(golden_trace), str(candidate_trace), "--out", str(tmp_path / "repro.cdt")],
    )

    assert result.exit_code == 2
    assert "No such option" in result.output


def test_dbg_record_forwards_impl_and_prints_warnings(tmp_path: Path, monkeypatch) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    captured: dict[str, object] = {}

    def _fake_record_replay_to_trace(
        *,
        replay_path: Path,
        out_path: Path,
        impl: str,
        chunk_ticks: int,
        warnings_out: list[str],
    ) -> object:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
        captured["impl"] = impl
        captured["chunk_ticks"] = chunk_ticks
        warnings_out.append("warning: zig replay verify exited 1; continuing with emitted trace")
        return SimpleNamespace(
            meta=SimpleNamespace(
                tick_range=SimpleNamespace(start_tick=0, end_tick=1, tick_count=2),
                channels=["checkpoint", "sim_state"],
            ),
        )

    import crimson.dbg.record as dbg_record_mod

    monkeypatch.setattr(dbg_record_mod, "record_replay_to_trace", _fake_record_replay_to_trace)
    result = runner.invoke(
        app,
        [
            "dbg",
            "record",
            str(replay_path),
            "--out",
            str(trace_path),
            "--impl",
            "zig",
            "--chunk-ticks",
            "8",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "warning: zig replay verify exited 1; continuing with emitted trace" in result.output
    assert "trace=" in result.output
    assert "channels=checkpoint,sim_state" in result.output
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == trace_path
    assert captured["impl"] == "zig"
    assert captured["chunk_ticks"] == 8


def _write_replay(path: Path, *, ticks: int = 3) -> Path:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    path.write_bytes(dump_replay(recorder.finish()))
    return path


def _write_replay_with_fire(path: Path, *, ticks: int = 3) -> Path:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick([PlayerInput(aim=Vec2(700.0, 512.0), fire_down=True)])
    path.write_bytes(dump_replay(recorder.finish()))
    return path


def _with_score_xp_delta(row: TickRecord, *, delta: int) -> TickRecord:
    checkpoint = msgspec.structs.replace(
        row.channels.checkpoint,
        score_xp=int(row.channels.checkpoint.score_xp) + int(delta),
    )
    row.channels = msgspec.structs.replace(row.channels, checkpoint=checkpoint)
    return row


def test_dbg_record_emits_required_channels(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path)],
    )
    assert result.exit_code == 0, result.output
    assert "channels=" in result.output
    assert "checkpoint" in result.output
    assert "rng_stream" in result.output
    assert "sim_state" in result.output
    assert "entity_samples" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        assert tick0.channels.checkpoint.tick_index == 0
        assert isinstance(tick0.channels.rng_stream, list)
        assert tick0.channels.sim_state is not None
        assert tick0.channels.entity_samples is not None


def test_dbg_record_uses_canonical_channels(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_full.crd")
    trace_path = tmp_path / "sample_full.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path)],
    )
    assert result.exit_code == 0, result.output
    assert "checkpoint" in result.output
    assert "rng_stream" in result.output
    assert "sim_state" in result.output
    assert "entity_samples" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        assert isinstance(tick0.channels.rng_stream, list)
        assert tick0.channels.sim_state.gameplay.mode_id == int(GameMode.SURVIVAL)
        assert tick0.channels.entity_samples is not None


def test_dbg_diff_and_bisect(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace)],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    _with_score_xp_delta(tick1, delta=1)
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    diff_result = runner.invoke(
        app,
        ["dbg", "diff", str(golden_trace), str(candidate_trace)],
    )
    assert diff_result.exit_code == 1, diff_result.output
    assert "result=diverged" in diff_result.output
    assert "checkpoint_field_mismatch" in diff_result.output

    bisect_result = runner.invoke(
        app,
        ["dbg", "bisect", str(golden_trace), str(candidate_trace)],
    )
    assert bisect_result.exit_code == 0, bisect_result.output
    assert "result=diverged" in bisect_result.output
    assert "first_bad_tick=1" in bisect_result.output
    assert "window=-11..7" in bisect_result.output


def test_dbg_diff_checkpoint_field_changes_report_mismatch(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_hashes.crd")
    golden_trace = tmp_path / "golden_hashes.cdt"
    candidate_trace = tmp_path / "candidate_hashes.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace)],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick0 = next(row for row in ticks if int(row.tick_index) == 0)
    tick0.channels = msgspec.structs.replace(
        tick0.channels,
        checkpoint=msgspec.structs.replace(tick0.channels.checkpoint, score_xp=999999),
    )
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    result = runner.invoke(
        app,
        [
            "dbg",
            "diff",
            str(golden_trace),
            str(candidate_trace),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "result=diverged" in result.output
    assert "checkpoint_field_mismatch" in result.output


def test_dbg_diff_default_policy_requires_canonical_channels(tmp_path: Path) -> None:
    replay_path = _write_replay_with_fire(tmp_path / "sample_optional_channels.crd", ticks=3)
    golden_trace = tmp_path / "golden_optional_channels.cdt"
    candidate_trace = tmp_path / "candidate_optional_channels.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace)],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    meta.channels = [name for name in meta.channels if name != "entity_samples"]
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    result = runner.invoke(
        app,
        ["dbg", "diff", str(golden_trace), str(candidate_trace)],
    )
    assert result.exit_code == 1, result.output
    assert "missing_channel" in result.output


def test_dbg_bisect_scans_once(tmp_path: Path, monkeypatch) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace)],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if row.tick_index == 1)
    _with_score_xp_delta(tick1, delta=1)
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    call_count = 0
    original_first_mismatch = dbg_diff._first_mismatch

    def _counting_first_mismatch(*, pairs, tick_end=None):
        nonlocal call_count
        call_count += 1
        return original_first_mismatch(
            pairs=pairs,
            tick_end=tick_end,
        )

    monkeypatch.setattr(dbg_diff, "_first_mismatch", _counting_first_mismatch)
    report = dbg_diff.bisect_traces(
        expected_trace_path=golden_trace,
        actual_trace_path=candidate_trace,
    )
    assert report.first_bad_tick == 1
    assert report.window_start == -11
    assert report.window_end == 7
    assert call_count == 1


def test_dbg_tick_entity_query_focus(tmp_path: Path) -> None:
    replay_path = _write_replay_with_fire(tmp_path / "capture_like.crd", ticks=2)
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace)],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    _with_score_xp_delta(tick1, delta=1)
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    entity_uid = -1
    entity_pool_kind = ""
    for row in ticks:
        samples = row.channels.entity_samples
        for pool in (
            samples.projectiles,
            samples.creatures,
            samples.secondary_projectiles,
            samples.bonuses,
        ):
            if not pool:
                continue
            first_entity = pool[0]
            entity_uid = int(first_entity.uid)
            entity_pool_kind = str(first_entity.pool_kind)
            break
        if entity_uid >= 0:
            break

    assert entity_uid >= 0
    assert entity_pool_kind

    tick_result = runner.invoke(
        app,
        ["dbg", "tick", str(golden_trace), "1"],
    )
    assert tick_result.exit_code == 0, tick_result.output
    assert "tick=1" in tick_result.output
    assert "entity_counts" in tick_result.output

    entity_result = runner.invoke(
        app,
        ["dbg", "entity", str(golden_trace), str(entity_uid)],
    )
    assert entity_result.exit_code == 0, entity_result.output
    assert f"uid={entity_uid}" in entity_result.output
    assert "spawn_tick=" in entity_result.output

    query_ticks_result = runner.invoke(
        app,
        ["dbg", "query", str(golden_trace), "ticks where checkpoint.score_xp >= 0"],
    )
    assert query_ticks_result.exit_code == 0, query_ticks_result.output
    assert "scope=ticks" in query_ticks_result.output
    assert "match_count=2" in query_ticks_result.output

    query_entities_result = runner.invoke(
        app,
        ["dbg", "query", str(golden_trace), f"entities where pool_kind == '{entity_pool_kind}'"],
    )
    assert query_entities_result.exit_code == 0, query_entities_result.output
    assert "scope=entities" in query_entities_result.output

    focus_result = runner.invoke(
        app,
        ["dbg", "focus", str(golden_trace), str(candidate_trace), "--tick", "1"],
    )
    assert focus_result.exit_code == 0, focus_result.output
    assert "result=diverged" in focus_result.output
    assert "checkpoint_diff_count=" in focus_result.output
    assert "timing_samples ok=" in focus_result.output
