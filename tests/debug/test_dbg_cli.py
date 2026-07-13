from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import msgspec
import pytest
from typer.testing import CliRunner

import crimson.dbg.diff as dbg_diff
import crimson.dbg.trace as dbg_trace
from crimson.cli import app
from crimson.dbg.schema import TRACE_REQUIRED_CHANNELS, TickRecord
from crimson.dbg.trace import TraceReader, load_trace, write_trace
from crimson.game_modes import GameMode
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def test_dbg_verify_reports_complete_current_format_matrix() -> None:
    result = CliRunner().invoke(app, ["dbg", "verify"])

    assert result.exit_code == 0, result.output
    assert "trace_format_version=2" in result.output
    assert "trace_schema_version=15" in result.output
    assert "replay_format_version=17" in result.output
    assert "checkpoint_format_version=5" in result.output
    assert "frida_capture_format_version=23" in result.output
    assert "frida_evidence_format_version=3" in result.output
    assert "frida_runtime_version=17.15.4" in result.output
    assert "result=ok" in result.output


def test_dbg_verify_fails_when_cross_language_contract_drifts(monkeypatch: pytest.MonkeyPatch) -> None:
    import crimson.dbg.format_contract as format_contract_mod

    monkeypatch.setattr(format_contract_mod, "format_contract_errors", lambda: ["Zig replay format drifted"])
    result = CliRunner().invoke(app, ["dbg", "verify"])

    assert result.exit_code == 1
    assert "contract_error=Zig replay format drifted" in result.output
    assert "result=failed" in result.output
    assert "result=ok" not in result.output


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
    assert "trace_format_version=2" in health_result.output
    assert "trace_schema_version=15" in health_result.output
    assert 'tick_spans=[{"end_tick": 2, "start_tick": 0, "tick_count": 3}]' in health_result.output
    assert "tick_gaps=[]" in health_result.output
    assert "replay_step_rows=3" in health_result.output
    assert "validated_tick_records=3" in health_result.output
    assert "parity_analysis_ready=True" in health_result.output
    assert "timing_samples_rows=" in health_result.output


def test_dbg_health_flags_empty_timing_rows(tmp_path: Path, monkeypatch) -> None:
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
    invalid_ticks = [
        msgspec.structs.replace(
            tick,
            channels=msgspec.structs.replace(tick.channels, timing_samples=[]),
        )
        for tick in ticks
    ]
    with monkeypatch.context() as patcher:
        patcher.setattr(dbg_trace, "validate_tick_record", lambda _row, **_kwargs: None)
        write_trace(empty_timing_trace, meta=meta, ticks=invalid_ticks, chunk_ticks=2)

    health_result = runner.invoke(
        app,
        ["dbg", "health", str(empty_timing_trace)],
    )
    assert health_result.exit_code == 1, health_result.output
    assert "issue=invalid tick record 0: tick 0: timing_samples must be non-empty" in health_result.output
    assert "issue=timing_samples missing for 3 tick(s) in trace window" in health_result.output


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
    ticks = _with_score_xp_delta(ticks, tick_index=1, delta=1)
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
        warnings_out: list[str],
    ) -> object:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
        captured["impl"] = impl
        warnings_out.append("warning: zig replay verify exited 1; continuing with emitted trace")
        return SimpleNamespace(
            meta=SimpleNamespace(
                tick_range=SimpleNamespace(start_tick=0, end_tick=1, tick_count=2),
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
        ],
    )

    assert result.exit_code == 0, result.output
    assert "warning: zig replay verify exited 1; continuing with emitted trace" in result.output
    assert "trace=" in result.output
    assert "channels=" + ",".join(TRACE_REQUIRED_CHANNELS) in result.output
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == trace_path
    assert captured["impl"] == "zig"


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


def _with_score_xp_delta(rows: list[TickRecord], *, tick_index: int, delta: int) -> list[TickRecord]:
    out: list[TickRecord] = []
    for row in rows:
        if int(row.tick_index) != int(tick_index):
            out.append(row)
            continue
        checkpoint = msgspec.structs.replace(
            row.channels.checkpoint,
            score_xp=int(row.channels.checkpoint.score_xp) + int(delta),
        )
        out.append(
            msgspec.structs.replace(
                row,
                channels=msgspec.structs.replace(row.channels, checkpoint=checkpoint),
            ),
        )
    return out


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
    ticks = _with_score_xp_delta(ticks, tick_index=1, delta=1)
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
    assert bisect_result.exit_code == 1, bisect_result.output
    assert "result=diverged" in bisect_result.output
    assert "first_bad_tick=1" in bisect_result.output
    assert "window=-11..7" in bisect_result.output


def test_dbg_diff_reports_first_mismatch_for_each_channel(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_channels.crd")
    golden_trace = tmp_path / "golden_channels.cdt"
    candidate_trace = tmp_path / "candidate_channels.cdt"
    runner = CliRunner()
    record_result = runner.invoke(app, ["dbg", "record", str(replay_path), "--out", str(golden_trace)])
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    candidate = list(ticks)
    candidate[0] = msgspec.structs.replace(
        candidate[0],
        channels=msgspec.structs.replace(
            candidate[0].channels,
            checkpoint=msgspec.structs.replace(
                candidate[0].channels.checkpoint,
                score_xp=int(candidate[0].channels.checkpoint.score_xp) + 1,
            ),
        ),
    )
    timing = list(candidate[1].channels.timing_samples)
    timing[0] = msgspec.structs.replace(timing[0], time_scale_factor=0.5)
    candidate[1] = msgspec.structs.replace(
        candidate[1],
        channels=msgspec.structs.replace(candidate[1].channels, timing_samples=timing),
    )
    player = candidate[2].channels.sim_state.players[0]
    candidate[2] = msgspec.structs.replace(
        candidate[2],
        channels=msgspec.structs.replace(
            candidate[2].channels,
            sim_state=msgspec.structs.replace(
                candidate[2].channels.sim_state,
                players=[msgspec.structs.replace(player, heading=float(player.heading) + 0.25)],
            ),
        ),
    )
    write_trace(candidate_trace, meta=meta, ticks=candidate, chunk_ticks=2)

    report = dbg_diff.diff_traces(expected_trace_path=golden_trace, actual_trace_path=candidate_trace)

    assert not report.ok
    assert report.compared_count == 3
    assert report.channel_first_mismatches["checkpoint"].tick_index == 0
    assert report.channel_first_mismatches["timing_samples"].tick_index == 1
    assert report.channel_first_mismatches["sim_state"].tick_index == 2


def test_dbg_diff_prints_caller_only_rng_diagnostic_on_success(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_rng_diag.crd")
    golden_trace = tmp_path / "golden_rng_diag.cdt"
    candidate_trace = tmp_path / "candidate_rng_diag.cdt"
    runner = CliRunner()
    record_result = runner.invoke(app, ["dbg", "record", str(replay_path), "--out", str(golden_trace)])
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick = next(row for row in ticks if row.channels.rng_stream)
    rng_rows = list(tick.channels.rng_stream)
    caller = 0 if rng_rows[0].caller is None else int(rng_rows[0].caller)
    rng_rows[0] = msgspec.structs.replace(rng_rows[0], caller=caller + 4)
    ticks[int(tick.tick_index)] = msgspec.structs.replace(
        tick,
        channels=msgspec.structs.replace(tick.channels, rng_stream=rng_rows),
    )
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    result = runner.invoke(app, ["dbg", "diff", str(golden_trace), str(candidate_trace)])

    assert result.exit_code == 0, result.output
    assert "result=ok" in result.output
    assert "diagnostics=1" in result.output
    assert "diagnostic_channel=rng_stream" in result.output


def test_dbg_diff_rejects_empty_or_invalid_windows(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_window.crd")
    trace_path = tmp_path / "window.cdt"
    runner = CliRunner()
    record_result = runner.invoke(app, ["dbg", "record", str(replay_path), "--out", str(trace_path)])
    assert record_result.exit_code == 0, record_result.output

    with pytest.raises(ValueError, match="start 2 is after end 1"):
        dbg_diff.diff_traces(
            expected_trace_path=trace_path,
            actual_trace_path=trace_path,
            tick_start=2,
            tick_end=1,
        )
    with pytest.raises(ValueError, match="contains no ticks"):
        dbg_diff.diff_traces(
            expected_trace_path=trace_path,
            actual_trace_path=trace_path,
            tick_start=100,
        )


def test_dbg_diff_and_focus_reject_different_replay_identity(tmp_path: Path) -> None:
    from crimson.dbg.focus import focus_tick

    replay_path = _write_replay(tmp_path / "sample_identity.crd")
    golden_trace = tmp_path / "golden_identity.cdt"
    candidate_trace = tmp_path / "candidate_identity.cdt"
    runner = CliRunner()
    record_result = runner.invoke(app, ["dbg", "record", str(replay_path), "--out", str(golden_trace)])
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    candidate_meta = msgspec.structs.replace(
        meta,
        source=msgspec.structs.replace(meta.source, seed=int(meta.source.seed or 0) + 1),
    )
    write_trace(candidate_trace, meta=candidate_meta, ticks=ticks, chunk_ticks=2)

    with pytest.raises(ValueError, match="seed"):
        dbg_diff.diff_traces(expected_trace_path=golden_trace, actual_trace_path=candidate_trace)
    with pytest.raises(ValueError, match="seed"):
        focus_tick(golden_trace=golden_trace, candidate_trace=candidate_trace, tick_index=0)


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
    ticks = _with_score_xp_delta(ticks, tick_index=0, delta=999999)
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
    ticks = _with_score_xp_delta(ticks, tick_index=1, delta=1)
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
    ticks = _with_score_xp_delta(ticks, tick_index=1, delta=1)
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
