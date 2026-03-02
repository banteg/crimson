from __future__ import annotations

from pathlib import Path
from typing import cast

from typer.testing import CliRunner

import crimson.dbg.diff as dbg_diff
from crimson.cli import app
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
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--profile", "standard"],
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
    assert "movement_root_cause_ready=" in health_result.output


def _write_replay(path: Path, *, ticks: int = 3) -> Path:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
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
        game_mode_id=int(GameMode.SURVIVAL),
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick([PlayerInput(aim=Vec2(700.0, 512.0), fire_down=True)])
    path.write_bytes(dump_replay(recorder.finish()))
    return path


def _as_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    out: dict[str, object] = {}
    for key, item in value.items():
        assert isinstance(key, str)
        out[key] = item
    return out


def test_dbg_record_standard_profile(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    trace_path = tmp_path / "sample.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--profile", "standard"],
    )
    assert result.exit_code == 0, result.output
    assert "channels=" in result.output
    assert "checkpoint" in result.output
    assert "rng_marks" in result.output
    assert "rng_stream" in result.output
    assert "sim_state" in result.output
    assert "entity_samples" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        assert "checkpoint" in tick0.channels
        assert "rng_marks" in tick0.channels
        assert "rng_stream" in tick0.channels
        assert "sim_state" in tick0.channels
        assert "entity_samples" in tick0.channels
        for row in trace.iter_ticks():
            rng_stream_obj = row.channels.get("rng_stream")
            assert isinstance(rng_stream_obj, list)
            for stream_row in rng_stream_obj:
                inferred_obj = _as_dict(stream_row).get("inferred")
                assert isinstance(inferred_obj, bool)
                assert not inferred_obj


def test_dbg_record_full_profile_uses_canonical_channels(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_full.crd")
    trace_path = tmp_path / "sample_full.cdt"
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(trace_path), "--profile", "full"],
    )
    assert result.exit_code == 0, result.output
    assert "checkpoint" in result.output
    assert "rng_marks" in result.output
    assert "rng_stream" in result.output
    assert "sim_state" in result.output
    assert "entity_samples" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        rng_stream = tick0.channels.get("rng_stream")
        assert isinstance(rng_stream, list)
        sim_state = tick0.channels.get("sim_state")
        assert isinstance(sim_state, dict)
        entity_samples = tick0.channels.get("entity_samples")
        assert isinstance(entity_samples, dict)


def test_dbg_diff_and_bisect(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample.crd")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    repro_trace = tmp_path / "repro.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
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
        ["dbg", "bisect", str(golden_trace), str(candidate_trace), "--out", str(repro_trace)],
    )
    assert bisect_result.exit_code == 0, bisect_result.output
    assert "result=diverged" in bisect_result.output
    assert "first_bad_tick=1" in bisect_result.output
    assert repro_trace.exists()


def test_dbg_diff_hash_field_changes_report_checkpoint_mismatch(tmp_path: Path) -> None:
    replay_path = _write_replay(tmp_path / "sample_hashes.crd")
    golden_trace = tmp_path / "golden_hashes.cdt"
    candidate_trace = tmp_path / "candidate_hashes.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick0 = next(row for row in ticks if int(row.tick_index) == 0)
    checkpoint = cast(dict[str, object], tick0.channels["checkpoint"])
    checkpoint["state_hash"] = "ffffffffffffffff"
    checkpoint["command_hash"] = "eeeeeeeeeeeeeeee"
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
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    for row in ticks:
        row.channels.pop("entity_samples", None)
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
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if row.tick_index == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    call_count = 0
    original_first_mismatch = dbg_diff._first_mismatch

    def _counting_first_mismatch(*, pairs, float_abs_tol, max_field_diffs, ignore_field_prefixes, tick_end=None):
        nonlocal call_count
        call_count += 1
        return original_first_mismatch(
            pairs=pairs,
            float_abs_tol=float_abs_tol,
            max_field_diffs=max_field_diffs,
            ignore_field_prefixes=ignore_field_prefixes,
            tick_end=tick_end,
        )

    monkeypatch.setattr(dbg_diff, "_first_mismatch", _counting_first_mismatch)
    report = dbg_diff.bisect_traces(
        expected_trace_path=golden_trace,
        actual_trace_path=candidate_trace,
    )
    assert report.first_bad_tick == 1
    assert call_count == 1


def test_dbg_tick_entity_query_focus(tmp_path: Path) -> None:
    replay_path = _write_replay_with_fire(tmp_path / "capture_like.crd", ticks=2)
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    entity_uid = -1
    entity_pool_kind = ""
    for row in ticks:
        entity_samples = _as_dict(row.channels["entity_samples"])
        for pool_name in ("projectiles", "creatures", "secondary_projectiles", "bonuses"):
            pool_obj = entity_samples.get(pool_name)
            if not isinstance(pool_obj, list) or not pool_obj:
                continue
            first_entity = _as_dict(pool_obj[0])
            uid_obj = first_entity.get("uid")
            pool_kind_obj = first_entity.get("pool_kind")
            if isinstance(uid_obj, int) and isinstance(pool_kind_obj, str):
                entity_uid = int(uid_obj)
                entity_pool_kind = str(pool_kind_obj)
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


def test_dbg_viz(tmp_path: Path) -> None:
    replay_path = _write_replay_with_fire(tmp_path / "capture_like.crd", ticks=2)
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    html_out = tmp_path / "viz.html"
    runner = CliRunner()

    record_result = runner.invoke(
        app,
        ["dbg", "record", str(replay_path), "--out", str(golden_trace), "--profile", "standard"],
    )
    assert record_result.exit_code == 0, record_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    result = runner.invoke(
        app,
        ["dbg", "viz", str(golden_trace), str(candidate_trace), "--tick", "1", "--out", str(html_out)],
    )
    assert result.exit_code == 0, result.output
    assert "viz_html=" in result.output
    assert html_out.exists()
    html_text = html_out.read_text(encoding="utf-8")
    assert "Crimson Debug Viz" in html_text
    assert "Focus tick: 1" in html_text
    assert "tick-slider" in html_text
