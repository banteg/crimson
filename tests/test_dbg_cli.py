from __future__ import annotations

from pathlib import Path
from typing import cast

from typer.testing import CliRunner

from crimson.cli import app
from crimson.dbg.trace import TraceReader, load_trace, write_trace
from crimson.game_modes import GameMode
from crimson.original.capture import dump_capture
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay
from crimson.sim.input import PlayerInput
from grim.geom import Vec2
from tests.builders.capture import (
    build_capture_creature_sample,
    build_capture_event_head_creature_update_micro_window,
    build_capture_file,
    build_capture_rng_head_entry,
    build_capture_tick,
)


def _write_capture(path: Path) -> Path:
    tick0 = build_capture_tick(
        tick_index=0,
        elapsed_ms=0,
        event_heads=[build_capture_event_head_creature_update_micro_window(slot=0)],
    )
    tick1 = build_capture_tick(
        tick_index=1,
        elapsed_ms=16,
        event_heads=[build_capture_event_head_creature_update_micro_window(slot=1)],
    )
    tick0.samples.creatures = [build_capture_creature_sample(index=5)]
    tick1.samples.creatures = [build_capture_creature_sample(index=5)]
    tick0.rng.head = [build_capture_rng_head_entry()]
    tick1.rng.head = [build_capture_rng_head_entry()]
    capture = build_capture_file(ticks=[tick0, tick1])
    dump_capture(path, capture)
    return path


def test_dbg_import_capture_and_health(tmp_path: Path) -> None:
    capture_path = _write_capture(tmp_path / "capture.json")
    trace_path = tmp_path / "capture.cdt"
    runner = CliRunner()

    import_result = runner.invoke(
        app,
        ["dbg", "import-capture", str(capture_path), "--out", str(trace_path)],
    )
    assert import_result.exit_code == 0, import_result.output
    assert trace_path.exists()
    assert "channels=" in import_result.output
    assert "entity_samples" in import_result.output

    health_result = runner.invoke(
        app,
        ["dbg", "health", str(trace_path), "--strict"],
    )
    assert health_result.exit_code == 0, health_result.output
    assert "movement_root_cause_ready=True" in health_result.output


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
    assert "entity_samples" in result.output

    with TraceReader(trace_path) as trace:
        tick0 = trace.tick(0)
        assert tick0 is not None
        assert "checkpoint" in tick0.channels
        assert "rng_marks" in tick0.channels
        assert "entity_samples" in tick0.channels


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


def test_dbg_tick_entity_query_focus(tmp_path: Path) -> None:
    capture_path = _write_capture(tmp_path / "capture.json")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    runner = CliRunner()

    import_result = runner.invoke(
        app,
        ["dbg", "import-capture", str(capture_path), "--out", str(golden_trace)],
    )
    assert import_result.exit_code == 0, import_result.output

    meta, ticks, _footer = load_trace(golden_trace)
    tick1 = next(row for row in ticks if int(row.tick_index) == 1)
    checkpoint = cast(dict[str, object], tick1.channels["checkpoint"])
    score_xp_obj = checkpoint.get("score_xp")
    assert isinstance(score_xp_obj, int)
    checkpoint["score_xp"] = score_xp_obj + 1
    write_trace(candidate_trace, meta=meta, ticks=ticks, chunk_ticks=2)

    entity_samples = _as_dict(tick1.channels["entity_samples"])
    creatures_obj = entity_samples.get("creatures")
    assert isinstance(creatures_obj, list)
    first_creature = _as_dict(creatures_obj[0])
    uid_obj = first_creature.get("uid")
    assert isinstance(uid_obj, int)
    entity_uid = int(uid_obj)

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
    assert "spawn_tick=0" in entity_result.output

    query_ticks_result = runner.invoke(
        app,
        ["dbg", "query", str(golden_trace), "ticks where checkpoint.score_xp >= 0"],
    )
    assert query_ticks_result.exit_code == 0, query_ticks_result.output
    assert "scope=ticks" in query_ticks_result.output
    assert "match_count=2" in query_ticks_result.output

    query_entities_result = runner.invoke(
        app,
        ["dbg", "query", str(golden_trace), "entities where pool_kind == 'creature'"],
    )
    assert query_entities_result.exit_code == 0, query_entities_result.output
    assert "scope=entities" in query_entities_result.output

    focus_result = runner.invoke(
        app,
        ["dbg", "focus", str(golden_trace), str(candidate_trace), "--tick", "1"],
    )
    assert focus_result.exit_code == 0, focus_result.output
    assert "result=diverged" in focus_result.output
    assert "checkpoint_field_count=" in focus_result.output


def test_dbg_viz(tmp_path: Path) -> None:
    capture_path = _write_capture(tmp_path / "capture.json")
    golden_trace = tmp_path / "golden.cdt"
    candidate_trace = tmp_path / "candidate.cdt"
    html_out = tmp_path / "viz.html"
    runner = CliRunner()

    import_result = runner.invoke(
        app,
        ["dbg", "import-capture", str(capture_path), "--out", str(golden_trace)],
    )
    assert import_result.exit_code == 0, import_result.output

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
