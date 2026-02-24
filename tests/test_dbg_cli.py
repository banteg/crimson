from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from crimson.cli import app
from crimson.original.capture import dump_capture
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
