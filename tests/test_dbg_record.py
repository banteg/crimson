from __future__ import annotations

from pathlib import Path

import pytest

import crimson.dbg.record as dbg_record


def test_record_replay_to_trace_dispatches_python_impl(monkeypatch, tmp_path: Path) -> None:
    replay_path = tmp_path / "sample.crd"
    out_path = tmp_path / "sample.cdt"
    sentinel = object()
    captured: dict[str, object] = {}

    def _fake_python(
        *,
        replay_path: Path,
        out_path: Path,
        strict_events: bool,
        chunk_ticks: int,
    ) -> object:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
        captured["strict_events"] = strict_events
        captured["chunk_ticks"] = chunk_ticks
        return sentinel

    monkeypatch.setattr(dbg_record, "_record_replay_to_trace_python", _fake_python)
    monkeypatch.setattr(
        dbg_record,
        "_record_replay_to_trace_zig",
        lambda **_kwargs: pytest.fail("zig impl should not be called"),
    )

    warnings: list[str] = []
    result = dbg_record.record_replay_to_trace(
        replay_path=replay_path,
        out_path=out_path,
        impl="python",
        strict_events=True,
        chunk_ticks=32,
        warnings_out=warnings,
    )

    assert result is sentinel
    assert warnings == []
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == out_path
    assert captured["strict_events"] is True
    assert captured["chunk_ticks"] == 32


def test_record_replay_to_trace_dispatches_zig_impl_and_collects_warnings(monkeypatch, tmp_path: Path) -> None:
    replay_path = tmp_path / "sample.crd"
    out_path = tmp_path / "sample.cdt"
    sentinel = object()
    captured: dict[str, object] = {}

    def _fake_zig(
        *,
        replay_path: Path,
        out_path: Path,
        strict_events: bool,
        chunk_ticks: int,
    ) -> tuple[object, list[str]]:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
        captured["strict_events"] = strict_events
        captured["chunk_ticks"] = chunk_ticks
        return sentinel, ["warning: first", "warning: second"]

    monkeypatch.setattr(
        dbg_record,
        "_record_replay_to_trace_python",
        lambda **_kwargs: pytest.fail("python impl should not be called"),
    )
    monkeypatch.setattr(dbg_record, "_record_replay_to_trace_zig", _fake_zig)

    warnings = ["warning: existing"]
    result = dbg_record.record_replay_to_trace(
        replay_path=replay_path,
        out_path=out_path,
        impl="zig",
        strict_events=True,
        chunk_ticks=64,
        warnings_out=warnings,
    )

    assert result is sentinel
    assert warnings == ["warning: existing", "warning: first", "warning: second"]
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == out_path
    assert captured["strict_events"] is True
    assert captured["chunk_ticks"] == 64
