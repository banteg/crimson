from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import crimson.dbg.record as dbg_record
from crimson.dbg.canonical_channels import (
    EntitySamplesSnapshot,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotStatus,
)
from crimson.dbg.trace import load_trace
from crimson.game_modes import GameMode
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.types import WEAPON_USAGE_COUNT, Replay, ReplayHeader, ReplayStatusSnapshot, ReplayTick


def test_record_replay_to_trace_dispatches_python_impl(monkeypatch, tmp_path: Path) -> None:
    replay_path = tmp_path / "sample.crd"
    out_path = tmp_path / "sample.cdt"
    sentinel = object()
    captured: dict[str, object] = {}

    def _fake_python(
        *,
        replay_path: Path,
        out_path: Path,
        chunk_ticks: int,
    ) -> object:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
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
        chunk_ticks=32,
        warnings_out=warnings,
    )

    assert result is sentinel
    assert warnings == []
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == out_path
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
        chunk_ticks: int,
    ) -> tuple[object, list[str]]:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
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
        chunk_ticks=64,
        warnings_out=warnings,
    )

    assert result is sentinel
    assert warnings == ["warning: existing", "warning: first", "warning: second"]
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == out_path
    assert captured["chunk_ticks"] == 64


def test_record_replay_to_trace_python_writes_caller_static_u32_rows(
    monkeypatch,
    tmp_path: Path,
) -> None:
    replay_path = tmp_path / "sample.crd"
    replay_path.write_bytes(b"fake")
    replay = Replay(
        header=ReplayHeader(
            game_mode_id=GameMode.SURVIVAL,
            seed=0x1234,
            status=ReplayStatusSnapshot(
                weapon_usage_counts=(0,) * int(WEAPON_USAGE_COUNT),
            ),
        ),
        ticks=[ReplayTick(dt=0.016, inputs=[[0.0, 0.0, 0.0, 0.0, 0]])],
    )

    class _FakeDriver:
        def build_checkpoint(self, *, tick_result) -> ReplayCheckpoint:
            return ReplayCheckpoint(
                tick_index=int(tick_result.source_tick.tick_index),
                rng_state=0,
                elapsed_ms=0,
                score_xp=0,
                kills=0,
                creature_count=0,
                perk_pending=0,
                players=[],
                bonus_timers={},
                deaths=[],
            )

        def run(self, *, hooks):
            tick_result = SimpleNamespace(source_tick=SimpleNamespace(tick_index=0))
            if hooks.after_tick is not None:
                hooks.after_tick(tick_result, SimpleNamespace())
            if hooks.on_rng_trace is not None:
                hooks.on_rng_trace(
                    tick_result,
                    ((0x90ABCDEF, 28052, 0xED9D2340, 0x00430B88),),
                )
            return SimpleNamespace()

    monkeypatch.setattr(dbg_record, "load_replay_file", lambda _path: replay)
    monkeypatch.setattr(dbg_record, "build_verify_playback_driver", lambda *_args, **_kwargs: _FakeDriver())
    monkeypatch.setattr(
        dbg_record,
        "_entity_samples_for_world",
        lambda *_args, **_kwargs: EntitySamplesSnapshot(
            creatures=[],
            projectiles=[],
            secondary_projectiles=[],
            bonuses=[],
        ),
    )
    monkeypatch.setattr(
        dbg_record,
        "_sim_state_from_world",
        lambda *_args, **_kwargs: SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=int(GameMode.SURVIVAL),
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
                status=SnapshotStatus(
                    quest_unlock_index=0,
                    quest_unlock_index_full=0,
                    weapon_usage_counts=[0] * int(WEAPON_USAGE_COUNT),
                ),
            ),
            players=[],
        ),
    )

    summary = dbg_record._record_replay_to_trace_python(
        replay_path=replay_path,
        out_path=tmp_path / "sample.cdt",
        chunk_ticks=1,
    )

    assert summary.meta.trace_schema_version == 8
    meta, ticks, footer = load_trace(tmp_path / "sample.cdt")
    assert meta.trace_schema_version == 8
    assert footer.tick_count == 1
    assert ticks[0].channels.rng_stream[0].caller_static_u32 == 0x00430B88
