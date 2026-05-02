from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import msgspec
import pytest

import crimson.dbg.record as dbg_record
from crimson.dbg.canonical_channels import (
    EntitySamplesSnapshot,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
)
from crimson.dbg.schema import TRACE_SCHEMA_VERSION
from crimson.dbg.trace import load_trace
from crimson.game_modes import GameMode
from crimson.persistence.save_status import GameStatusData
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.types import Replay, ReplayHeader, ReplayTick
from crimson.rng_caller_static import RngCallerStatic


def test_record_replay_to_trace_dispatches_python_impl(monkeypatch, tmp_path: Path) -> None:
    replay_path = tmp_path / "sample.crd"
    out_path = tmp_path / "sample.cdt"
    sentinel = object()
    captured: dict[str, object] = {}

    def _fake_python(
        *,
        replay_path: Path,
        out_path: Path,
    ) -> object:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
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
        warnings_out=warnings,
    )

    assert result is sentinel
    assert warnings == []
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == out_path


def test_record_replay_to_trace_dispatches_zig_impl_and_collects_warnings(monkeypatch, tmp_path: Path) -> None:
    replay_path = tmp_path / "sample.crd"
    out_path = tmp_path / "sample.cdt"
    sentinel = object()
    captured: dict[str, object] = {}

    def _fake_zig(
        *,
        replay_path: Path,
        out_path: Path,
    ) -> tuple[object, list[str]]:
        captured["replay_path"] = replay_path
        captured["out_path"] = out_path
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
        warnings_out=warnings,
    )

    assert result is sentinel
    assert warnings == ["warning: existing", "warning: first", "warning: second"]
    assert captured["replay_path"] == replay_path
    assert captured["out_path"] == out_path


def test_record_replay_to_trace_python_writes_unattributed_rows(
    monkeypatch,
    tmp_path: Path,
) -> None:
    replay_path = tmp_path / "sample.crd"
    replay_path.write_bytes(b"fake")
    replay = Replay(
        header=ReplayHeader(
            game_mode_id=GameMode.SURVIVAL,
            seed=0x1234,
            status=GameStatusData(),
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

        def run(self, *, observer):
            tick_result = SimpleNamespace(source_tick=SimpleNamespace(tick_index=0))
            world = SimpleNamespace(
                state=SimpleNamespace(
                    time_scale_active=False,
                    bonuses=SimpleNamespace(reflex_boost=0.0),
                ),
            )
            observer.before_tick(0, world, 0.016)
            observer.after_tick(tick_result, world)
            observer.rng_trace(
                tick_result,
                ((0x90ABCDEF, 28052, 0xED9D2340, None),),
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
            ),
            players=[],
        ),
    )

    summary = dbg_record._record_replay_to_trace_python(
        replay_path=replay_path,
        out_path=tmp_path / "sample.cdt",
    )

    assert summary.meta.trace_schema_version == TRACE_SCHEMA_VERSION
    meta, ticks, footer = load_trace(tmp_path / "sample.cdt")
    assert meta.trace_schema_version == TRACE_SCHEMA_VERSION
    assert meta.status == replay.header.status
    assert footer.tick_count == 1
    assert ticks[0].channels.rng_stream[0].caller is None
    assert len(ticks[0].channels.timing_samples) == 1
    assert ticks[0].channels.timing_samples[0].phase == "gpur_enter"


def test_record_replay_to_trace_zig_emits_python_readable_trace(tmp_path: Path) -> None:
    replay_path = tmp_path / "zig-compatible.crd"
    out_path = tmp_path / "zig-sample.cdt"
    _write_zig_compatible_msgpack_replay(replay_path, player_count=1)

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    verify_run = dbg_record._run_process(
        [
            str(dbg_record._ZIG_BIN),
            "replay",
            "verify",
            str(replay_path),
            "--debug-trace-cdt",
            str(out_path),
            "--format",
            "json",
        ],
        cwd=Path.cwd(),
    )
    assert verify_run.returncode == 0, dbg_record._command_detail(verify_run)

    meta, ticks, footer = load_trace(out_path)
    assert meta.trace_schema_version == TRACE_SCHEMA_VERSION
    assert meta.status is not None
    assert footer.tick_count == len(ticks)
    assert len(ticks) > 0
    assert len(ticks[0].channels.sim_state.players) == 1
    assert len(ticks[0].channels.timing_samples) > 0
    gpur_enter = next(sample for sample in ticks[0].channels.timing_samples if sample.phase == "gpur_enter")
    assert gpur_enter.frame_dt_f32 == pytest.approx(1.0 / 60.0)
    assert gpur_enter.frame_dt_ms_i32 == ticks[0].dt_ms_i32
    assert gpur_enter.mode_fn == "gameplay_update_and_render"
    if ticks[0].channels.rng_stream:
        assert ticks[0].channels.rng_stream[0].caller == int(RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE)


def test_record_replay_to_trace_zig_emits_two_player_trace(tmp_path: Path) -> None:
    replay_path = tmp_path / "zig-compatible-2p.crd"
    out_path = tmp_path / "zig-sample-2p.cdt"
    _write_zig_compatible_msgpack_replay(replay_path, player_count=2)

    summary, warnings = dbg_record._record_replay_to_trace_zig(
        replay_path=replay_path,
        out_path=out_path,
    )

    assert warnings == []
    assert summary.meta.trace_schema_version == TRACE_SCHEMA_VERSION
    meta, ticks, footer = load_trace(out_path)
    assert meta.trace_schema_version == TRACE_SCHEMA_VERSION
    assert footer.tick_count == len(ticks)
    assert len(ticks) > 0
    assert len(ticks[0].channels.checkpoint.players) == 2
    assert len(ticks[0].channels.checkpoint.perk.player_nonzero_counts) == 2
    assert len(ticks[0].channels.sim_state.players) == 2


def test_zig_dbg_record_cli_writes_cdt_trace(tmp_path: Path) -> None:
    replay_path = tmp_path / "zig-cli-2p.crd"
    out_path = tmp_path / "zig-cli-2p.cdt"
    _write_zig_compatible_msgpack_replay(replay_path, player_count=2)

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    record_run = dbg_record._run_process(
        [
            str(dbg_record._ZIG_BIN),
            "dbg",
            "record",
            str(replay_path),
            "--out",
            str(out_path),
        ],
        cwd=dbg_record._REPO_ROOT,
    )

    assert record_run.returncode == 0, dbg_record._command_detail(record_run)
    assert f"trace={out_path}" in record_run.stdout
    assert "ticks start=0 end=0 count=1" in record_run.stdout
    assert "channels=checkpoint,sim_state,entity_samples,rng_stream,timing_samples" in record_run.stdout
    meta, ticks, footer = load_trace(out_path)
    assert meta.trace_schema_version == TRACE_SCHEMA_VERSION
    assert footer.tick_count == len(ticks)
    assert len(ticks[0].channels.sim_state.players) == 2


def _write_zig_compatible_msgpack_replay(path: Path, *, player_count: int) -> None:
    path.write_bytes(
        msgspec.msgpack.encode(
            {
                "header": {
                    "game_mode_id": int(GameMode.SURVIVAL),
                    "seed": 0xBEEF,
                    "replay_format_version": 8,
                    "quest_level": "",
                    "bootstrap_kind": "none",
                    "bootstrap_seed": 0,
                    "game_version": "0.9.0",
                    "tick_rate": 60,
                    "difficulty_level": 0,
                    "hardcore": False,
                    "preserve_bugs": False,
                    "detail_preset": 5,
                    "gore_disabled": 0,
                    "world_size": 1024.0,
                    "player_count": int(player_count),
                    "status": {
                        "quest_unlock_index": 0,
                        "quest_unlock_index_full": 0,
                        "weapon_usage_counts": [0] * 53,
                    },
                    "claimed_stats": {
                        "complete": False,
                        "ticks": 1,
                        "elapsed_ms": 16,
                        "score_xp": 0,
                        "kills": 0,
                        "most_used_weapon_id": 1,
                        "shots_fired": 0,
                        "shots_hit": 0,
                    },
                    "input_quantization": "f32",
                },
                "inputs": [
                    [[0.0, 0.0, 512.0, 512.0, 0] for _ in range(int(player_count))],
                ],
                "dt": [1.0 / 60.0],
                "events": [],
            },
        ),
    )
