from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from crimson.dbg.frida_finalize import FridaFinalizeError, finalize_frida_jsonl_to_traces
from crimson.dbg.rng import canonical_rng_marks
from crimson.dbg.trace import load_trace
from crimson.replay.codec import load_replay_file
from crimson.replay.types import WEAPON_USAGE_COUNT
from crimson.sim.bootstrap import run_terrain_bootstrap
from grim.rand import CrtRand

CAPTURE_FORMAT_VERSION = 9


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row))
            handle.write("\n")
    return path


def _checkpoint_stub(*, tick_index: int, elapsed_ms: int) -> dict[str, object]:
    return {
        "tick_index": int(tick_index),
        "rng_state": 0,
        "elapsed_ms": int(elapsed_ms),
        "score_xp": 0,
        "kills": 0,
        "creature_count": 0,
        "perk_pending": 0,
        "players": [],
        "bonus_timers": {},
    }


def _sim_state_stub(
    *,
    mode_id: int,
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
) -> dict[str, object]:
    return {
        "gameplay": {
            "mode_id": int(mode_id),
            "quest_stage_major": int(quest_stage_major),
            "quest_stage_minor": int(quest_stage_minor),
            "perk_pending_count": 0,
            "perk_choices_dirty": True,
            "bonus_timers": {
                "weapon_power_up_ms": 0,
                "reflex_boost_ms": 0,
                "energizer_ms": 0,
                "double_experience_ms": 0,
                "freeze_ms": 0,
            },
            "status": {
                "quest_unlock_index": 0,
                "quest_unlock_index_full": 0,
                "weapon_usage_counts": [0] * int(WEAPON_USAGE_COUNT),
            },
        },
        "players": [],
    }


def _entity_samples_stub(*, creatures: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "creatures": list(creatures or []),
        "projectiles": [],
        "secondary_projectiles": [],
        "bonuses": [],
    }


def _creature_sample(
    *,
    uid: int,
    generation: int,
    index: int,
    active: bool = True,
) -> dict[str, object]:
    return {
        "uid": int(uid),
        "generation": int(generation),
        "pool_kind": "creature",
        "index": int(index),
        "active": bool(active),
        "type_id": 0,
        "hp": 1.0,
        "pos": {"x": 0.0, "y": 0.0},
        "flags": 0,
        "ai_mode": 0,
        "link_index": -1,
        "heading": 0.0,
        "target_heading": 0.0,
        "orbit_angle": 0.0,
        "orbit_radius": 0.0,
        "lifecycle_stage": 0.0,
    }


def _channels_stub(
    *,
    tick_index: int,
    elapsed_ms: int,
    mode_id: int,
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    creatures: list[dict[str, object]] | None = None,
    checkpoint_overrides: dict[str, object] | None = None,
    rng_marks: dict[str, int] | None = None,
) -> dict[str, object]:
    checkpoint = _checkpoint_stub(tick_index=int(tick_index), elapsed_ms=int(elapsed_ms))
    if checkpoint_overrides:
        checkpoint.update(dict(checkpoint_overrides))
    if rng_marks is None:
        rng_state_obj = checkpoint.get("rng_state", -1)
        assert isinstance(rng_state_obj, int)
        marks = canonical_rng_marks(
            rng_state=int(rng_state_obj),
            rng_stream=[],
        )
    else:
        marks = dict(rng_marks)
    checkpoint["rng_marks"] = dict(marks)
    return {
        "checkpoint": checkpoint,
        "sim_state": _sim_state_stub(
            mode_id=int(mode_id),
            quest_stage_major=int(quest_stage_major),
            quest_stage_minor=int(quest_stage_minor),
        ),
        "entity_samples": _entity_samples_stub(creatures=creatures),
        "rng_marks": dict(marks),
        "rng_stream": [],
        "timing_samples": [],
    }


def _terrain_seed_after(*, bootstrap_seed: int, quest_unlock_index: int = 0, world_size: int = 1024) -> int:
    rng = CrtRand(seed=int(bootstrap_seed))
    terrain = run_terrain_bootstrap(
        rng,
        quest_unlock_index=int(quest_unlock_index),
        width=int(world_size),
        height=int(world_size),
        layers=3,
    )
    return int(terrain.seed_after)


def _replay_inputs_stub(*, player_count: int = 1) -> list[list[float | int]]:
    return [[0.0, 0.0, 0.0, 0.0, 0] for _ in range(max(1, int(player_count)))]


def _run_start_row(
    *,
    run_id: int,
    mode_id: int,
    seed: int = 123,
    player_count: int = 1,
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    bootstrap_kind: str | None = None,
    bootstrap_seed: int | None = None,
) -> dict[str, object]:
    mode = int(mode_id)
    kind = bootstrap_kind
    if kind is None:
        kind = "terrain_v1" if mode in (1, 2) else "none"
    seed_val = bootstrap_seed
    if seed_val is None:
        seed_val = int(seed) if str(kind) == "terrain_v1" else 0
    run_seed = int(seed)
    if str(kind) == "terrain_v1":
        run_seed = _terrain_seed_after(bootstrap_seed=int(seed_val), quest_unlock_index=0)
    return {
        "event": "run_start",
        "run_id": int(run_id),
        "mode_id": mode,
        "seed": int(run_seed),
        "bootstrap_kind": str(kind),
        "bootstrap_seed": int(seed_val),
        "seed_source": "terrain_bootstrap_sim" if str(kind) == "terrain_v1" else "crt_srand",
        "player_count": int(player_count),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
    }


def test_finalize_frida_jsonl_to_traces_writes_trace_and_replay_and_deletes_raw(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {
                "event": "session_start",
                "capture_format_version": CAPTURE_FORMAT_VERSION,
                "platform": "windows",
                "arch": "x86",
                "script_version": "5",
                "config": {"a": 1},
            },
            _run_start_row(run_id=1, mode_id=1, seed=777, player_count=1),
            {
                "event": "tick",
                "run_id": 1,
                "tick_index_global": 100,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "phase_markers": ["a"],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=100,
                    elapsed_ms=0,
                    mode_id=1,
                    creatures=[_creature_sample(uid=562949953421317, generation=1, index=5, active=True)],
                ),
            },
            {
                "event": "tick",
                "run_id": 1,
                "tick_index_global": 101,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=101,
                    elapsed_ms=16,
                    mode_id=1,
                    creatures=[_creature_sample(uid=562949953421317, generation=1, index=5, active=False)],
                ),
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=True)

    assert result.deleted_raw is True
    assert not raw_path.exists()
    assert len(result.traces) == 1

    out_trace = result.traces[0]
    assert out_trace.tick_count == 2
    assert out_trace.replay_path.is_file()

    replay = load_replay_file(out_trace.replay_path)
    assert replay.header.game_mode_id == 1
    assert replay.header.seed == _terrain_seed_after(bootstrap_seed=777)
    assert replay.header.bootstrap_kind == "terrain_v1"
    assert replay.header.bootstrap_seed == 777
    assert replay.header.player_count == 1
    assert len(replay.ticks) == 2

    meta, ticks, footer = load_trace(out_trace.out_path)
    assert footer.tick_count == 2
    assert meta.producer["impl"] == "frida_original"
    assert "checkpoint" in meta.channels
    assert "sim_state" in meta.channels
    assert "entity_samples" in meta.channels
    assert "rng_stream" in meta.channels
    assert cast("dict[str, object]", ticks[0].channels["checkpoint"])["tick_index"] == 0
    assert cast("dict[str, object]", ticks[1].channels["checkpoint"])["tick_index"] == 1

    creatures0 = cast("dict[str, list[dict[str, object]]]", ticks[0].channels["entity_samples"])["creatures"]
    creatures1 = cast("dict[str, list[dict[str, object]]]", ticks[1].channels["entity_samples"])["creatures"]
    assert isinstance(creatures0[0]["uid"], int)
    assert creatures0[0]["generation"] == 1
    assert creatures1[0]["generation"] == 1


def test_finalize_frida_jsonl_to_traces_allows_missing_session_end_when_run_closed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=1, mode_id=1, seed=11, player_count=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1),
            },
            {"event": "run_end", "run_id": 1},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].tick_count == 1
    assert result.traces[0].replay_path.is_file()


def test_finalize_frida_jsonl_to_traces_finalizes_active_run_when_capture_abruptly_ends(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=4, mode_id=2, seed=22, player_count=1),
            {
                "event": "tick",
                "run_id": 4,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "dt": 0.033,
                "mode_id": 2,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=33, mode_id=2),
            },
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].run_id == 4
    assert result.traces[0].tick_count == 1
    assert result.traces[0].replay_path.is_file()


def test_finalize_frida_jsonl_to_traces_rejects_missing_session_end_when_no_runs(tmp_path: Path) -> None:
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [{"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION}])

    with pytest.raises(FridaFinalizeError, match="missing session_end"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_names_runs_by_mode_not_stale_quest_stage(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=1, mode_id=3, seed=31, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=3),
            },
            {"event": "run_end", "run_id": 1},
            _run_start_row(run_id=2, mode_id=2, seed=32, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                "run_id": 2,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 2,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=1, elapsed_ms=16, mode_id=2),
            },
            {"event": "run_end", "run_id": 2},
            _run_start_row(run_id=3, mode_id=1, seed=33, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                "run_id": 3,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "dt": 0.033,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=2, elapsed_ms=33, mode_id=1),
            },
            {"event": "run_end", "run_id": 3},
            {"event": "session_end"},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 3
    names = sorted(trace.out_path.name for trace in result.traces)
    assert names == [
        "capture.quest_1_5.run1.cdt",
        "capture.rush.run1.cdt",
        "capture.survival.run1.cdt",
    ]
    replay_names = sorted(trace.replay_path.name for trace in result.traces)
    assert replay_names == [
        "capture.quest_1_5.run1.crd",
        "capture.rush.run1.crd",
        "capture.survival.run1.crd",
    ]


def test_finalize_frida_jsonl_to_traces_rejects_non_int_checkpoint_rng_marks(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=1, mode_id=1, seed=51, player_count=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    **_channels_stub(tick_index=123, elapsed_ms=0, mode_id=1),
                    "checkpoint": {
                        "tick_index": 123,
                        "rng_state": 777,
                        "elapsed_ms": 0,
                        "score_xp": 0,
                        "kills": 0,
                        "creature_count": 0,
                        "perk_pending": 0,
                        "players": [],
                        "bonus_timers": {},
                        "state_hash": "",
                        "rng_marks": {
                            "rand_calls": 3,
                            "rand_last": 99,
                            "rand_hash": "0xdeadbeef",
                            "rand_head": [],
                        },
                    },
                    "rng_marks": {
                        "rand_calls": 3,
                        "rand_last": 99,
                        "rand_seq_first": 1,
                        "rand_seq_last": 3,
                    },
                },
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="invalid capture row: Expected `int`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_null_run_start_seed_with_actionable_error(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "seed": None,
                "player_count": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="Expected `int`, got `null` - at `\\$\\.seed`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_terrain_mode_without_bootstrap_metadata(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "seed": 7,
                "bootstrap_kind": "none",
                "bootstrap_seed": 0,
                "player_count": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="requires bootstrap_kind='terrain_v1'"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_terrain_seed_mismatch(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "seed": 7,
                "bootstrap_kind": "terrain_v1",
                "bootstrap_seed": 7,
                "seed_source": "thread_rng_sample",
                "player_count": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1),
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="terrain bootstrap seed mismatch"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_legacy_capture_format_version(
    tmp_path: Path,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": 6},
            _run_start_row(run_id=1, mode_id=3, seed=91, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3),
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unsupported capture_format_version=6; expected 9"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_keeps_large_first_tick_elapsed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=1, mode_id=3, seed=92, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 25_000,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=25_000, mode_id=3),
            },
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    assert result.deleted_raw is False
    assert len(result.traces) == 1
    assert result.traces[0].tick_count == 1


def test_finalize_frida_jsonl_to_traces_rejects_missing_required_canonical_channel(
    tmp_path: Path,
) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3)
    channels.pop("sim_state", None)
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=1, mode_id=3, seed=93, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": channels,
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `sim_state`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_extra_non_canonical_channel(
    tmp_path: Path,
) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3)
    channels["event_heads"] = []
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": CAPTURE_FORMAT_VERSION},
            _run_start_row(run_id=1, mode_id=3, seed=94, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": channels,
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `event_heads`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_missing_capture_format_version(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `capture_format_version`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
