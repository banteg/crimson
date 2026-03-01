from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from crimson.dbg.frida_finalize import FridaFinalizeError, finalize_frida_jsonl_to_traces
from crimson.dbg.trace import load_trace
from crimson.replay.codec import load_replay_file
from crimson.sim.bootstrap import run_terrain_bootstrap
from grim.rand import CrtRand


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
                "mode_id": 1,
                "phase_markers": ["a"],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    "checkpoint": _checkpoint_stub(tick_index=100, elapsed_ms=0),
                    "entity_samples": {
                        "creatures": [{"index": 5, "active": True}],
                        "projectiles": [],
                        "secondary_projectiles": [],
                        "bonuses": [],
                    },
                },
            },
            {
                "event": "tick",
                "run_id": 1,
                "tick_index_global": 101,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    "checkpoint": _checkpoint_stub(tick_index=101, elapsed_ms=16),
                    "entity_samples": {
                        "creatures": [{"index": 5, "active": False}],
                        "projectiles": [],
                        "secondary_projectiles": [],
                        "bonuses": [],
                    },
                },
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
    assert len(replay.inputs) == 2

    meta, ticks, footer = load_trace(out_trace.out_path)
    assert footer.tick_count == 2
    assert meta.producer["impl"] == "frida_original"
    assert "checkpoint" in meta.channels
    assert "entity_samples" in meta.channels
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
            {"event": "session_start"},
            _run_start_row(run_id=1, mode_id=1, seed=11, player_count=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {"checkpoint": _checkpoint_stub(tick_index=0, elapsed_ms=0)},
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
            {"event": "session_start"},
            _run_start_row(run_id=4, mode_id=2, seed=22, player_count=1),
            {
                "event": "tick",
                "run_id": 4,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "mode_id": 2,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {"checkpoint": _checkpoint_stub(tick_index=0, elapsed_ms=33)},
            },
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].run_id == 4
    assert result.traces[0].tick_count == 1
    assert result.traces[0].replay_path.is_file()


def test_finalize_frida_jsonl_to_traces_rejects_missing_session_end_when_no_runs(tmp_path: Path) -> None:
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [{"event": "session_start"}])

    with pytest.raises(FridaFinalizeError, match="missing session_end"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_names_runs_by_mode_not_stale_quest_stage(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
            _run_start_row(run_id=1, mode_id=3, seed=31, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {"checkpoint": _checkpoint_stub(tick_index=0, elapsed_ms=0)},
            },
            {"event": "run_end", "run_id": 1},
            _run_start_row(run_id=2, mode_id=2, seed=32, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                "run_id": 2,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 2,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {"checkpoint": _checkpoint_stub(tick_index=1, elapsed_ms=16)},
            },
            {"event": "run_end", "run_id": 2},
            _run_start_row(run_id=3, mode_id=1, seed=33, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                "run_id": 3,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {"checkpoint": _checkpoint_stub(tick_index=2, elapsed_ms=33)},
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
            {"event": "session_start"},
            _run_start_row(run_id=1, mode_id=1, seed=51, player_count=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
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
                        "command_hash": "",
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

    with pytest.raises(FridaFinalizeError, match="valid ReplayCheckpoint payload"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_null_run_start_seed_with_actionable_error(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
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

    with pytest.raises(FridaFinalizeError, match="seed is null; update gameplay_diff_capture.js"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_terrain_mode_without_bootstrap_metadata(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
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
            {"event": "session_start"},
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
                "mode_id": 1,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {"checkpoint": _checkpoint_stub(tick_index=0, elapsed_ms=0)},
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="terrain bootstrap seed mismatch"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_canonicalizes_unknown_death_and_negative_event_counts(
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
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    "checkpoint": {
                        **_checkpoint_stub(tick_index=0, elapsed_ms=16),
                        "deaths": [
                            {
                                "creature_index": -1,
                                "type_id": -1,
                                "xp_awarded": -1,
                                "owner_id": -1,
                                "reward_value": 0,
                            },
                        ],
                        "events": {
                            "hit_count": -1,
                            "pickup_count": -1,
                            "sfx_count": 0,
                            "sfx_head": [],
                        },
                    },
                },
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    _, ticks, _ = load_trace(result.traces[0].out_path)
    checkpoint = cast("dict[str, object]", ticks[0].channels["checkpoint"])
    events = cast("dict[str, object]", checkpoint["events"])
    event_heads = cast("list[dict[str, object]]", ticks[0].channels["event_heads"])
    event_head_types = [str(row.get("type")) for row in event_heads]

    assert checkpoint["deaths"] == []
    assert events["hit_count"] == 0
    assert events["pickup_count"] == 0
    assert "event_summary" in event_head_types
    assert "creature_death" not in event_head_types


def test_finalize_frida_jsonl_to_traces_rejects_mid_session_first_tick_elapsed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
            _run_start_row(run_id=1, mode_id=3, seed=92, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 25_000,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    "checkpoint": _checkpoint_stub(tick_index=0, elapsed_ms=25_000),
                },
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="run likely started mid-session"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_unknown_death_sentinel_in_new_capture_format(
    tmp_path: Path,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": 7},
            _run_start_row(run_id=1, mode_id=3, seed=93, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    "checkpoint": {
                        **_checkpoint_stub(tick_index=0, elapsed_ms=16),
                        "deaths": [
                            {
                                "creature_index": -1,
                                "type_id": -1,
                                "reward_value": 0,
                                "xp_awarded": -1,
                                "owner_id": -1,
                            },
                        ],
                    },
                },
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="legacy unknown death sentinel"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_negative_event_counts_in_new_capture_format(
    tmp_path: Path,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start", "capture_format_version": 7},
            _run_start_row(run_id=1, mode_id=3, seed=94, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "phase_markers": [],
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": {
                    "checkpoint": {
                        **_checkpoint_stub(tick_index=0, elapsed_ms=16),
                        "events": {
                            "hit_count": -1,
                            "pickup_count": 0,
                            "sfx_count": 0,
                            "sfx_head": [],
                        },
                    },
                },
            },
            {"event": "run_end", "run_id": 1},
            {"event": "session_end"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="checkpoint.events.hit_count must be >= 0"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
