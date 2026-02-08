from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

from grim.geom import Vec2

from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)


def _load_report_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "original_capture_divergence_report.py"
    spec = importlib.util.spec_from_file_location("original_capture_divergence_report", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _step_crt_state(state: int, calls: int) -> int:
    value = int(state) & 0xFFFFFFFF
    for _ in range(max(0, int(calls))):
        value = (value * 214013 + 2531011) & 0xFFFFFFFF
    return value


def _checkpoint(*, tick: int, rng_marks: dict[str, int], deaths: list[ReplayDeathLedgerEntry] | None = None) -> ReplayCheckpoint:
    return ReplayCheckpoint(
        tick_index=int(tick),
        rng_state=int(rng_marks.get("after_wave_spawns", rng_marks.get("after_world_step", 0))),
        elapsed_ms=0,
        score_xp=0,
        kills=0,
        creature_count=0,
        perk_pending=0,
        players=[
            ReplayPlayerCheckpoint(
                pos=Vec2(0.0, 0.0),
                health=100.0,
                weapon_id=1,
                ammo=12.0,
                experience=0,
                level=1,
            )
        ],
        bonus_timers={},
        state_hash="state",
        command_hash="cmd",
        rng_marks=dict(rng_marks),
        deaths=list(deaths or []),
        perk=ReplayPerkSnapshot(),
        events=ReplayEventSummary(),
    )


def test_infer_rand_calls_between_states_and_stage_breakdown() -> None:
    report = _load_report_module()
    start = 0x12345678
    s1 = _step_crt_state(start, 1)
    s9 = _step_crt_state(start, 9)
    s10 = _step_crt_state(start, 10)
    s12 = _step_crt_state(start, 12)

    assert report._infer_rand_calls_between_states(start, s1) == 1
    assert report._infer_rand_calls_between_states(start, start) == 0
    assert report._infer_rand_calls_between_states(-1, s1) is None

    ckpt = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "ws_after_creatures": s1,
            "ws_after_projectiles": s1,
            "ws_after_secondary_projectiles": s9,
            "ws_after_death_sfx": s10,
            "after_world_step": s10,
            "after_stage_spawns": s12,
            "after_wave_spawns": s12,
        },
    )
    assert report._actual_rand_calls_for_checkpoint(ckpt) == 12
    assert report._actual_rand_stage_calls(ckpt) == {
        "creatures": 1,
        "projectiles": 0,
        "secondary_projectiles": 8,
        "death_sfx_preplan": 1,
        "world_step_tail": 0,
        "survival_stage_spawns": 2,
        "survival_wave_spawns": 0,
    }


def test_window_rows_include_actual_rand_calls_and_delta() -> None:
    report = _load_report_module()
    start = 0x0BADF00D
    after = _step_crt_state(start, 10)

    expected_ckpt = _checkpoint(
        tick=5,
        rng_marks={"rand_calls": 2},
    )
    actual_ckpt = _checkpoint(
        tick=5,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after,
            "after_wave_spawns": after,
        },
        deaths=[
            ReplayDeathLedgerEntry(
                creature_index=25,
                type_id=2,
                reward_value=41.0,
                xp_awarded=41,
                owner_id=-1,
            )
        ],
    )

    rows = report._build_window_rows(
        expected_by_tick={5: expected_ckpt},
        actual_by_tick={5: actual_ckpt},
        raw_debug_by_tick={5: {"rng_rand_calls": 2, "spawn_bonus_count": 0, "spawn_death_count": 0}},
        focus_tick=5,
        window=0,
    )

    assert len(rows) == 1
    row = rows[0]
    assert int(row["expected_rand_calls"]) == 2
    assert int(row["actual_rand_calls"]) == 10
    assert int(row["rand_calls_delta"]) == 8
    assert int(row["actual_deaths"]) == 1
