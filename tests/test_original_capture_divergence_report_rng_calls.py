from __future__ import annotations

import importlib.util
import json
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


def _checkpoint(
    *,
    tick: int,
    rng_marks: dict[str, int],
    deaths: list[ReplayDeathLedgerEntry] | None = None,
    events: ReplayEventSummary | None = None,
) -> ReplayCheckpoint:
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
        events=events if events is not None else ReplayEventSummary(),
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


def test_load_raw_tick_debug_tracks_sample_coverage(tmp_path: Path) -> None:
    report = _load_report_module()
    capture_path = tmp_path / "capture.jsonl"
    row = {
        "event": "tick",
        "tick_index": 42,
        "checkpoint": {"tick_index": 42},
        "samples": {
            "creatures": [{"index": 5, "type_id": 2, "hp": 100.0, "hitbox_size": 16.0, "pos": {"x": 10.0, "y": 20.0}}],
            "projectiles": [],
            "secondary_projectiles": [
                {"index": 7, "type_id": 1, "target_id": -1, "life_timer": 0.9, "pos": {"x": 15.0, "y": 25.0}}
            ],
            "bonuses": [],
        },
    }
    capture_path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    raw = report._load_raw_tick_debug(capture_path, {42})
    assert 42 in raw
    tick = raw[42]
    assert tick["sample_streams_present"] is True
    assert tick["sample_counts"]["creatures"] == 1
    assert tick["sample_counts"]["secondary_projectiles"] == 1
    assert tick["sample_secondary_head"][0]["index"] == 7
    assert tick["sample_creatures_head"][0]["index"] == 5


def test_investigation_leads_flag_missing_focus_samples() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(
        tick=5,
        rng_marks={"rand_calls": 0},
    )
    actual_ckpt = _checkpoint(
        tick=5,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
    )
    divergence = report.Divergence(
        tick_index=5,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=5,
        lookback_ticks=32,
        float_abs_tol=1e-3,
        expected_by_tick={5: expected_ckpt},
        actual_by_tick={5: actual_ckpt},
        raw_debug_by_tick={5: {}},
        native_ranges=tuple(),
    )
    assert any(lead.title == "Capture lacks entity samples at the focus tick" for lead in leads)


def test_find_first_rng_head_shortfall_detects_pre_focus_gap() -> None:
    report = _load_report_module()
    start = 0x10203040
    after_two = _step_crt_state(start, 2)

    expected_ckpt = _checkpoint(
        tick=7,
        rng_marks={"rand_calls": 3},
    )
    actual_ckpt = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    shortfall = report._find_first_rng_head_shortfall(
        expected_by_tick={7: expected_ckpt},
        actual_by_tick={7: actual_ckpt},
        raw_debug_by_tick={
            7: {
                "rng_head_len": 3,
                "rng_rand_calls": 3,
                "rng_callers": [{"caller_static": "0x00420fd7", "calls": 3}],
            }
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 7
    assert int(shortfall["expected_head_len"]) == 3
    assert int(shortfall["actual_rand_calls"]) == 2
    assert int(shortfall["missing_draws"]) == 1


def test_investigation_leads_include_rng_head_shortfall() -> None:
    report = _load_report_module()
    start = 0x55667788
    after_two = _step_crt_state(start, 2)

    expected_shortfall = _checkpoint(
        tick=7,
        rng_marks={"rand_calls": 3},
    )
    actual_shortfall = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    expected_focus = _checkpoint(
        tick=10,
        rng_marks={"rand_calls": 0},
    )
    actual_focus = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": after_two,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    divergence = report.Divergence(
        tick_index=10,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_focus,
        actual=actual_focus,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=10,
        lookback_ticks=8,
        float_abs_tol=1e-3,
        expected_by_tick={7: expected_shortfall, 10: expected_focus},
        actual_by_tick={7: actual_shortfall, 10: actual_focus},
        raw_debug_by_tick={
            7: {
                "rng_head_len": 3,
                "rng_rand_calls": 3,
                "rng_callers": [{"caller_static": "0x00420fd7", "calls": 3}],
                "sample_counts": {"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            },
            10: {
                "rng_head_len": 0,
                "rng_rand_calls": 0,
                "sample_counts": {"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            },
        },
        native_ranges=(
            report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),
        ),
    )

    lead = next((item for item in leads if item.title == "Pre-focus RNG-head shortfall indicates missing RNG-consuming branch"), None)
    assert lead is not None
    assert "projectile_update" in lead.native_functions


def test_find_first_projectile_hit_shortfall_detects_gap() -> None:
    report = _load_report_module()
    actual_ckpt = _checkpoint(
        tick=12,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
        events=ReplayEventSummary(hit_count=4, pickup_count=0, sfx_count=0, sfx_head=[]),
    )

    shortfall = report._find_first_projectile_hit_shortfall(
        actual_by_tick={12: actual_ckpt},
        raw_debug_by_tick={
            12: {
                "projectile_find_hit_count": 5,
                "projectile_find_hit_corpse_count": 1,
                "spawn_top_projectile_find_hit_callers": [{"key": "0x00420fd7", "count": 5}],
            }
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 12
    assert int(shortfall["capture_hits"]) == 5
    assert int(shortfall["actual_hits"]) == 4
    assert int(shortfall["missing_hits"]) == 1


def test_investigation_leads_include_projectile_hit_shortfall() -> None:
    report = _load_report_module()
    expected_focus = _checkpoint(
        tick=10,
        rng_marks={"rand_calls": 0},
    )
    actual_focus = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": 0x12345678,
            "after_world_step": 0x12345678,
            "after_wave_spawns": 0x12345678,
        },
        events=ReplayEventSummary(hit_count=4, pickup_count=0, sfx_count=0, sfx_head=[]),
    )
    divergence = report.Divergence(
        tick_index=10,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_focus,
        actual=actual_focus,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=10,
        lookback_ticks=8,
        float_abs_tol=1e-3,
        expected_by_tick={10: expected_focus},
        actual_by_tick={10: actual_focus},
        raw_debug_by_tick={
            10: {
                "rng_rand_calls": 0,
                "projectile_find_hit_count": 6,
                "projectile_find_hit_corpse_count": 2,
                "spawn_top_projectile_find_hit_callers": [{"key": "0x00420fd7", "count": 6}],
                "sample_counts": {"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            }
        },
        native_ranges=(
            report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),
        ),
    )

    lead = next((item for item in leads if item.title == "Native projectile hit resolves exceed rewrite hit events"), None)
    assert lead is not None
    assert "projectile_update" in lead.native_functions
