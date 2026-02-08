from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

from grim.geom import Vec2

from crimson.replay.checkpoints import (
    ReplayCheckpoint,
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


def test_run_summary_events_from_raw_capture(tmp_path: Path) -> None:
    report = _load_report_module()
    capture_path = tmp_path / "capture.jsonl"
    rows = [
        {
            "event": "tick",
            "tick_index": 0,
            "checkpoint": {
                "tick_index": 0,
                "players": [
                    {
                        "pos": {"x": 0.0, "y": 0.0},
                        "health": 100.0,
                        "weapon_id": 1,
                        "ammo": 12.0,
                        "experience": 0,
                        "level": 1,
                    }
                ],
                "perk": {"player_nonzero_counts": [[]]},
            },
            "event_heads": {
                "bonus_apply": [
                    {
                        "player_index": 0,
                        "bonus_id": 3,
                        "amount_i32": 12,
                    }
                ],
                "weapon_assign": [
                    {
                        "player_index": 0,
                        "weapon_before": 1,
                        "weapon_after": 12,
                    }
                ],
                "state_transition": [
                    {
                        "before": {"id": 9},
                        "after": {"id": 6},
                    }
                ],
            },
        },
        {
            "event": "tick",
            "tick_index": 1,
            "checkpoint": {
                "tick_index": 1,
                "players": [
                    {
                        "pos": {"x": 0.0, "y": 0.0},
                        "health": 100.0,
                        "weapon_id": 12,
                        "ammo": 4.0,
                        "experience": 120,
                        "level": 2,
                    }
                ],
                "perk": {"player_nonzero_counts": [[[20, 1]]]},
            },
            "event_heads": {},
        },
    ]
    capture_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    events = report._build_run_summary_events_from_raw_capture(capture_path)

    assert any(event.kind == "bonus_pickup" and "Weapon (3)" in event.detail for event in events)
    assert any(event.kind == "weapon_assign" and "Pistol (1)" in event.detail for event in events)
    assert any(event.kind == "state_transition" and "state 9 -> 6" in event.detail for event in events)
    assert any(event.kind == "level_up" and "level 1 -> 2" in event.detail for event in events)
    assert any(event.kind == "perk_pick" and "Telekinetic (20)" in event.detail for event in events)


def test_run_summary_events_fall_back_to_checkpoints() -> None:
    report = _load_report_module()
    expected = [
        ReplayCheckpoint(
            tick_index=0,
            rng_state=1,
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
            state_hash="a",
            command_hash="a",
            rng_marks={},
            deaths=[],
            perk=ReplayPerkSnapshot(player_nonzero_counts=[[]]),
            events=ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1),
        ),
        ReplayCheckpoint(
            tick_index=1,
            rng_state=2,
            elapsed_ms=16,
            score_xp=100,
            kills=0,
            creature_count=0,
            perk_pending=0,
            players=[
                ReplayPlayerCheckpoint(
                    pos=Vec2(1.0, 1.0),
                    health=100.0,
                    weapon_id=12,
                    ammo=4.0,
                    experience=100,
                    level=2,
                )
            ],
            bonus_timers={},
            state_hash="b",
            command_hash="b",
            rng_marks={},
            deaths=[],
            perk=ReplayPerkSnapshot(player_nonzero_counts=[[[20, 1]]]),
            events=ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1),
        ),
    ]

    events = report._build_run_summary_events(Path("capture.json.gz"), expected=expected)

    assert any(event.kind == "weapon_assign" and "Pistol (1)" in event.detail for event in events)
    assert any(event.kind == "level_up" and "level 1 -> 2" in event.detail for event in events)
    assert any(event.kind == "perk_pick" and "Telekinetic (20)" in event.detail for event in events)


def test_build_short_run_summary_events_prefers_key_kinds() -> None:
    report = _load_report_module()
    events = [
        report.RunSummaryEvent(tick_index=10, kind="weapon_assign", detail="weapon change"),
        report.RunSummaryEvent(tick_index=11, kind="perk_pick", detail="perk pick"),
        report.RunSummaryEvent(tick_index=12, kind="debug_note", detail="ignored detail"),
        report.RunSummaryEvent(tick_index=13, kind="bonus_pickup", detail="bonus"),
        report.RunSummaryEvent(tick_index=14, kind="state_transition", detail="state"),
    ]

    short_events = report._build_short_run_summary_events(events, max_rows=3)

    assert [event.kind for event in short_events] == [
        "weapon_assign",
        "perk_pick",
        "bonus_pickup",
    ]
