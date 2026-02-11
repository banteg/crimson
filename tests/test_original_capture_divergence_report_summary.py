from __future__ import annotations

import json
from pathlib import Path

from grim.geom import Vec2

from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)


def _load_report_module():
    from crimson.original import divergence_report

    return divergence_report


def _checkpoint_tick(tick: int, *, level: int, weapon_id: int, experience: int, perk_pairs: list[list[int]]) -> dict[str, object]:
    return {
        "tick_index": int(tick),
        "state_hash": f"s{tick}",
        "command_hash": f"c{tick}",
        "rng_state": 0,
        "elapsed_ms": int(tick) * 16,
        "score_xp": int(experience),
        "kills": 0,
        "creature_count": 0,
        "perk_pending": 0,
        "players": [
            {
                "pos": {"x": 0.0, "y": 0.0},
                "health": 100.0,
                "weapon_id": int(weapon_id),
                "ammo": 12.0,
                "experience": int(experience),
                "level": int(level),
            }
        ],
        "status": {
            "quest_unlock_index": -1,
            "quest_unlock_index_full": -1,
            "weapon_usage_counts": [],
        },
        "bonus_timers": {},
        "rng_marks": {
            "rand_calls": 0,
            "rand_hash": "",
            "rand_last": None,
            "rand_head": [],
            "rand_callers": [],
            "rand_caller_overflow": 0,
            "rand_seq_first": None,
            "rand_seq_last": None,
            "rand_seed_epoch_enter": None,
            "rand_seed_epoch_last": None,
            "rand_outside_before_calls": 0,
            "rand_outside_before_dropped": 0,
            "rand_outside_before_head": [],
            "rand_mirror_mismatch_total": 0,
            "rand_mirror_unknown_total": 0,
        },
        "deaths": [],
        "perk": {
            "pending_count": 0,
            "choices_dirty": False,
            "choices": [],
            "player_nonzero_counts": [perk_pairs],
        },
        "events": {"hit_count": -1, "pickup_count": -1, "sfx_count": -1, "sfx_head": []},
        "debug": {
            "sampling_phase": "",
            "timing": {},
            "spawn": {},
            "rng": {},
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "before_players": [],
            "before_status": {"quest_unlock_index": -1, "quest_unlock_index_full": -1},
        },
    }


def _capture_tick(
    tick: int,
    *,
    level: int,
    weapon_id: int,
    experience: int,
    perk_pairs: list[list[int]],
    event_heads: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "tick_index": int(tick),
        "gameplay_frame": int(tick) + 1,
        "mode_hint": "survival_update",
        "game_mode_id": 6,
        "checkpoint": _checkpoint_tick(
            tick,
            level=int(level),
            weapon_id=int(weapon_id),
            experience=int(experience),
            perk_pairs=perk_pairs,
        ),
        "event_heads": list(event_heads),
        "input_queries": {
            "stats": {
                "primary_edge": {"calls": 0, "true_calls": 0},
                "primary_down": {"calls": 0, "true_calls": 0},
                "any_key": {"calls": 0, "true_calls": 0},
            },
            "query_hash": "",
        },
        "input_player_keys": [{"player_index": 0}],
        "input_approx": [{"player_index": 0, "aim_x": 0.0, "aim_y": 0.0}],
    }


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    return {
        "script": "gameplay_diff_capture",
        "session_id": "s",
        "out_path": "capture.json",
        "config": {},
        "session_fingerprint": {"session_id": "s", "module_hash": "a", "ptrs_hash": "b"},
        "process": {"pid": 1, "platform": "windows", "arch": "x86", "frida_version": "16", "runtime": "v8"},
        "exe": {"base": "0x400000", "size": 1, "path": "crimsonland.exe"},
        "grim": None,
        "pointers_resolved": {},
        "ticks": ticks,
    }


def _write_capture_stream(path: Path, capture: dict[str, object]) -> None:
    meta = {k: v for k, v in capture.items() if k != "ticks"}
    ticks_obj = capture.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks
    )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_run_summary_events_from_raw_capture(tmp_path: Path) -> None:
    report = _load_report_module()
    capture_path = tmp_path / "capture.json"
    capture = _capture_obj(
        ticks=[
            _capture_tick(
                0,
                level=1,
                weapon_id=1,
                experience=0,
                perk_pairs=[],
                event_heads=[
                    {"kind": "bonus_apply", "data": {"player_index": 0, "bonus_id": 3, "amount_i32": 12}},
                    {"kind": "weapon_assign", "data": {"player_index": 0, "weapon_before": 1, "weapon_after": 12}},
                    {"kind": "state_transition", "data": {"before": {"id": 9}, "after": {"id": 6}}},
                ],
            ),
            _capture_tick(
                1,
                level=2,
                weapon_id=12,
                experience=120,
                perk_pairs=[[20, 1]],
                event_heads=[],
            ),
        ]
    )
    _write_capture_stream(capture_path, capture)

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


def test_build_focus_run_summary_events_uses_short_kinds_around_focus() -> None:
    report = _load_report_module()
    events = [
        report.RunSummaryEvent(tick_index=90, kind="debug_note", detail="ignored"),
        report.RunSummaryEvent(tick_index=95, kind="bonus_pickup", detail="bonus"),
        report.RunSummaryEvent(tick_index=98, kind="weapon_assign", detail="weapon"),
        report.RunSummaryEvent(tick_index=100, kind="debug_note", detail="ignored focus"),
        report.RunSummaryEvent(tick_index=101, kind="perk_pick", detail="perk"),
        report.RunSummaryEvent(tick_index=106, kind="level_up", detail="lvl"),
        report.RunSummaryEvent(tick_index=110, kind="state_transition", detail="state"),
    ]

    focus_events = report._build_focus_run_summary_events(
        events,
        focus_tick=100,
        before_rows=2,
        after_rows=2,
    )

    assert [(event.tick_index, event.kind) for event in focus_events] == [
        (95, "bonus_pickup"),
        (98, "weapon_assign"),
        (101, "perk_pick"),
        (106, "level_up"),
    ]


def test_build_focus_run_summary_events_falls_back_when_no_short_kinds() -> None:
    report = _load_report_module()
    events = [
        report.RunSummaryEvent(tick_index=10, kind="debug_note", detail="a"),
        report.RunSummaryEvent(tick_index=12, kind="debug_note", detail="b"),
        report.RunSummaryEvent(tick_index=15, kind="debug_note", detail="c"),
    ]

    focus_events = report._build_focus_run_summary_events(
        events,
        focus_tick=12,
        before_rows=1,
        after_rows=1,
    )

    assert [(event.tick_index, event.kind, event.detail) for event in focus_events] == [
        (12, "debug_note", "b"),
        (15, "debug_note", "c"),
    ]
