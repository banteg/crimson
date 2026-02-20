from __future__ import annotations

import copy
from pathlib import Path

import msgspec

from crimson.original.schema import CaptureEventHead, CaptureFile, CaptureTick
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from grim.geom import Vec2
from tests.builders.capture import (
    build_capture_event_head_bonus_apply,
    build_capture_event_head_state_transition,
    build_capture_event_head_weapon_assign,
    build_capture_file,
    build_capture_tick,
)


def _load_report_module():
    from crimson.original import divergence_report

    return divergence_report


def _capture_tick(
    tick: int,
    *,
    level: int,
    weapon_id: int,
    experience: int,
    perk_pairs: list[list[int]],
    event_heads: list[CaptureEventHead],
) -> CaptureTick:
    tick_obj = build_capture_tick(tick_index=int(tick), elapsed_ms=int(tick) * 16)

    checkpoint = tick_obj.checkpoint
    checkpoint.tick_index = int(tick)
    checkpoint.state_hash = f"s{tick}"
    checkpoint.command_hash = f"c{tick}"
    checkpoint.score_xp = int(experience)
    checkpoint.players[0].pos.x = 0.0
    checkpoint.players[0].pos.y = 0.0
    checkpoint.players[0].weapon_id = int(weapon_id)
    checkpoint.players[0].ammo = 12.0
    checkpoint.players[0].experience = int(experience)
    checkpoint.players[0].level = int(level)
    checkpoint.perk.player_nonzero_counts = [[list(map(int, pair)) for pair in perk_pairs]]

    tick_obj.event_heads = list(event_heads)
    return tick_obj


def _capture_obj(*, ticks: list[CaptureTick]) -> CaptureFile:
    return build_capture_file(ticks=ticks, session_id="s")


def _write_capture_stream(path: Path, capture: CaptureFile) -> None:
    meta_capture = copy.deepcopy(capture)
    meta_capture.ticks = []
    rows = [msgspec.json.encode({"event": "capture_meta", "capture": meta_capture}).decode("utf-8")]
    rows.extend(msgspec.json.encode({"event": "tick", "tick": tick}).decode("utf-8") for tick in capture.ticks)
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
                    build_capture_event_head_bonus_apply(
                        player_index=0,
                        bonus_id=3,
                        entry_state=None,
                        amount_i32=12,
                        amount_f32=12.0,
                    ),
                    build_capture_event_head_weapon_assign(
                        player_index=0,
                        weapon_id=12,
                        weapon_before=1,
                        weapon_after=12,
                    ),
                    build_capture_event_head_state_transition(
                        target_state=6,
                        before_id=9,
                        after_id=6,
                    ),
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
        ],
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
                ),
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
                ),
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
