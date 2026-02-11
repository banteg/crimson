from __future__ import annotations

from grim.geom import Vec2

from crimson.original import divergence_bisect
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)


def _step_crt_state(state: int, calls: int) -> int:
    value = int(state) & 0xFFFFFFFF
    for _ in range(max(0, int(calls))):
        value = (value * 214013 + 2531011) & 0xFFFFFFFF
    return value


def _crt_rand_values(state: int, calls: int) -> list[int]:
    value = int(state) & 0xFFFFFFFF
    out: list[int] = []
    for _ in range(max(0, int(calls))):
        value = (value * 214013 + 2531011) & 0xFFFFFFFF
        out.append((value >> 16) & 0x7FFF)
    return out


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


def test_binary_search_first_bad_tick() -> None:
    first = divergence_bisect._binary_search_first_bad_tick(
        start_tick=0,
        end_tick=32,
        is_bad=lambda tick: int(tick) >= 11,
    )
    assert first == 11

    none = divergence_bisect._binary_search_first_bad_tick(
        start_tick=0,
        end_tick=32,
        is_bad=lambda _tick: False,
    )
    assert none is None


def test_build_repro_tick_row_includes_rng_stream_and_branch_events() -> None:
    start = 0x55667788
    values = _crt_rand_values(start, 3)
    after_three = _step_crt_state(start, 3)

    expected = _checkpoint(
        tick=25,
        rng_marks={
            "rand_calls": 3,
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )
    actual = _checkpoint(
        tick=25,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )
    raw = {
        "rng_rand_calls": 3,
        "rng_head_len": 3,
        "rng_stream_rows": [
            {"tick_call_index": 1, "value_15": values[0], "branch_id": "0x00420fd7", "caller_static": "0x00420fd7"},
            {
                "tick_call_index": 2,
                "value_15": values[1] ^ 1,
                "branch_id": "0x00420fd7",
                "caller_static": "0x00420fd7",
            },
            {"tick_call_index": 3, "value_15": values[2], "branch_id": "0x00420fd7", "caller_static": "0x00420fd7"},
        ],
        "creature_damage_head": [{"creature_index": 3, "caller_static": "0x004207c0"}],
        "projectile_find_query_head": [{"caller_static": "0x00420e52"}],
        "projectile_find_hit_head": [{"caller_static": "0x00420fd7"}],
    }

    row = divergence_bisect._build_repro_tick_row(
        tick=25,
        expected=expected,
        actual=actual,
        raw=raw,
        rng_row_limit=8,
        branch_event_limit=4,
    )

    assert int(row["tick"]) == 25
    align = row["rng_stream_alignment"]
    assert isinstance(align, dict)
    assert int(align["first_mismatch_idx"]) == 1
    assert align["first_mismatch_reason"] == "value"
    assert align["first_mismatch_capture_branch_id"] == "0x00420fd7"
    capture_rows = row["capture_rng_stream_rows"]
    assert isinstance(capture_rows, list)
    assert str(capture_rows[0]["branch_id"]) == "0x00420fd7"
    branch_events = row["capture_branch_events"]
    assert isinstance(branch_events, dict)
    assert branch_events["creature_damage_head"] == [{"creature_index": 3, "caller_static": "0x004207c0"}]
