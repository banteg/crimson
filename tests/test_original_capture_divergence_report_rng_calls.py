from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.original.schema import (
    CaptureCounterEntry,
    CaptureEventCounts,
    CaptureEventHead,
    CaptureFile,
    CaptureInputPlayerKeys,
    CaptureRngCallerCount,
    CaptureRngHeadEntry,
    CaptureSpawnDiagnostics,
    CaptureTick,
)
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from grim.geom import Vec2
from tests.builders.capture import (
    build_capture_bonus_sample,
    build_capture_counter_entry,
    build_capture_creature_sample,
    build_capture_event_head_projectile_find_hit,
    build_capture_event_head_projectile_find_query,
    build_capture_file,
    build_capture_projectile_sample,
    build_capture_rng_head_entry,
    build_capture_secondary_projectile_sample,
    build_capture_tick,
)


def _load_report_module():
    from crimson.original import divergence_report

    return divergence_report


_DEFAULT_CAPTURE_TICK = build_capture_tick(tick_index=0, elapsed_ms=0)
_DEFAULT_CAPTURE_RNG_HEAD_ENTRY = build_capture_rng_head_entry()
_DEFAULT_CAPTURE_CREATURE_SAMPLE = build_capture_creature_sample()
_DEFAULT_CAPTURE_PROJECTILE_SAMPLE = build_capture_projectile_sample()
_DEFAULT_CAPTURE_SECONDARY_PROJECTILE_SAMPLE = build_capture_secondary_projectile_sample()
_DEFAULT_CAPTURE_BONUS_SAMPLE = build_capture_bonus_sample()


def _replace_capture_struct[T: msgspec.Struct](row: T, **kwargs: object) -> T:
    return msgspec.structs.replace(row, **kwargs)


def _snapshot_globals(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.before.globals, **kwargs)


def _snapshot_status(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.before.status, **kwargs)


def _snapshot_input(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.before.input, **kwargs)


def _snapshot_input_bindings(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.before.input_bindings, **kwargs)


def _timing_diagnostics(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.checkpoint.debug.timing, **kwargs)


def _spawn_diagnostics(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.checkpoint.debug.spawn, **kwargs)


def _rng_diagnostics(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.checkpoint.debug.rng, **kwargs)


def _player_fire_diagnostics(**kwargs: object):
    row = _DEFAULT_CAPTURE_TICK.checkpoint.debug.player_fire
    if row is None:
        assert not kwargs
        return None
    return _replace_capture_struct(row, **kwargs)


def _event_counts_dict(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.event_counts, **kwargs)


def _rng_head_entry(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_RNG_HEAD_ENTRY, **kwargs)


def _rng_summary_dict(**kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.rng, **kwargs)


def _input_player_keys(player_index: int, **kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_TICK.input_player_keys[0], player_index=int(player_index), **kwargs)


def _sample_creature(index: int, **kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_CREATURE_SAMPLE, index=int(index), **kwargs)


def _sample_projectile(index: int, **kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_PROJECTILE_SAMPLE, index=int(index), **kwargs)


def _sample_secondary_projectile(index: int, **kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_SECONDARY_PROJECTILE_SAMPLE, index=int(index), **kwargs)


def _sample_bonus(index: int, **kwargs: object):
    return _replace_capture_struct(_DEFAULT_CAPTURE_BONUS_SAMPLE, index=int(index), **kwargs)


def _rng_caller_count(*, caller_static: str, calls: int) -> CaptureRngCallerCount:
    return CaptureRngCallerCount(caller_static=str(caller_static), calls=int(calls))


def _event_heads(rows: list[CaptureEventHead]) -> list[CaptureEventHead]:
    return list(rows)


def _spawn_top_caller_rows(rows: list[CaptureCounterEntry]) -> list[CaptureCounterEntry]:
    return list(rows)


def _capture_tick(
    *,
    tick: int,
    rng_rand_calls: int = 0,
    rng_head: list[CaptureRngHeadEntry] | None = None,
    rng_callers: list[CaptureRngCallerCount] | None = None,
    event_counts: CaptureEventCounts | None = None,
    spawn: CaptureSpawnDiagnostics | None = None,
    event_heads: list[CaptureEventHead] | None = None,
    sample_counts: dict[str, int] | None = None,
    input_player_keys: list[CaptureInputPlayerKeys] | None = None,
) -> CaptureTick:
    rng_head_rows = copy.deepcopy(rng_head) if rng_head is not None else []
    rng_caller_rows = copy.deepcopy(rng_callers) if rng_callers is not None else []
    counts_row = copy.deepcopy(event_counts) if event_counts is not None else copy.deepcopy(_DEFAULT_CAPTURE_TICK.event_counts)
    spawn_row = copy.deepcopy(spawn) if spawn is not None else copy.deepcopy(_DEFAULT_CAPTURE_TICK.checkpoint.debug.spawn)
    event_head_rows = copy.deepcopy(event_heads) if event_heads is not None else []
    input_key_rows = (
        copy.deepcopy(input_player_keys) if input_player_keys is not None else [copy.deepcopy(_DEFAULT_CAPTURE_TICK.input_player_keys[0])]
    )
    sample_counts_row: dict[str, int] = {
        "creatures": 0,
        "projectiles": 0,
        "secondary_projectiles": 0,
        "bonuses": 0,
    }
    if sample_counts is not None:
        for key, value in sample_counts.items():
            sample_counts_row[str(key)] = int(value)

    tick_obj = build_capture_tick(tick_index=int(tick), elapsed_ms=int(tick) * 16)
    checkpoint = tick_obj.checkpoint
    checkpoint.state_hash = f"s{tick}"
    checkpoint.command_hash = f"c{tick}"
    checkpoint.players = []

    rng_marks = checkpoint.rng_marks
    rng_marks.rand_calls = int(rng_rand_calls)
    rng_marks.rand_hash = ""
    rng_marks.rand_last = None
    rng_marks.rand_head = rng_head_rows
    rng_marks.rand_callers = rng_caller_rows
    rng_marks.rand_caller_overflow = 0
    rng_marks.rand_seq_first = None
    rng_marks.rand_seq_last = None
    rng_marks.rand_seed_epoch_enter = None
    rng_marks.rand_seed_epoch_last = None
    rng_marks.rand_outside_before_calls = 0
    rng_marks.rand_outside_before_dropped = 0
    rng_marks.rand_outside_before_head = []
    rng_marks.rand_mirror_mismatch_total = 0
    rng_marks.rand_mirror_unknown_total = 0

    checkpoint_debug = checkpoint.debug
    checkpoint_debug.sampling_phase = ""
    checkpoint_debug.timing = _timing_diagnostics()
    checkpoint_debug.spawn = spawn_row
    checkpoint_debug.rng = _rng_diagnostics()
    checkpoint_debug.perk_apply_outside_before.calls = 0
    checkpoint_debug.perk_apply_outside_before.dropped = 0
    checkpoint_debug.perk_apply_outside_before.head = []
    checkpoint_debug.creature_lifecycle = None
    checkpoint_debug.player_fire = _player_fire_diagnostics()
    checkpoint_debug.before_players = []
    checkpoint_debug.before_status.quest_unlock_index = 0
    checkpoint_debug.before_status.quest_unlock_index_full = 0

    tick_obj.event_counts = counts_row
    tick_obj.event_heads = event_head_rows
    tick_obj.input_player_keys = input_key_rows
    tick_obj.rng = _rng_summary_dict(calls=int(rng_rand_calls), head=rng_head_rows, callers=rng_caller_rows)
    tick_obj.input_approx = []

    diagnostics = tick_obj.diagnostics
    diagnostics.sampling_phase = ""
    diagnostics.timing = _timing_diagnostics()
    diagnostics.spawn = _spawn_diagnostics()
    diagnostics.rng = _rng_diagnostics()
    diagnostics.perk_apply_outside_before.calls = 0
    diagnostics.perk_apply_outside_before.dropped = 0
    diagnostics.perk_apply_outside_before.head = []
    diagnostics.creature_lifecycle = None
    diagnostics.player_fire = _player_fire_diagnostics()

    before = tick_obj.before
    before.globals = _snapshot_globals()
    before.status = _snapshot_status()
    before.player_count = 1
    before.players = []
    before.input = _snapshot_input()
    before.input_bindings = _snapshot_input_bindings()

    after = tick_obj.after
    after.globals = _snapshot_globals()
    after.status = _snapshot_status()
    after.player_count = 1
    after.players = []
    after.input = _snapshot_input()
    after.input_bindings = _snapshot_input_bindings()

    samples = tick_obj.samples
    samples.creatures = [_sample_creature(index=i) for i in range(max(0, int(sample_counts_row["creatures"])))]
    samples.projectiles = [_sample_projectile(index=i) for i in range(max(0, int(sample_counts_row["projectiles"])))]
    samples.secondary_projectiles = [
        _sample_secondary_projectile(index=i) for i in range(max(0, int(sample_counts_row["secondary_projectiles"])))
    ]
    samples.bonuses = [_sample_bonus(index=i) for i in range(max(0, int(sample_counts_row["bonuses"])))]
    return tick_obj


def _write_capture_stream(path: Path, capture: CaptureFile) -> None:
    meta_capture = copy.deepcopy(capture)
    meta_capture.ticks = []
    rows = [msgspec.json.encode({"event": "capture_meta", "capture": meta_capture}).decode("utf-8")]
    rows.extend(msgspec.json.encode({"event": "tick", "tick": tick}).decode("utf-8") for tick in capture.ticks)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


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
    kills: int = 0,
    creature_count: int = 0,
    deaths: list[ReplayDeathLedgerEntry] | None = None,
    events: ReplayEventSummary | None = None,
) -> ReplayCheckpoint:
    if "after_wave_spawns" in rng_marks:
        rng_state = int(rng_marks["after_wave_spawns"])
    elif "after_world_step" in rng_marks:
        rng_state = int(rng_marks["after_world_step"])
    else:
        rng_state = 0
    return ReplayCheckpoint(
        tick_index=int(tick),
        rng_state=rng_state,
        elapsed_ms=0,
        score_xp=0,
        kills=int(kills),
        creature_count=int(creature_count),
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
        state_hash="state",
        command_hash="cmd",
        rng_marks=dict(rng_marks),
        deaths=list(deaths or []),
        perk=ReplayPerkSnapshot(),
        events=events if events is not None else ReplayEventSummary(),
    )


def test_run_actual_checkpoints_quest_uses_capture_inter_tick_rand_draw_overrides(
    mocker,
) -> None:
    report = _load_report_module()
    replay = SimpleNamespace(
        header=SimpleNamespace(
            game_mode_id=int(GameMode.QUESTS),
            tick_rate=60,
        ),
    )
    seen_inter_tick_rand_draws = -1
    seen_inter_tick_rand_draws_by_tick: dict[int, int] = {}

    class _Stop(RuntimeError):
        pass

    mocker.patch.object(
        report,
        "convert_capture_to_checkpoints",
        side_effect=lambda _capture: SimpleNamespace(checkpoints=[]),
    )
    mocker.patch.object(
        report,
        "convert_capture_to_replay",
        side_effect=lambda _capture, seed=None, aim_scheme_overrides_by_player=None: replay,
    )
    mocker.patch.object(
        report,
        "build_capture_dt_frame_overrides",
        side_effect=lambda _capture, tick_rate: {},
    )
    mocker.patch.object(
        report,
        "build_capture_dt_frame_ms_i32_overrides",
        side_effect=lambda _capture: {},
    )
    mocker.patch.object(
        report,
        "build_capture_inter_tick_rand_draws_overrides",
        side_effect=lambda _capture: {0: 24021, 1: 1},
    )

    def _fake_run_quest_replay(*_args: object, **kwargs: object):
        nonlocal seen_inter_tick_rand_draws, seen_inter_tick_rand_draws_by_tick
        inter_tick_draws_obj = kwargs["inter_tick_rand_draws"]
        assert isinstance(inter_tick_draws_obj, int)
        seen_inter_tick_rand_draws = int(inter_tick_draws_obj)
        draws_by_tick_obj = kwargs["inter_tick_rand_draws_by_tick"]
        assert isinstance(draws_by_tick_obj, dict)
        seen_inter_tick_rand_draws_by_tick = {}
        for key, value in draws_by_tick_obj.items():
            assert isinstance(key, int)
            assert isinstance(value, int)
            seen_inter_tick_rand_draws_by_tick[key] = value
        raise _Stop("stop after capturing kwargs")

    mocker.patch.object(report, "run_quest_replay", side_effect=_fake_run_quest_replay)

    with pytest.raises(_Stop):
        report._run_actual_checkpoints(
            object(),
            max_ticks=None,
            seed=None,
            inter_tick_rand_draws=1,
        )

    assert seen_inter_tick_rand_draws == 1
    assert seen_inter_tick_rand_draws_by_tick == {0: 24021, 1: 1}


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


def test_actual_rand_calls_prefers_non_stale_after_mark() -> None:
    report = _load_report_module()
    start = 0x3AB51475
    after_world = _step_crt_state(start, 36)

    ckpt = _checkpoint(
        tick=570,
        rng_marks={
            "before_world_step": start,
            "before_events": start,
            "after_events": start,
            "ws_after_creatures": start,
            "ws_after_projectiles": start,
            "ws_after_secondary_projectiles": start,
            "ws_after_death_sfx": start,
            "after_world_step": after_world,
            "after_stage_spawns": start,
            "after_wave_spawns": start,
        },
    )

    assert report._actual_rand_calls_for_checkpoint(ckpt) == 36
    assert report._rng_changed(ckpt) is True


def test_actual_rand_calls_prefers_late_event_after_mark() -> None:
    report = _load_report_module()
    start = 0xE199E00E
    after_world = _step_crt_state(start, 1)
    after_post_events = _step_crt_state(start, 11)

    ckpt = _checkpoint(
        tick=1247,
        rng_marks={
            "before_events": start,
            "before_world_step": start,
            "after_world_step": after_world,
            "after_stage_spawns": after_world,
            "after_wave_spawns": after_world,
            "before_post_events": after_world,
            "after_events": after_post_events,
            "after_post_events": after_post_events,
        },
    )

    assert report._actual_rand_calls_for_checkpoint(ckpt) == 11
    assert report._rng_changed(ckpt) is True


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
            ),
        ],
    )

    rows = report._build_window_rows(
        expected_by_tick={5: expected_ckpt},
        actual_by_tick={5: actual_ckpt},
        raw_debug_by_tick={5: _capture_tick(tick=5, rng_rand_calls=2)},
        focus_tick=5,
        window=0,
    )

    assert len(rows) == 1
    row = rows[0]
    assert int(row["expected_rand_calls"]) == 2
    assert int(row["actual_rand_calls"]) == 10
    assert int(row["rand_calls_delta"]) == 8
    assert int(row["actual_deaths"]) == 1
    assert int(row["rng_stream_prefix_match"]) == 0
    assert int(row["rng_stream_compared"]) == 0
    assert row["rng_stream_first_mismatch_idx"] is None


def test_window_rows_include_rng_stream_mismatch_details() -> None:
    report = _load_report_module()
    start = 0x0BADF00D
    values = _crt_rand_values(start, 3)
    after = _step_crt_state(start, 3)

    expected_ckpt = _checkpoint(
        tick=6,
        rng_marks={"rand_calls": 3},
    )
    actual_ckpt = _checkpoint(
        tick=6,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after,
            "after_wave_spawns": after,
        },
    )

    rows = report._build_window_rows(
        expected_by_tick={6: expected_ckpt},
        actual_by_tick={6: actual_ckpt},
        raw_debug_by_tick={
            6: _capture_tick(
                tick=6,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1] ^ 1, branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
            ),
        },
        focus_tick=6,
        window=0,
    )

    assert len(rows) == 1
    row = rows[0]
    assert int(row["rng_stream_prefix_match"]) == 1
    assert int(row["rng_stream_compared"]) == 3
    assert int(row["rng_stream_first_mismatch_idx"]) == 1
    assert row["rng_stream_first_mismatch_reason"] == "value"
    assert row["rng_stream_first_mismatch_capture_branch_id"] == "0x00420fd7"
    assert int(row["rng_stream_missing_tail"]) == 0


def test_find_first_divergence_prefers_rng_stream_before_checkpoint_fields() -> None:
    report = _load_report_module()
    start = 0x10203040
    values = _crt_rand_values(start, 2)
    after_two = _step_crt_state(start, 2)

    expected_ckpt = _checkpoint(
        tick=9,
        rng_marks={
            "rand_calls": 2,
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )
    actual_ckpt = _checkpoint(
        tick=9,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    divergence = report._find_first_divergence(
        [expected_ckpt],
        [actual_ckpt],
        float_abs_tol=1e-3,
        max_field_diffs=16,
        raw_debug_by_tick={
            9: _capture_tick(
                tick=9,
                rng_head=[
                    _rng_head_entry(
                        seq=11,
                        tick_call_index=1,
                        value_15=values[0] ^ 1,
                        state_before_u32=start,
                        state_after_u32=_step_crt_state(start, 1),
                        branch_id="0x00420fd7",
                        caller_static="0x00420fd7",
                    ),
                    _rng_head_entry(
                        seq=12,
                        tick_call_index=2,
                        value_15=values[1],
                        state_before_u32=_step_crt_state(start, 1),
                        state_after_u32=after_two,
                        branch_id="0x00420fd7",
                        caller_static="0x00420fd7",
                    ),
                ],
            ),
        },
    )

    assert divergence is not None
    assert int(divergence.tick_index) == 9
    assert divergence.kind == "rng_stream_mismatch"
    assert divergence.field_diffs == tuple()


def test_find_first_divergence_ignores_one_tick_kills_lag() -> None:
    report = _load_report_module()

    expected = [
        _checkpoint(tick=5169, rng_marks={"rand_calls": 0}, kills=486, creature_count=51),
        _checkpoint(tick=5170, rng_marks={"rand_calls": 0}, kills=487, creature_count=51),
        _checkpoint(tick=5171, rng_marks={"rand_calls": 0}, kills=487, creature_count=51),
    ]
    actual = [
        _checkpoint(tick=5169, rng_marks={"rand_calls": 0}, kills=486, creature_count=51),
        _checkpoint(tick=5170, rng_marks={"rand_calls": 0}, kills=486, creature_count=51),
        _checkpoint(tick=5171, rng_marks={"rand_calls": 0}, kills=487, creature_count=51),
    ]

    divergence = report._find_first_divergence(
        expected,
        actual,
        float_abs_tol=1e-3,
        max_field_diffs=16,
    )

    assert divergence is None


def test_find_first_divergence_allows_one_tick_creature_count_sample_lag() -> None:
    report = _load_report_module()

    expected = [
        _checkpoint(tick=5178, rng_marks={"rand_calls": 0}, creature_count=52),
        _checkpoint(tick=5179, rng_marks={"rand_calls": 0}, creature_count=52),
        _checkpoint(tick=5180, rng_marks={"rand_calls": 0}, creature_count=51),
    ]
    actual = [
        _checkpoint(tick=5178, rng_marks={"rand_calls": 0}, creature_count=51),
        _checkpoint(tick=5179, rng_marks={"rand_calls": 0}, creature_count=51),
        _checkpoint(tick=5180, rng_marks={"rand_calls": 0}, creature_count=51),
    ]

    divergence = report._find_first_divergence(
        expected,
        actual,
        float_abs_tol=1e-3,
        max_field_diffs=16,
        capture_sample_creature_counts={5178: 52, 5179: 51, 5180: 51},
    )

    assert divergence is None


def test_load_raw_tick_debug_tracks_sample_coverage(tmp_path: Path) -> None:
    report = _load_report_module()
    capture_path = tmp_path / "capture.json"
    tick = _capture_tick(
        tick=42,
        event_counts=_event_counts_dict(projectile_find_query=3, projectile_find_hit=2),
        spawn=_spawn_diagnostics(
            event_count_projectile_find_query=3,
            event_count_projectile_find_query_miss=1,
            event_count_projectile_find_query_owner_collision=1,
            top_projectile_find_query_callers=_spawn_top_caller_rows(
                [build_capture_counter_entry(key="0x00420e52", count=3)],
            ),
        ),
        event_heads=_event_heads(
            [
                build_capture_event_head_projectile_find_query(
                    result_kind="miss",
                    caller_static="0x00420e52",
                ),
                build_capture_event_head_projectile_find_query(
                    result_creature_index=19,
                    result_kind="owner_collision",
                    owner_collision=True,
                    caller_static="0x00420e52",
                ),
                build_capture_event_head_projectile_find_hit(
                    result_creature_index=19,
                    result_kind="hit",
                    caller_static="0x00420e52",
                    creature_index=19,
                ),
            ],
        ),
        sample_counts={"creatures": 1, "secondary_projectiles": 1},
    )
    tick.samples.creatures[0].index = 5
    tick.samples.secondary_projectiles[0].index = 7
    capture = build_capture_file(ticks=[tick], session_id="s")
    _write_capture_stream(capture_path, capture)

    raw = report._load_raw_tick_debug(capture_path, {42})
    assert 42 in raw
    tick = raw[42]
    assert len(tick.samples.creatures) == 1
    assert len(tick.samples.secondary_projectiles) == 1
    assert int(tick.samples.secondary_projectiles[0].index) == 7
    assert int(tick.samples.creatures[0].index) == 5
    assert int(tick.event_counts.projectile_find_query) == 3
    assert int(tick.checkpoint.debug.spawn.event_count_projectile_find_query_miss) == 1
    assert int(tick.checkpoint.debug.spawn.event_count_projectile_find_query_owner_collision) == 1
    assert [
        {"key": str(item.key), "count": int(item.count)}
        for item in tick.checkpoint.debug.spawn.top_projectile_find_query_callers
    ] == [{"key": "0x00420e52", "count": 3}]


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
        raw_debug_by_tick={},
        native_ranges=tuple(),
    )
    assert any(lead.title == "Capture lacks entity samples at the focus tick" for lead in leads)


def test_investigation_leads_flag_focus_micro_head_cap() -> None:
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
        raw_debug_by_tick={
            5: _capture_tick(
                tick=5,
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
                event_counts=_event_counts_dict(creature_update_micro=128),
            ),
        },
        native_ranges=tuple(),
        capture_config={
            "creature_micro_max_head_per_tick": 128,
            "creature_micro_slots": [],
            "creature_micro_tick_start": -1,
            "creature_micro_tick_end": -1,
        },
    )

    lead = next(
        (
            item
            for item in leads
            if item.title == "Capture creature-update micro telemetry likely head-capped at focus tick"
        ),
        None,
    )
    assert lead is not None
    assert any("count=128 cap=128" in line for line in lead.evidence)


def test_divergence_category_prefers_projectile_hit_shortfall_signature() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(tick=10, rng_marks={"rand_calls": 0})
    actual_ckpt = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": 0x12345678,
            "after_world_step": 0x12345678,
            "after_wave_spawns": 0x12345678,
        },
        events=ReplayEventSummary(hit_count=1, pickup_count=0, sfx_count=0, sfx_head=[]),
    )
    divergence = report.Divergence(
        tick_index=10,
        kind="rng_stream_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    category = report._classify_divergence_category(
        divergence=divergence,
        leads=[],
        focus_raw=_capture_tick(tick=10, event_counts=_event_counts_dict(projectile_find_hit=2)),
        focus_actual_ckpt=actual_ckpt,
    )

    assert category.id == "rng.projectile_hit_resolution_shortfall"


def test_divergence_category_ignores_owner_collision_queries_for_shortfall_signature() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(tick=10, rng_marks={"rand_calls": 0})
    actual_ckpt = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": 0x12345678,
            "after_world_step": 0x12345678,
            "after_wave_spawns": 0x12345678,
        },
        events=ReplayEventSummary(hit_count=1, pickup_count=0, sfx_count=0, sfx_head=[]),
    )
    divergence = report.Divergence(
        tick_index=10,
        kind="rng_stream_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    category = report._classify_divergence_category(
        divergence=divergence,
        leads=[],
        focus_raw=_capture_tick(
            tick=10,
            event_counts=_event_counts_dict(projectile_find_hit=3),
            spawn=_spawn_diagnostics(event_count_projectile_find_query_owner_collision=2),
        ),
        focus_actual_ckpt=actual_ckpt,
    )

    assert category.id == "rng.stream_mismatch"


def test_divergence_category_marks_player_motion_precision_drift() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(tick=12, rng_marks={"rand_calls": 0})
    actual_ckpt = _checkpoint(
        tick=12,
        rng_marks={
            "before_world_step": 0x87654321,
            "after_world_step": 0x87654321,
            "after_wave_spawns": 0x87654321,
        },
    )
    divergence = report.Divergence(
        tick_index=12,
        kind="state_mismatch",
        field_diffs=(report.ReplayFieldDiff(field="players[0].pos.x", expected=10.0, actual=10.125),),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    category = report._classify_divergence_category(
        divergence=divergence,
        leads=[],
        focus_raw=None,
        focus_actual_ckpt=actual_ckpt,
    )

    assert category.id == "state.player_motion_precision_drift"


def test_find_first_rng_head_shortfall_detects_pre_focus_gap() -> None:
    report = _load_report_module()
    start = 0x10203040
    values = _crt_rand_values(start, 3)
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
            7: _capture_tick(
                tick=7,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[_rng_caller_count(caller_static="0x00420fd7", calls=3)],
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 7
    assert int(shortfall["expected_head_len"]) == 3
    assert int(shortfall["actual_rand_calls"]) == 2
    assert int(shortfall["missing_draws"]) == 1


def test_find_first_rng_head_shortfall_detects_stream_value_mismatch() -> None:
    report = _load_report_module()
    start = 0x21436587
    values = _crt_rand_values(start, 3)
    after_three = _step_crt_state(start, 3)

    expected_ckpt = _checkpoint(
        tick=8,
        rng_marks={"rand_calls": 3},
    )
    actual_ckpt = _checkpoint(
        tick=8,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )

    shortfall = report._find_first_rng_head_shortfall(
        expected_by_tick={8: expected_ckpt},
        actual_by_tick={8: actual_ckpt},
        raw_debug_by_tick={
            8: _capture_tick(
                tick=8,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0] ^ 1, branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[_rng_caller_count(caller_static="0x00420fd7", calls=3)],
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 8
    assert int(shortfall["stream_first_mismatch_idx"]) == 0
    assert int(shortfall["stream_first_mismatch_capture"]) != int(shortfall["stream_first_mismatch_actual"])
    assert int(shortfall["stream_missing_tail"]) == 0
    assert int(shortfall["missing_draws"]) == 0


def test_investigation_leads_include_rng_head_shortfall() -> None:
    report = _load_report_module()
    start = 0x55667788
    values = _crt_rand_values(start, 3)
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
            7: _capture_tick(
                tick=7,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[_rng_caller_count(caller_static="0x00420fd7", calls=3)],
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
            10: _capture_tick(
                tick=10,
                rng_rand_calls=0,
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
        },
        native_ranges=(report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),),
    )

    lead = next(
        (item for item in leads if item.title == "Pre-focus RNG-head shortfall indicates missing RNG-consuming branch"),
        None,
    )
    assert lead is not None
    assert "projectile_update" in lead.native_functions


def test_investigation_leads_include_rng_stream_mismatch() -> None:
    report = _load_report_module()
    start = 0x55667788
    values = _crt_rand_values(start, 3)
    after_three = _step_crt_state(start, 3)

    expected_shortfall = _checkpoint(
        tick=7,
        rng_marks={"rand_calls": 3},
    )
    actual_shortfall = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )

    expected_focus = _checkpoint(
        tick=10,
        rng_marks={"rand_calls": 0},
    )
    actual_focus = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": after_three,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
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
            7: _capture_tick(
                tick=7,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1] ^ 1, branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[_rng_caller_count(caller_static="0x00420fd7", calls=3)],
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
            10: _capture_tick(
                tick=10,
                rng_rand_calls=0,
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
        },
        native_ranges=(report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),),
    )

    lead = next(
        (item for item in leads if item.title == "Pre-focus RNG stream mismatch indicates branch divergence"), None,
    )
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
            12: _capture_tick(
                tick=12,
                event_counts=_event_counts_dict(projectile_find_hit=6, projectile_find_query=8),
                spawn=_spawn_diagnostics(
                    event_count_projectile_find_query_miss=2,
                    event_count_projectile_find_query_owner_collision=1,
                    top_projectile_find_query_callers=_spawn_top_caller_rows(
                        [build_capture_counter_entry(key="0x00420e52", count=8)],
                    ),
                    top_projectile_find_hit_callers=_spawn_top_caller_rows(
                        [build_capture_counter_entry(key="0x00420fd7", count=5)],
                    ),
                ),
                event_heads=_event_heads(
                    [
                        build_capture_event_head_projectile_find_hit(
                            result_creature_index=19,
                            result_kind="hit",
                            caller_static="0x00420fd7",
                            creature_index=19,
                            corpse_hit=True,
                        ),
                    ],
                ),
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 12
    assert int(shortfall["capture_hits"]) == 5
    assert int(shortfall["capture_hits_raw"]) == 6
    assert int(shortfall["actual_hits"]) == 4
    assert int(shortfall["missing_hits"]) == 1
    assert int(shortfall["query_counts"]) == 8
    assert int(shortfall["query_miss_count"]) == 2
    assert int(shortfall["query_owner_collision_count"]) == 1


def test_find_first_projectile_hit_shortfall_ignores_owner_collision_queries() -> None:
    report = _load_report_module()
    actual_ckpt = _checkpoint(
        tick=12,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
        events=ReplayEventSummary(hit_count=3, pickup_count=0, sfx_count=0, sfx_head=[]),
    )

    shortfall = report._find_first_projectile_hit_shortfall(
        actual_by_tick={12: actual_ckpt},
        raw_debug_by_tick={
            12: _capture_tick(
                tick=12,
                event_counts=_event_counts_dict(projectile_find_hit=5),
                spawn=_spawn_diagnostics(event_count_projectile_find_query_owner_collision=2),
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is None


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
            10: _capture_tick(
                tick=10,
                rng_rand_calls=0,
                event_counts=_event_counts_dict(projectile_find_hit=7, projectile_find_query=9),
                spawn=_spawn_diagnostics(
                    event_count_projectile_find_query_miss=2,
                    event_count_projectile_find_query_owner_collision=1,
                    top_projectile_find_query_callers=_spawn_top_caller_rows(
                        [build_capture_counter_entry(key="0x00420e52", count=9)],
                    ),
                    top_projectile_find_hit_callers=_spawn_top_caller_rows(
                        [build_capture_counter_entry(key="0x00420fd7", count=6)],
                    ),
                ),
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
                event_heads=_event_heads(
                    [
                        build_capture_event_head_projectile_find_hit(
                            result_creature_index=19,
                            result_kind="hit",
                            caller_static="0x00420fd7",
                            creature_index=19,
                            corpse_hit=True,
                        ),
                        build_capture_event_head_projectile_find_hit(
                            result_creature_index=20,
                            result_kind="hit",
                            caller_static="0x00420fd7",
                            creature_index=20,
                            corpse_hit=True,
                        ),
                    ],
                ),
            ),
        },
        native_ranges=(report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),),
    )

    lead = next(
        (item for item in leads if item.title == "Native projectile hit resolves exceed rewrite hit events"), None,
    )
    assert lead is not None
    assert "projectile_update" in lead.native_functions
