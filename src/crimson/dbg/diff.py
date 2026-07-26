from __future__ import annotations

from pathlib import Path

import msgspec

from .channel_compare import (
    compare_entity_samples,
    compare_replay_step,
    compare_rng_stream,
    compare_sim_state,
    compare_timing_samples,
)
from .channel_helpers import (
    checkpoint_channel_required,
    entity_samples_channel_required,
    rng_stream_channel_required,
    sim_state_channel_required,
    timing_samples_channel_required,
)
from .checkpoint_diff import checkpoint_deepdiff
from .payloads import BuiltinObject, to_builtin_object
from .schema import TickRecord
from .trace import TraceError, TraceReader


class TraceMismatch(msgspec.Struct, frozen=True):
    kind: str
    tick_index: int
    detail: BuiltinObject | None = None


class TraceDiffReport(msgspec.Struct, frozen=True):
    ok: bool
    checked_count: int
    tick_start: int | None
    tick_end: int | None
    mismatch: TraceMismatch | None = None
    compared_count: int = 0
    channel_first_mismatches: dict[str, TraceMismatch] = msgspec.field(default_factory=dict)
    channel_first_diagnostics: dict[str, TraceMismatch] = msgspec.field(default_factory=dict)


class TraceBisectReport(msgspec.Struct, frozen=True):
    ok: bool
    first_bad_tick: int | None
    checked_count: int
    mismatch: TraceMismatch | None
    window_start: int | None = None
    window_end: int | None = None


class _TickPair(msgspec.Struct, frozen=True):
    tick_index: int
    expected_row: TickRecord | None
    actual_row: TickRecord | None


def _tick_mismatch_row(*, kind: str, channel: str, detail: BuiltinObject | None) -> BuiltinObject:
    return to_builtin_object(
        {
            "kind": str(kind),
            "channel": str(channel),
            "detail": (None if detail is None else to_builtin_object(detail, field=f"{channel}.detail")),
        },
        field=f"{channel}.mismatch",
    )


def _compare_tick_channels(expected_row: TickRecord, actual_row: TickRecord) -> tuple[list[BuiltinObject], list[BuiltinObject]]:
    mismatches: list[BuiltinObject] = []
    diagnostics: list[BuiltinObject] = []

    replay_step_ok, replay_step_detail = compare_replay_step(
        expected_row.channels.replay_step,
        actual_row.channels.replay_step,
    )
    if not replay_step_ok:
        mismatches.append(
            _tick_mismatch_row(
                kind="replay_step_mismatch",
                channel="replay_step",
                detail=replay_step_detail,
            ),
        )

    checkpoint_diff = checkpoint_deepdiff(
        checkpoint_channel_required(expected_row),
        checkpoint_channel_required(actual_row),
    )
    if checkpoint_diff is not None:
        mismatches.append(
            _tick_mismatch_row(
                kind="checkpoint_field_mismatch",
                channel="checkpoint",
                detail={
                    "diff_count": int(checkpoint_diff.diff_count),
                    "payload": msgspec.to_builtins(checkpoint_diff.payload),
                    "pretty": str(checkpoint_diff.pretty),
                },
            ),
        )

    rng_ok, rng_detail = compare_rng_stream(
        rng_stream_channel_required(expected_row),
        rng_stream_channel_required(actual_row),
    )
    if not rng_ok:
        mismatches.append(
            _tick_mismatch_row(
                kind="rng_stream_mismatch",
                channel="rng_stream",
                detail=rng_detail,
            ),
        )
    elif rng_detail is not None:
        diagnostics.append(
            _tick_mismatch_row(
                kind="rng_caller_attribution_mismatch",
                channel="rng_stream",
                detail=rng_detail,
            ),
        )

    sim_ok, sim_detail = compare_sim_state(
        sim_state_channel_required(expected_row),
        sim_state_channel_required(actual_row),
    )
    if not sim_ok:
        mismatches.append(
            _tick_mismatch_row(kind="sim_state_mismatch", channel="sim_state", detail=sim_detail),
        )

    entities_ok, entities_detail = compare_entity_samples(
        entity_samples_channel_required(expected_row),
        entity_samples_channel_required(actual_row),
    )
    if not entities_ok:
        mismatches.append(
            _tick_mismatch_row(
                kind="entity_sample_mismatch",
                channel="entity_samples",
                detail=entities_detail,
            ),
        )

    timing_ok, timing_detail = compare_timing_samples(
        timing_samples_channel_required(expected_row),
        timing_samples_channel_required(actual_row),
    )
    if not timing_ok:
        mismatches.append(
            _tick_mismatch_row(
                kind="timing_samples_mismatch",
                channel="timing_samples",
                detail=timing_detail,
            ),
        )
    return mismatches, diagnostics


def _first_mismatch(
    *,
    pairs: list[_TickPair],
    tick_end: int | None = None,
) -> tuple[int, TraceMismatch | None]:
    checked_count = 0
    for pair in pairs:
        tick = pair.tick_index
        if tick_end is not None and tick > tick_end:
            break
        checked_count += 1
        if pair.expected_row is None or pair.actual_row is None:
            return (
                checked_count,
                TraceMismatch(
                    kind="missing_tick",
                    tick_index=tick,
                ),
            )
        tick_mismatches, _diagnostics = _compare_tick_channels(pair.expected_row, pair.actual_row)

        if tick_mismatches:
            return (
                checked_count,
                TraceMismatch(
                    kind="tick_mismatch",
                    tick_index=tick,
                    detail=to_builtin_object(
                        {
                            "mismatch_count": len(tick_mismatches),
                            "mismatches": tick_mismatches,
                        },
                        field=f"ticks[{tick}].mismatch",
                    ),
                ),
            )

    return checked_count, None


def _channel_first_results(
    *,
    pairs: list[_TickPair],
    tick_end: int | None,
) -> tuple[int, dict[str, TraceMismatch], dict[str, TraceMismatch]]:
    compared_count = 0
    mismatches: dict[str, TraceMismatch] = {}
    diagnostics: dict[str, TraceMismatch] = {}
    for pair in pairs:
        tick = int(pair.tick_index)
        if tick_end is not None and tick > int(tick_end):
            break
        compared_count += 1
        if pair.expected_row is None or pair.actual_row is None:
            mismatches.setdefault("tick", TraceMismatch(kind="missing_tick", tick_index=tick))
            continue
        tick_mismatches, tick_diagnostics = _compare_tick_channels(pair.expected_row, pair.actual_row)
        for item in tick_mismatches:
            channel = str(item.get("channel", "unknown"))
            detail = item.get("detail")
            mismatches.setdefault(
                channel,
                TraceMismatch(
                    kind=str(item.get("kind", "channel_mismatch")),
                    tick_index=tick,
                    detail=(detail if isinstance(detail, dict) else None),
                ),
            )
        for item in tick_diagnostics:
            channel = str(item.get("channel", "unknown"))
            detail = item.get("detail")
            diagnostics.setdefault(
                channel,
                TraceMismatch(
                    kind=str(item.get("kind", "channel_diagnostic")),
                    tick_index=tick,
                    detail=(detail if isinstance(detail, dict) else None),
                ),
            )
    return compared_count, mismatches, diagnostics


def _load_pairs(
    *,
    expected_trace: TraceReader,
    actual_trace: TraceReader,
    tick_start: int | None,
    tick_end: int | None,
) -> list[_TickPair]:
    expected_rows = {row.tick_index: row for row in expected_trace.iter_ticks(tick_start=tick_start, tick_end=tick_end)}
    actual_rows = {row.tick_index: row for row in actual_trace.iter_ticks(tick_start=tick_start, tick_end=tick_end)}
    all_ticks = sorted(set(expected_rows) | set(actual_rows))
    pairs: list[_TickPair] = []
    for tick in all_ticks:
        exp_row = expected_rows.get(tick)
        act_row = actual_rows.get(tick)
        pairs.append(
            _TickPair(
                tick_index=tick,
                expected_row=exp_row,
                actual_row=act_row,
            ),
        )
    return pairs


def validate_comparison_identity(expected_trace: TraceReader, actual_trace: TraceReader) -> None:
    expected = expected_trace.meta.source
    actual = actual_trace.meta.source
    required_fields = ("replay_sha256", "tick_rate", "seed", "mode_id", "player_count")
    for label, source in (("expected", expected), ("actual", actual)):
        missing = [
            field
            for field in required_fields
            if getattr(source, field) is None or (field == "replay_sha256" and not str(getattr(source, field)))
        ]
        if missing:
            raise ValueError(f"{label} trace is missing comparison identity fields: {', '.join(missing)}")
    fields = (*required_fields, "quest_level", "quest_stage_major", "quest_stage_minor")
    mismatches: list[str] = []
    for field in fields:
        expected_value = getattr(expected, field)
        actual_value = getattr(actual, field)
        if expected_value != actual_value:
            mismatches.append(f"{field}: expected={expected_value!r} actual={actual_value!r}")
    if mismatches:
        raise ValueError("trace comparison identity mismatch: " + "; ".join(mismatches))


def diff_traces(
    *,
    expected_trace_path: Path,
    actual_trace_path: Path,
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> TraceDiffReport:
    with TraceReader(Path(expected_trace_path)) as expected_trace, TraceReader(Path(actual_trace_path)) as actual_trace:
        if tick_start is not None and tick_end is not None and int(tick_start) > int(tick_end):
            raise ValueError(f"invalid tick window: start {int(tick_start)} is after end {int(tick_end)}")
        validate_comparison_identity(expected_trace, actual_trace)
        pairs = _load_pairs(
            expected_trace=expected_trace,
            actual_trace=actual_trace,
            tick_start=tick_start,
            tick_end=tick_end,
        )
        if not pairs:
            raise ValueError("trace comparison window contains no ticks")
        try:
            checked_count, mismatch = _first_mismatch(
                pairs=pairs,
                tick_end=tick_end,
            )
            compared_count, channel_mismatches, channel_diagnostics = _channel_first_results(
                pairs=pairs,
                tick_end=tick_end,
            )
        except TraceError as exc:
            raise ValueError(str(exc)) from exc
        return TraceDiffReport(
            ok=(mismatch is None),
            checked_count=checked_count,
            tick_start=tick_start,
            tick_end=tick_end,
            mismatch=mismatch,
            compared_count=compared_count,
            channel_first_mismatches=channel_mismatches,
            channel_first_diagnostics=channel_diagnostics,
        )


def bisect_traces(
    *,
    expected_trace_path: Path,
    actual_trace_path: Path,
    tick_start: int | None = None,
    tick_end: int | None = None,
    window_before: int = 12,
    window_after: int = 6,
) -> TraceBisectReport:
    with TraceReader(Path(expected_trace_path)) as expected_trace, TraceReader(Path(actual_trace_path)) as actual_trace:
        if tick_start is not None and tick_end is not None and int(tick_start) > int(tick_end):
            raise ValueError(f"invalid tick window: start {int(tick_start)} is after end {int(tick_end)}")
        validate_comparison_identity(expected_trace, actual_trace)
        pairs = _load_pairs(
            expected_trace=expected_trace,
            actual_trace=actual_trace,
            tick_start=tick_start,
            tick_end=tick_end,
        )
        if not pairs:
            raise ValueError("trace comparison window contains no ticks")

        end_tick_bound = pairs[-1].tick_index if tick_end is None else tick_end
        try:
            checked_count, mismatch = _first_mismatch(
                pairs=pairs,
                tick_end=end_tick_bound,
            )
        except TraceError as exc:
            raise ValueError(str(exc)) from exc
        if mismatch is None:
            return TraceBisectReport(
                ok=True,
                first_bad_tick=None,
                checked_count=checked_count,
                mismatch=None,
                window_start=None,
                window_end=None,
            )

        first_bad = mismatch.tick_index
        final_mismatch = mismatch
        left = first_bad - max(0, window_before)
        right = first_bad + max(0, window_after)

        return TraceBisectReport(
            ok=False,
            first_bad_tick=first_bad,
            checked_count=checked_count,
            mismatch=final_mismatch,
            window_start=left,
            window_end=right,
        )


def mismatch_to_json(mismatch: TraceMismatch | None) -> BuiltinObject | None:
    if mismatch is None:
        return None
    return to_builtin_object(
        {
            "kind": mismatch.kind,
            "tick_index": mismatch.tick_index,
            "detail": (None if mismatch.detail is None else to_builtin_object(mismatch.detail, field="mismatch.detail")),
        },
        field="mismatch_json",
    )


def diff_report_to_json(report: TraceDiffReport) -> BuiltinObject:
    return to_builtin_object(
        {
            "schema_version": 2,
            "status": ("ok" if report.ok else "diverged"),
            "checked_count": report.checked_count,
            "compared_count": report.compared_count,
            "tick_start": report.tick_start,
            "tick_end": report.tick_end,
            "mismatch": mismatch_to_json(report.mismatch),
            "channel_first_mismatches": {
                channel: mismatch_to_json(mismatch)
                for channel, mismatch in sorted(report.channel_first_mismatches.items())
            },
            "channel_first_diagnostics": {
                channel: mismatch_to_json(mismatch)
                for channel, mismatch in sorted(report.channel_first_diagnostics.items())
            },
        },
        field="diff_report",
    )


def bisect_report_to_json(report: TraceBisectReport) -> BuiltinObject:
    return to_builtin_object(
        {
            "schema_version": 1,
            "status": ("ok" if report.ok else "diverged"),
            "checked_count": report.checked_count,
            "first_bad_tick": report.first_bad_tick,
            "mismatch": mismatch_to_json(report.mismatch),
            "window_start": report.window_start,
            "window_end": report.window_end,
        },
        field="bisect_report",
    )
