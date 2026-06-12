from __future__ import annotations

from pathlib import Path

import msgspec

from .channel_compare import compare_entity_samples, compare_rng_stream, compare_sim_state, compare_timing_samples
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


def _is_capture_impl(impl: str) -> bool:
    return str(impl) == "frida_original"


def _first_mismatch(
    *,
    pairs: list[_TickPair],
    tick_end: int | None = None,
    capture_compare: bool = False,
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
        tick_mismatches: list[BuiltinObject] = []

        expected = checkpoint_channel_required(pair.expected_row)
        actual = checkpoint_channel_required(pair.actual_row)
        exp_rng_stream = rng_stream_channel_required(pair.expected_row)
        act_rng_stream = rng_stream_channel_required(pair.actual_row)

        checkpoint_diff = checkpoint_deepdiff(expected, actual, capture_compare=capture_compare)
        if checkpoint_diff is not None:
            tick_mismatches.append(
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

        rng_ok, rng_detail = compare_rng_stream(exp_rng_stream, act_rng_stream)
        if not rng_ok:
            tick_mismatches.append(
                _tick_mismatch_row(
                    kind="rng_stream_mismatch",
                    channel="rng_stream",
                    detail=rng_detail,
                ),
            )

        expected_sim_state = sim_state_channel_required(pair.expected_row)
        actual_sim_state = sim_state_channel_required(pair.actual_row)
        sim_ok, sim_detail = compare_sim_state(
            expected_sim_state,
            actual_sim_state,
        )
        if not sim_ok:
            tick_mismatches.append(
                _tick_mismatch_row(
                    kind="sim_state_mismatch",
                    channel="sim_state",
                    detail=sim_detail,
                ),
            )

        expected_entity_samples = entity_samples_channel_required(pair.expected_row)
        actual_entity_samples = entity_samples_channel_required(pair.actual_row)
        entities_ok, entities_detail = compare_entity_samples(
            expected_entity_samples,
            actual_entity_samples,
        )
        if not entities_ok:
            tick_mismatches.append(
                _tick_mismatch_row(
                    kind="entity_sample_mismatch",
                    channel="entity_samples",
                    detail=entities_detail,
                ),
            )

        expected_timing_samples = timing_samples_channel_required(pair.expected_row)
        actual_timing_samples = timing_samples_channel_required(pair.actual_row)
        timing_ok, timing_detail = compare_timing_samples(
            expected_timing_samples,
            actual_timing_samples,
        )
        if not timing_ok:
            tick_mismatches.append(
                _tick_mismatch_row(
                    kind="timing_samples_mismatch",
                    channel="timing_samples",
                    detail=timing_detail,
                ),
            )

        if tick_mismatches:
            return (
                checked_count,
                TraceMismatch(
                    kind="tick_mismatch",
                    tick_index=tick,
                    detail={
                        "mismatch_count": len(tick_mismatches),
                        "mismatches": tick_mismatches,
                    },
                ),
            )

    return checked_count, None


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


def diff_traces(
    *,
    expected_trace_path: Path,
    actual_trace_path: Path,
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> TraceDiffReport:
    with TraceReader(Path(expected_trace_path)) as expected_trace, TraceReader(Path(actual_trace_path)) as actual_trace:
        pairs = _load_pairs(
            expected_trace=expected_trace,
            actual_trace=actual_trace,
            tick_start=tick_start,
            tick_end=tick_end,
        )
        capture_compare = _is_capture_impl(expected_trace.meta.producer.impl) or _is_capture_impl(
            actual_trace.meta.producer.impl,
        )
        try:
            checked_count, mismatch = _first_mismatch(
                pairs=pairs,
                tick_end=tick_end,
                capture_compare=capture_compare,
            )
        except TraceError as exc:
            raise ValueError(str(exc)) from exc
        return TraceDiffReport(
            ok=(mismatch is None),
            checked_count=checked_count,
            tick_start=tick_start,
            tick_end=tick_end,
            mismatch=mismatch,
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
        pairs = _load_pairs(
            expected_trace=expected_trace,
            actual_trace=actual_trace,
            tick_start=tick_start,
            tick_end=tick_end,
        )
        if not pairs:
            return TraceBisectReport(
                ok=True,
                first_bad_tick=None,
                checked_count=0,
                mismatch=None,
                window_start=None,
                window_end=None,
            )

        capture_compare = _is_capture_impl(expected_trace.meta.producer.impl) or _is_capture_impl(
            actual_trace.meta.producer.impl,
        )
        end_tick_bound = pairs[-1].tick_index if tick_end is None else tick_end
        try:
            checked_count, mismatch = _first_mismatch(
                pairs=pairs,
                tick_end=end_tick_bound,
                capture_compare=capture_compare,
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
            "schema_version": 1,
            "status": ("ok" if report.ok else "diverged"),
            "checked_count": report.checked_count,
            "tick_start": report.tick_start,
            "tick_end": report.tick_end,
            "mismatch": mismatch_to_json(report.mismatch),
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
