from __future__ import annotations

from pathlib import Path

import msgspec

from .channel_compare import compare_entity_samples, compare_rng_stream, compare_sim_state
from .channel_helpers import (
    checkpoint_channel_required,
    entity_samples_channel_required,
    rng_stream_channel_required,
    sim_state_channel_required,
)
from .checkpoint_diff import checkpoint_deepdiff
from .schema import (
    TRACE_FORMAT_VERSION,
    TRACE_REQUIRED_CHANNELS_V3,
    TRACE_SCHEMA_VERSION,
    TickRecord,
    TraceMeta,
    channel_versions_for,
)
from .trace import TraceError, TraceReader, write_trace


class TraceMismatch(msgspec.Struct, frozen=True):
    kind: str
    tick_index: int
    detail: dict[str, object] | None = None


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
    repro_trace_path: Path | None = None


class _TickPair(msgspec.Struct, frozen=True):
    tick_index: int
    expected_row: TickRecord | None
    actual_row: TickRecord | None


def _tick_mismatch_row(*, kind: str, channel: str, detail: dict[str, object] | None) -> dict[str, object]:
    return {
        "kind": str(kind),
        "channel": str(channel),
        "detail": (None if detail is None else msgspec.to_builtins(detail)),
    }


def _first_mismatch(
    *,
    pairs: list[_TickPair],
    float_abs_tol: float,
    max_field_diffs: int | None,
    ignore_field_prefixes: tuple[str, ...],
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
        tick_mismatches: list[dict[str, object]] = []

        expected = checkpoint_channel_required(pair.expected_row)
        actual = checkpoint_channel_required(pair.actual_row)
        exp_rng_stream = rng_stream_channel_required(pair.expected_row)
        act_rng_stream = rng_stream_channel_required(pair.actual_row)

        checkpoint_diff = checkpoint_deepdiff(
            expected,
            actual,
            ignore_field_prefixes=ignore_field_prefixes,
            max_diffs=max_field_diffs,
            float_abs_tol=float_abs_tol,
        )
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
    float_abs_tol: float = 0.0,
    max_field_diffs: int | None = None,
    ignore_field_prefixes: tuple[str, ...] = (),
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> TraceDiffReport:
    with TraceReader(Path(expected_trace_path)) as expected_trace, TraceReader(Path(actual_trace_path)) as actual_trace:
        expected_channels = {str(channel) for channel in expected_trace.meta.channels}
        actual_channels = {str(channel) for channel in actual_trace.meta.channels}
        for required_channel in TRACE_REQUIRED_CHANNELS_V3:
            channel_name = str(required_channel)
            if channel_name not in expected_channels or channel_name not in actual_channels:
                return TraceDiffReport(
                    ok=False,
                    checked_count=0,
                    tick_start=tick_start,
                    tick_end=tick_end,
                    mismatch=TraceMismatch(
                        kind="missing_channel",
                        tick_index=-1,
                        detail={
                            "channel": channel_name,
                            "expected_has": channel_name in expected_channels,
                            "actual_has": channel_name in actual_channels,
                        },
                    ),
                )
        pairs = _load_pairs(
            expected_trace=expected_trace,
            actual_trace=actual_trace,
            tick_start=tick_start,
            tick_end=tick_end,
        )
        try:
            checked_count, mismatch = _first_mismatch(
                pairs=pairs,
                float_abs_tol=float(float_abs_tol),
                max_field_diffs=max_field_diffs,
                ignore_field_prefixes=tuple(ignore_field_prefixes),
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
        )


def bisect_traces(
    *,
    expected_trace_path: Path,
    actual_trace_path: Path,
    float_abs_tol: float = 0.0,
    max_field_diffs: int | None = None,
    ignore_field_prefixes: tuple[str, ...] = (),
    tick_start: int | None = None,
    tick_end: int | None = None,
    window_before: int = 12,
    window_after: int = 6,
    repro_out: Path | None = None,
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
                repro_trace_path=None,
            )

        end_tick_bound = pairs[-1].tick_index if tick_end is None else tick_end
        try:
            checked_count, mismatch = _first_mismatch(
                pairs=pairs,
                float_abs_tol=float(float_abs_tol),
                max_field_diffs=max_field_diffs,
                ignore_field_prefixes=tuple(ignore_field_prefixes),
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
                repro_trace_path=None,
            )

        first_bad = mismatch.tick_index
        final_mismatch = mismatch

        repro_path = None
        if repro_out is not None:
            left = first_bad - max(0, window_before)
            right = first_bad + max(0, window_after)
            repro_rows: list[TickRecord] = []
            for pair in pairs:
                tick = pair.tick_index
                if tick < left or tick > right:
                    continue
                channels: dict[str, object] = {}
                if pair.expected_row is not None:
                    channels["golden"] = msgspec.to_builtins(pair.expected_row.channels)
                if pair.actual_row is not None:
                    channels["candidate"] = msgspec.to_builtins(pair.actual_row.channels)
                channels["focus_tick"] = tick == first_bad
                repro_rows.append(
                    TickRecord(
                        tick_index=tick,
                        elapsed_ms=(
                            pair.expected_row.elapsed_ms
                            if pair.expected_row is not None
                            else (pair.actual_row.elapsed_ms if pair.actual_row is not None else 0)
                        ),
                        dt_ms_i32=(
                            pair.expected_row.dt_ms_i32
                            if pair.expected_row is not None
                            else (pair.actual_row.dt_ms_i32 if pair.actual_row is not None else None)
                        ),
                        mode_id=(
                            pair.expected_row.mode_id
                            if pair.expected_row is not None
                            else (pair.actual_row.mode_id if pair.actual_row is not None else -1)
                        ),
                        phase_markers=[],
                        channels=channels,
                    ),
                )
            meta = TraceMeta(
                trace_format_version=TRACE_FORMAT_VERSION,
                trace_schema_version=TRACE_SCHEMA_VERSION,
                created_utc="",
                producer={
                    "impl": "dbg_bisect",
                    "impl_version": "",
                    "platform": "",
                    "arch": "",
                },
                source={
                    "expected_trace": str(expected_trace_path),
                    "actual_trace": str(actual_trace_path),
                    "first_bad_tick": first_bad,
                },
                channels=["golden", "candidate", "focus_tick"],
                channel_versions=channel_versions_for(("golden", "candidate", "focus_tick")),
                tick_range={
                    "start_tick": left,
                    "end_tick": right,
                    "tick_count": len(repro_rows),
                },
                config={
                    "window_before": window_before,
                    "window_after": window_after,
                },
            )
            write_trace(Path(repro_out), meta=meta, ticks=repro_rows, chunk_ticks=128)
            repro_path = Path(repro_out)

        return TraceBisectReport(
            ok=False,
            first_bad_tick=first_bad,
            checked_count=checked_count,
            mismatch=final_mismatch,
            repro_trace_path=repro_path,
        )


def mismatch_to_json(mismatch: TraceMismatch | None) -> dict[str, object] | None:
    if mismatch is None:
        return None
    return {
        "kind": mismatch.kind,
        "tick_index": mismatch.tick_index,
        "detail": (None if mismatch.detail is None else msgspec.to_builtins(mismatch.detail)),
    }


def diff_report_to_json(report: TraceDiffReport) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": ("ok" if report.ok else "diverged"),
        "checked_count": report.checked_count,
        "tick_start": report.tick_start,
        "tick_end": report.tick_end,
        "mismatch": mismatch_to_json(report.mismatch),
    }


def bisect_report_to_json(report: TraceBisectReport) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": ("ok" if report.ok else "diverged"),
        "checked_count": report.checked_count,
        "first_bad_tick": report.first_bad_tick,
        "mismatch": mismatch_to_json(report.mismatch),
        "repro_trace_path": (None if report.repro_trace_path is None else str(report.repro_trace_path)),
    }
