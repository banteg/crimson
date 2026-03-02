from __future__ import annotations

from pathlib import Path

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .channel_compare import compare_entity_samples, compare_rng_stream, compare_sim_state
from .channel_helpers import entity_samples_channel, rng_stream_channel, sim_state_channel
from .checkpoint_codec import channel_to_checkpoint
from .checkpoint_diff import DEFAULT_RNG_MARK_ORDER, ReplayFieldDiff, checkpoint_field_diffs
from .policy import ParityPolicy
from .schema import (
    TRACE_FORMAT_VERSION,
    TRACE_REQUIRED_CHANNELS_V3,
    TRACE_SCHEMA_VERSION,
    TickRecord,
    TraceMeta,
    channel_versions_for,
)
from .trace import TraceReader, write_trace


class TraceMismatch(msgspec.Struct, frozen=True):
    kind: str
    tick_index: int
    field_diffs: tuple[ReplayFieldDiff, ...] = ()
    first_rng_mark: str | None = None
    detail: dict[str, object] | None = None


class TraceDiffReport(msgspec.Struct, frozen=True):
    ok: bool
    checked_count: int
    policy: str
    tick_start: int | None
    tick_end: int | None
    mismatch: TraceMismatch | None = None


class TraceBisectReport(msgspec.Struct, frozen=True):
    ok: bool
    policy: str
    first_bad_tick: int | None
    checked_count: int
    mismatch: TraceMismatch | None
    repro_trace_path: Path | None = None


class _TickPair(msgspec.Struct, frozen=True):
    tick_index: int
    expected_row: TickRecord | None
    actual_row: TickRecord | None
    expected_checkpoint: ReplayCheckpoint | None
    actual_checkpoint: ReplayCheckpoint | None


def _trace_has_channel(
    pairs: list[_TickPair],
    *,
    side: str,
    channel_name: str,
) -> bool:
    for pair in pairs:
        row = pair.expected_row if side == "expected" else pair.actual_row
        if row is not None and channel_name in row.channels:
            return True
    return False


def _extract_checkpoint(row: TickRecord | None) -> ReplayCheckpoint | None:
    if row is None:
        return None
    payload = row.channels.get("checkpoint")
    if payload is None:
        return None
    return channel_to_checkpoint(payload)


def _first_mismatch(
    *,
    pairs: list[_TickPair],
    policy: ParityPolicy,
    tick_end: int | None = None,
) -> tuple[int, TraceMismatch | None]:
    checked_count = 0
    elapsed_baseline: tuple[int, int] | None = None
    compare_sim_state_channels = (
        _trace_has_channel(pairs, side="expected", channel_name="sim_state")
        and _trace_has_channel(pairs, side="actual", channel_name="sim_state")
    )
    compare_entity_channels = (
        bool(policy.include_entity_channels)
        and _trace_has_channel(pairs, side="expected", channel_name="entity_samples")
        and _trace_has_channel(pairs, side="actual", channel_name="entity_samples")
    )
    for pair in pairs:
        tick = pair.tick_index
        if tick_end is not None and tick > tick_end:
            break
        checked_count += 1
        expected = pair.expected_checkpoint
        actual = pair.actual_checkpoint
        if expected is None or actual is None:
            return (
                checked_count,
                TraceMismatch(
                    kind="missing_checkpoint",
                    tick_index=tick,
                ),
            )

        if bool(policy.include_hash_fields) and expected.command_hash and expected.command_hash != actual.command_hash:
            return (
                checked_count,
                TraceMismatch(
                    kind="command_hash_mismatch",
                    tick_index=tick,
                    detail={
                        "expected": expected.command_hash,
                        "actual": actual.command_hash,
                    },
                ),
            )
        if bool(policy.include_hash_fields) and expected.state_hash != actual.state_hash:
            return (
                checked_count,
                TraceMismatch(
                    kind="state_hash_mismatch",
                    tick_index=tick,
                    detail={
                        "expected": expected.state_hash,
                        "actual": actual.state_hash,
                    },
                ),
            )

        if elapsed_baseline is None and expected.elapsed_ms >= 0 and actual.elapsed_ms >= 0:
            elapsed_baseline = (expected.elapsed_ms, actual.elapsed_ms)

        field_diffs = checkpoint_field_diffs(
            expected,
            actual,
            include_hash_fields=bool(policy.include_hash_fields),
            include_rng_fields=bool(policy.include_rng_fields),
            normalize_unknown=bool(policy.normalize_unknown),
            unknown_events_wildcard=bool(policy.unknown_events_wildcard),
            elapsed_baseline=elapsed_baseline,
            max_diffs=policy.max_field_diffs,
            float_abs_tol=float(policy.float_abs_tol),
        )
        if policy.ignore_field_prefixes:
            field_diffs = [
                diff
                for diff in field_diffs
                if not _field_matches_ignored_prefix(str(diff.field), policy.ignore_field_prefixes)
            ]
        if field_diffs:
            return (
                checked_count,
                TraceMismatch(
                    kind="checkpoint_field_mismatch",
                    tick_index=tick,
                    field_diffs=tuple(field_diffs),
                ),
            )

        if bool(policy.include_rng_fields):
            exp_rng = dict(expected.rng_marks)
            act_rng = dict(actual.rng_marks)
            mismatching_rng_keys = [key for key in sorted(set(exp_rng) | set(act_rng)) if exp_rng.get(key, -1) != act_rng.get(key, -1)]
            if mismatching_rng_keys:
                first_rng_mark = next(
                    (mark for mark in DEFAULT_RNG_MARK_ORDER if mark in mismatching_rng_keys),
                    mismatching_rng_keys[0],
                )
                return (
                    checked_count,
                    TraceMismatch(
                        kind="rng_mark_mismatch",
                        tick_index=tick,
                        first_rng_mark=first_rng_mark,
                        detail={
                            "expected": exp_rng.get(first_rng_mark),
                            "actual": act_rng.get(first_rng_mark),
                        },
                    ),
                )

            act_rng_stream = rng_stream_channel(pair.actual_row)
            exp_rng_stream = rng_stream_channel(pair.expected_row)
            rng_ok, rng_detail = compare_rng_stream(exp_rng_stream, act_rng_stream)
            if not rng_ok:
                return (
                    checked_count,
                    TraceMismatch(
                        kind="rng_stream_mismatch",
                        tick_index=tick,
                        detail=rng_detail,
                    ),
                )

        if compare_sim_state_channels:
            sim_ok, sim_detail = compare_sim_state(
                sim_state_channel(pair.expected_row),
                sim_state_channel(pair.actual_row),
            )
            if not sim_ok:
                return (
                    checked_count,
                    TraceMismatch(
                        kind="sim_state_mismatch",
                        tick_index=tick,
                        detail=sim_detail,
                    ),
                )

        if compare_entity_channels:
            entities_ok, entities_detail = compare_entity_samples(
                entity_samples_channel(pair.expected_row),
                entity_samples_channel(pair.actual_row),
            )
            if not entities_ok:
                return (
                    checked_count,
                    TraceMismatch(
                        kind="entity_sample_mismatch",
                        tick_index=tick,
                        detail=entities_detail,
                    ),
                )

    return checked_count, None


def _field_matches_ignored_prefix(field: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if field == prefix:
            return True
        if field.startswith(f"{prefix}."):
            return True
        if field.startswith(f"{prefix}["):
            return True
    return False


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
                expected_checkpoint=_extract_checkpoint(exp_row),
                actual_checkpoint=_extract_checkpoint(act_row),
            ),
        )
    return pairs


def diff_traces(
    *,
    expected_trace_path: Path,
    actual_trace_path: Path,
    policy: ParityPolicy,
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
                    policy=policy.name,
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
        checked_count, mismatch = _first_mismatch(
            pairs=pairs,
            policy=policy,
            tick_end=tick_end,
        )
        return TraceDiffReport(
            ok=(mismatch is None),
            checked_count=checked_count,
            policy=policy.name,
            tick_start=tick_start,
            tick_end=tick_end,
            mismatch=mismatch,
        )


def bisect_traces(
    *,
    expected_trace_path: Path,
    actual_trace_path: Path,
    policy: ParityPolicy,
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
                policy=policy.name,
                first_bad_tick=None,
                checked_count=0,
                mismatch=None,
                repro_trace_path=None,
            )

        end_tick_bound = pairs[-1].tick_index if tick_end is None else tick_end
        checked_count, mismatch = _first_mismatch(pairs=pairs, policy=policy, tick_end=end_tick_bound)
        if mismatch is None:
            return TraceBisectReport(
                ok=True,
                policy=policy.name,
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
                    "policy": policy.name,
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
            policy=policy.name,
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
        "first_rng_mark": mismatch.first_rng_mark,
        "field_diffs": [
            {
                "field": diff.field,
                "expected": diff.expected,
                "actual": diff.actual,
            }
            for diff in mismatch.field_diffs
        ],
        "detail": (None if mismatch.detail is None else msgspec.to_builtins(mismatch.detail)),
    }


def diff_report_to_json(report: TraceDiffReport) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": ("ok" if report.ok else "diverged"),
        "policy": report.policy,
        "checked_count": report.checked_count,
        "tick_start": report.tick_start,
        "tick_end": report.tick_end,
        "mismatch": mismatch_to_json(report.mismatch),
    }


def bisect_report_to_json(report: TraceBisectReport) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": ("ok" if report.ok else "diverged"),
        "policy": report.policy,
        "checked_count": report.checked_count,
        "first_bad_tick": report.first_bad_tick,
        "mismatch": mismatch_to_json(report.mismatch),
        "repro_trace_path": (None if report.repro_trace_path is None else str(report.repro_trace_path)),
    }
