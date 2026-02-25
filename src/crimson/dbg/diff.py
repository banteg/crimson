from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import msgspec

from ..original.diff import DEFAULT_RNG_MARK_ORDER, ReplayFieldDiff, checkpoint_field_diffs
from ..replay.checkpoints import ReplayCheckpoint
from .channel_helpers import as_object_dict, channel_dict, channel_list, rng_row_key
from .checkpoint_codec import channel_to_checkpoint
from .policy import ParityPolicy
from .schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta
from .trace import TraceReader, write_trace


@dataclass(frozen=True, slots=True)
class TraceMismatch:
    kind: str
    tick_index: int
    field_diffs: tuple[ReplayFieldDiff, ...] = ()
    first_rng_mark: str | None = None
    detail: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class TraceDiffReport:
    ok: bool
    checked_count: int
    policy: str
    tick_start: int | None
    tick_end: int | None
    mismatch: TraceMismatch | None = None


@dataclass(frozen=True, slots=True)
class TraceBisectReport:
    ok: bool
    policy: str
    first_bad_tick: int | None
    checked_count: int
    mismatch: TraceMismatch | None
    repro_trace_path: Path | None = None


@dataclass(frozen=True, slots=True)
class _TickPair:
    tick_index: int
    expected_row: TickRecord | None
    actual_row: TickRecord | None
    expected_checkpoint: ReplayCheckpoint | None
    actual_checkpoint: ReplayCheckpoint | None


def _extract_checkpoint(row: TickRecord | None) -> ReplayCheckpoint | None:
    if row is None:
        return None
    payload = row.channels.get("checkpoint")
    if payload is None:
        return None
    return channel_to_checkpoint(payload)


def _compare_rng_stream(expected: list[object], actual: list[object]) -> tuple[bool, dict[str, object] | None]:
    exp_keys = [rng_row_key(row) for row in expected]
    act_keys = [rng_row_key(row) for row in actual]
    max_prefix = min(len(exp_keys), len(act_keys))
    prefix = 0
    while prefix < max_prefix and exp_keys[prefix] == act_keys[prefix]:
        prefix += 1
    if prefix == len(exp_keys) == len(act_keys):
        return True, None
    detail: dict[str, object] = {
        "prefix_match_len": prefix,
        "expected_calls": len(exp_keys),
        "actual_calls": len(act_keys),
        "missing_tail": max(0, len(exp_keys) - len(act_keys)),
        "extra_tail": max(0, len(act_keys) - len(exp_keys)),
    }
    if prefix < len(exp_keys):
        detail["expected_first_mismatch"] = expected[prefix]
    if prefix < len(act_keys):
        detail["actual_first_mismatch"] = actual[prefix]
    return False, detail


def _compare_entity_samples(expected: dict[str, object], actual: dict[str, object]) -> tuple[bool, dict[str, object] | None]:
    kinds = ("creatures", "projectiles", "secondary_projectiles", "bonuses")
    diffs: dict[str, object] = {}
    for kind in kinds:
        exp_rows = expected.get(kind)
        act_rows = actual.get(kind)
        exp_list = exp_rows if isinstance(exp_rows, list) else []
        act_list = act_rows if isinstance(act_rows, list) else []
        if len(exp_list) != len(act_list):
            diffs[f"{kind}_count"] = {
                "expected": len(exp_list),
                "actual": len(act_list),
            }
            continue
        exp_uids: list[int] = []
        act_uids: list[int] = []
        for row in exp_list:
            mapped = as_object_dict(row)
            if mapped is None:
                continue
            uid = mapped.get("uid")
            if isinstance(uid, int) and not isinstance(uid, bool):
                exp_uids.append(uid)
        for row in act_list:
            mapped = as_object_dict(row)
            if mapped is None:
                continue
            uid = mapped.get("uid")
            if isinstance(uid, int) and not isinstance(uid, bool):
                act_uids.append(uid)
        exp_uids.sort()
        act_uids.sort()
        if exp_uids != act_uids:
            diffs[f"{kind}_uids"] = {
                "expected_head": exp_uids[:16],
                "actual_head": act_uids[:16],
            }
    if not diffs:
        return True, None
    return False, diffs


def _first_mismatch(
    *,
    pairs: list[_TickPair],
    policy: ParityPolicy,
    tick_end: int | None = None,
) -> tuple[int, TraceMismatch | None]:
    checked_count = 0
    elapsed_baseline: tuple[int, int] | None = None
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

        if expected.command_hash and expected.command_hash != actual.command_hash:
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
        if expected.state_hash != actual.state_hash:
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
        if field_diffs:
            return (
                checked_count,
                TraceMismatch(
                    kind="checkpoint_field_mismatch",
                    tick_index=tick,
                    field_diffs=tuple(field_diffs),
                ),
            )

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

        exp_rng_head = channel_list(pair.expected_row, "rng_stream_head")
        act_rng_head = channel_list(pair.actual_row, "rng_stream_head")
        rng_ok, rng_detail = _compare_rng_stream(exp_rng_head, act_rng_head)
        if not rng_ok:
            return (
                checked_count,
                TraceMismatch(
                    kind="rng_stream_mismatch",
                    tick_index=tick,
                    detail=rng_detail,
                ),
            )

        exp_entities = channel_dict(pair.expected_row, "entity_samples")
        act_entities = channel_dict(pair.actual_row, "entity_samples")
        entities_ok, entities_detail = _compare_entity_samples(exp_entities, act_entities)
        if not entities_ok:
            return (
                checked_count,
                TraceMismatch(
                    kind="entity_sample_mismatch",
                    tick_index=tick,
                    detail=entities_detail,
                ),
            )

        exp_events = channel_list(pair.expected_row, "event_heads")
        act_events = channel_list(pair.actual_row, "event_heads")
        if len(exp_events) != len(act_events):
            return (
                checked_count,
                TraceMismatch(
                    kind="event_head_mismatch",
                    tick_index=tick,
                    detail={
                        "expected_count": len(exp_events),
                        "actual_count": len(act_events),
                    },
                ),
            )

        exp_micro = channel_list(pair.expected_row, "micro_traces")
        act_micro = channel_list(pair.actual_row, "micro_traces")
        if len(exp_micro) != len(act_micro):
            return (
                checked_count,
                TraceMismatch(
                    kind="micro_trace_mismatch",
                    tick_index=tick,
                    detail={
                        "expected_count": len(exp_micro),
                        "actual_count": len(act_micro),
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
                channel_versions={"golden": 1, "candidate": 1, "focus_tick": 1},
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
