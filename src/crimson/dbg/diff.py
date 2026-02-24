from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import msgspec

from ..original.diff import DEFAULT_RNG_MARK_ORDER, ReplayFieldDiff, checkpoint_field_diffs
from ..replay.checkpoints import ReplayCheckpoint
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


def _channel_list(row: TickRecord | None, channel_name: str) -> list[object]:
    if row is None:
        return []
    value = row.channels.get(channel_name)
    if isinstance(value, list):
        return list(value)
    return []


def _as_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            out[key] = item
    return out


def _coerce_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _channel_dict(row: TickRecord | None, channel_name: str) -> dict[str, object]:
    if row is None:
        return {}
    value = row.channels.get(channel_name)
    mapped = _as_object_dict(value)
    if mapped is not None:
        return mapped
    return {}


def _rng_row_key(row: object) -> tuple[object, object, object]:
    mapped = _as_object_dict(row)
    if mapped is None:
        return (None, None, None)
    value_15 = mapped.get("value_15")
    if value_15 is None:
        value_15 = mapped.get("value")
    return (value_15, mapped.get("caller_static"), mapped.get("branch_id"))


def _compare_rng_stream(expected: list[object], actual: list[object]) -> tuple[bool, dict[str, object] | None]:
    exp_keys = [_rng_row_key(row) for row in expected]
    act_keys = [_rng_row_key(row) for row in actual]
    max_prefix = min(len(exp_keys), len(act_keys))
    prefix = 0
    while prefix < max_prefix and exp_keys[prefix] == act_keys[prefix]:
        prefix += 1
    if prefix == len(exp_keys) == len(act_keys):
        return True, None
    detail: dict[str, object] = {
        "prefix_match_len": int(prefix),
        "expected_calls": int(len(exp_keys)),
        "actual_calls": int(len(act_keys)),
        "missing_tail": int(max(0, len(exp_keys) - len(act_keys))),
        "extra_tail": int(max(0, len(act_keys) - len(exp_keys))),
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
                "expected": int(len(exp_list)),
                "actual": int(len(act_list)),
            }
            continue
        exp_uids = sorted(_coerce_int(mapped.get("uid"), default=-1) for row in exp_list if (mapped := _as_object_dict(row)) is not None)
        act_uids = sorted(_coerce_int(mapped.get("uid"), default=-1) for row in act_list if (mapped := _as_object_dict(row)) is not None)
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
        tick = int(pair.tick_index)
        if tick_end is not None and tick > int(tick_end):
            break
        checked_count += 1
        expected = pair.expected_checkpoint
        actual = pair.actual_checkpoint
        if expected is None or actual is None:
            return (
                int(checked_count),
                TraceMismatch(
                    kind="missing_checkpoint",
                    tick_index=int(tick),
                ),
            )

        if str(expected.command_hash) and str(expected.command_hash) != str(actual.command_hash):
            return (
                int(checked_count),
                TraceMismatch(
                    kind="command_hash_mismatch",
                    tick_index=int(tick),
                    detail={
                        "expected": str(expected.command_hash),
                        "actual": str(actual.command_hash),
                    },
                ),
            )
        if str(expected.state_hash) != str(actual.state_hash):
            return (
                int(checked_count),
                TraceMismatch(
                    kind="state_hash_mismatch",
                    tick_index=int(tick),
                    detail={
                        "expected": str(expected.state_hash),
                        "actual": str(actual.state_hash),
                    },
                ),
            )

        if elapsed_baseline is None and int(expected.elapsed_ms) >= 0 and int(actual.elapsed_ms) >= 0:
            elapsed_baseline = (int(expected.elapsed_ms), int(actual.elapsed_ms))

        field_diffs = checkpoint_field_diffs(
            expected,
            actual,
            include_hash_fields=bool(policy.include_hash_fields),
            include_rng_fields=bool(policy.include_rng_fields),
            normalize_unknown=bool(policy.normalize_unknown),
            unknown_events_wildcard=bool(policy.unknown_events_wildcard),
            elapsed_baseline=elapsed_baseline,
            max_diffs=int(policy.max_field_diffs),
            float_abs_tol=float(policy.float_abs_tol),
        )
        if field_diffs:
            return (
                int(checked_count),
                TraceMismatch(
                    kind="checkpoint_field_mismatch",
                    tick_index=int(tick),
                    field_diffs=tuple(field_diffs),
                ),
            )

        exp_rng = {str(key): int(value) for key, value in expected.rng_marks.items()}
        act_rng = {str(key): int(value) for key, value in actual.rng_marks.items()}
        mismatching_rng_keys = [key for key in sorted(set(exp_rng) | set(act_rng)) if exp_rng.get(key, -1) != act_rng.get(key, -1)]
        if mismatching_rng_keys:
            first_rng_mark = next(
                (mark for mark in DEFAULT_RNG_MARK_ORDER if mark in mismatching_rng_keys),
                mismatching_rng_keys[0],
            )
            return (
                int(checked_count),
                TraceMismatch(
                    kind="rng_mark_mismatch",
                    tick_index=int(tick),
                    first_rng_mark=str(first_rng_mark),
                    detail={
                        "expected": exp_rng.get(str(first_rng_mark)),
                        "actual": act_rng.get(str(first_rng_mark)),
                    },
                ),
            )

        exp_rng_head = _channel_list(pair.expected_row, "rng_stream_head")
        act_rng_head = _channel_list(pair.actual_row, "rng_stream_head")
        rng_ok, rng_detail = _compare_rng_stream(exp_rng_head, act_rng_head)
        if not rng_ok:
            return (
                int(checked_count),
                TraceMismatch(
                    kind="rng_stream_mismatch",
                    tick_index=int(tick),
                    detail=rng_detail,
                ),
            )

        exp_entities = _channel_dict(pair.expected_row, "entity_samples")
        act_entities = _channel_dict(pair.actual_row, "entity_samples")
        entities_ok, entities_detail = _compare_entity_samples(exp_entities, act_entities)
        if not entities_ok:
            return (
                int(checked_count),
                TraceMismatch(
                    kind="entity_sample_mismatch",
                    tick_index=int(tick),
                    detail=entities_detail,
                ),
            )

        exp_events = _channel_list(pair.expected_row, "event_heads")
        act_events = _channel_list(pair.actual_row, "event_heads")
        if len(exp_events) != len(act_events):
            return (
                int(checked_count),
                TraceMismatch(
                    kind="event_head_mismatch",
                    tick_index=int(tick),
                    detail={
                        "expected_count": int(len(exp_events)),
                        "actual_count": int(len(act_events)),
                    },
                ),
            )

        exp_micro = _channel_list(pair.expected_row, "micro_traces")
        act_micro = _channel_list(pair.actual_row, "micro_traces")
        if len(exp_micro) != len(act_micro):
            return (
                int(checked_count),
                TraceMismatch(
                    kind="micro_trace_mismatch",
                    tick_index=int(tick),
                    detail={
                        "expected_count": int(len(exp_micro)),
                        "actual_count": int(len(act_micro)),
                    },
                ),
            )

    return int(checked_count), None


def _load_pairs(
    *,
    expected_trace: TraceReader,
    actual_trace: TraceReader,
    tick_start: int | None,
    tick_end: int | None,
) -> list[_TickPair]:
    expected_rows = {int(row.tick_index): row for row in expected_trace.iter_ticks(tick_start=tick_start, tick_end=tick_end)}
    actual_rows = {int(row.tick_index): row for row in actual_trace.iter_ticks(tick_start=tick_start, tick_end=tick_end)}
    all_ticks = sorted(set(expected_rows) | set(actual_rows))
    pairs: list[_TickPair] = []
    for tick in all_ticks:
        exp_row = expected_rows.get(tick)
        act_row = actual_rows.get(tick)
        pairs.append(
            _TickPair(
                tick_index=int(tick),
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
            checked_count=int(checked_count),
            policy=str(policy.name),
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
                policy=str(policy.name),
                first_bad_tick=None,
                checked_count=0,
                mismatch=None,
                repro_trace_path=None,
            )

        start_tick = int(pairs[0].tick_index if tick_start is None else tick_start)
        end_tick_bound = int(pairs[-1].tick_index if tick_end is None else tick_end)
        checked_count, mismatch = _first_mismatch(pairs=pairs, policy=policy, tick_end=end_tick_bound)
        if mismatch is None:
            return TraceBisectReport(
                ok=True,
                policy=str(policy.name),
                first_bad_tick=None,
                checked_count=int(checked_count),
                mismatch=None,
                repro_trace_path=None,
            )

        lo = int(start_tick)
        hi = int(end_tick_bound)
        first_bad = int(mismatch.tick_index)
        while lo <= hi:
            mid = (lo + hi) // 2
            _checked_mid, mid_mismatch = _first_mismatch(pairs=pairs, policy=policy, tick_end=int(mid))
            if mid_mismatch is not None:
                first_bad = int(mid_mismatch.tick_index)
                hi = int(mid) - 1
            else:
                lo = int(mid) + 1

        _checked_final, final_mismatch = _first_mismatch(pairs=pairs, policy=policy, tick_end=int(first_bad))
        assert final_mismatch is not None

        repro_path = None
        if repro_out is not None:
            left = int(first_bad) - max(0, int(window_before))
            right = int(first_bad) + max(0, int(window_after))
            repro_rows: list[TickRecord] = []
            for pair in pairs:
                tick = int(pair.tick_index)
                if tick < left or tick > right:
                    continue
                channels: dict[str, object] = {}
                if pair.expected_row is not None:
                    channels["golden"] = msgspec.to_builtins(pair.expected_row.channels)
                if pair.actual_row is not None:
                    channels["candidate"] = msgspec.to_builtins(pair.actual_row.channels)
                channels["focus_tick"] = bool(int(tick) == int(first_bad))
                repro_rows.append(
                    TickRecord(
                        tick_index=int(tick),
                        elapsed_ms=(
                            int(pair.expected_row.elapsed_ms)
                            if pair.expected_row is not None
                            else (int(pair.actual_row.elapsed_ms) if pair.actual_row is not None else 0)
                        ),
                        dt_ms_i32=(
                            pair.expected_row.dt_ms_i32
                            if pair.expected_row is not None
                            else (pair.actual_row.dt_ms_i32 if pair.actual_row is not None else None)
                        ),
                        mode_id=(
                            int(pair.expected_row.mode_id)
                            if pair.expected_row is not None
                            else (int(pair.actual_row.mode_id) if pair.actual_row is not None else -1)
                        ),
                        phase_markers=[],
                        channels=channels,
                    ),
                )
            meta = TraceMeta(
                trace_format_version=int(TRACE_FORMAT_VERSION),
                trace_schema_version=int(TRACE_SCHEMA_VERSION),
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
                    "policy": str(policy.name),
                    "first_bad_tick": int(first_bad),
                },
                channels=["golden", "candidate", "focus_tick"],
                channel_versions={"golden": 1, "candidate": 1, "focus_tick": 1},
                tick_range={
                    "start_tick": int(left),
                    "end_tick": int(right),
                    "tick_count": int(len(repro_rows)),
                },
                config={
                    "window_before": int(window_before),
                    "window_after": int(window_after),
                },
            )
            write_trace(Path(repro_out), meta=meta, ticks=repro_rows, chunk_ticks=128)
            repro_path = Path(repro_out)

        return TraceBisectReport(
            ok=False,
            policy=str(policy.name),
            first_bad_tick=int(first_bad),
            checked_count=int(checked_count),
            mismatch=final_mismatch,
            repro_trace_path=repro_path,
        )


def mismatch_to_json(mismatch: TraceMismatch | None) -> dict[str, object] | None:
    if mismatch is None:
        return None
    return {
        "kind": str(mismatch.kind),
        "tick_index": int(mismatch.tick_index),
        "first_rng_mark": (None if mismatch.first_rng_mark is None else str(mismatch.first_rng_mark)),
        "field_diffs": [
            {
                "field": str(diff.field),
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
        "policy": str(report.policy),
        "checked_count": int(report.checked_count),
        "tick_start": (None if report.tick_start is None else int(report.tick_start)),
        "tick_end": (None if report.tick_end is None else int(report.tick_end)),
        "mismatch": mismatch_to_json(report.mismatch),
    }


def bisect_report_to_json(report: TraceBisectReport) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": ("ok" if report.ok else "diverged"),
        "policy": str(report.policy),
        "checked_count": int(report.checked_count),
        "first_bad_tick": (None if report.first_bad_tick is None else int(report.first_bad_tick)),
        "mismatch": mismatch_to_json(report.mismatch),
        "repro_trace_path": (None if report.repro_trace_path is None else str(report.repro_trace_path)),
    }
