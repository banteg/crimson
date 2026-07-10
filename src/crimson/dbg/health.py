from __future__ import annotations

from pathlib import Path

import msgspec

from . import trace as trace_io
from .channel_helpers import entity_samples_channel, rng_stream_channel_required, sim_state_channel
from .payloads import BuiltinObject, to_builtin_object
from .schema import CHUNK_KIND_TICK, TRACE_REQUIRED_CHANNELS, TickBlock, TickRecord
from .trace import TraceError, TraceReader, validate_tick_record


def _tick_coverage(tick_indices: list[int]) -> tuple[list[BuiltinObject], list[BuiltinObject]]:
    ordered = sorted(set(int(tick) for tick in tick_indices))
    if not ordered:
        return [], []

    spans: list[BuiltinObject] = []
    gaps: list[BuiltinObject] = []
    span_start = ordered[0]
    previous = ordered[0]
    for tick in ordered[1:]:
        if tick == previous + 1:
            previous = tick
            continue
        spans.append(
            {
                "start_tick": span_start,
                "end_tick": previous,
                "tick_count": previous - span_start + 1,
            },
        )
        gaps.append(
            {
                "start_tick": previous + 1,
                "end_tick": tick - 1,
                "tick_count": tick - previous - 1,
            },
        )
        span_start = tick
        previous = tick
    spans.append(
        {
            "start_tick": span_start,
            "end_tick": previous,
            "tick_count": previous - span_start + 1,
        },
    )
    return spans, gaps


def _health_payload(
    *,
    trace_format_version: int | None,
    trace_schema_version: int | None,
    tick_start: int | None,
    tick_end: int | None,
    tick_indices: list[int],
    channels_present: dict[str, int],
    channel_row_counts: dict[str, int],
    metrics: dict[str, int],
    issues: list[str],
) -> BuiltinObject:
    spans, gaps = _tick_coverage(tick_indices)
    return to_builtin_object(
        {
            "trace_format_version": trace_format_version,
            "trace_schema_version": trace_schema_version,
            "tick_window": {
                "requested_start": tick_start,
                "requested_end": tick_end,
                "actual_start": (None if not tick_indices else min(tick_indices)),
                "actual_end": (None if not tick_indices else max(tick_indices)),
                "ticks_in_window": len(tick_indices),
            },
            "tick_spans": spans,
            "tick_gaps": gaps,
            "channels_present": {str(key): int(value) for key, value in sorted(channels_present.items())},
            "channel_row_counts": {
                str(key): int(value)
                for key, value in sorted(channel_row_counts.items())
            },
            "metrics": metrics,
            "issues": issues,
            "ok_for_parity_analysis": len(issues) == 0,
        },
        field="trace_health",
    )


def _empty_metrics() -> dict[str, int]:
    return {
        "ticks_with_dt_ms_i32": 0,
        "validated_tick_records": 0,
        "replay_step_rows": 0,
        "rng_stream_rows": 0,
        "sim_state_rows": 0,
        "sample_creature_rows": 0,
        "sample_projectile_rows": 0,
        "sample_secondary_projectile_rows": 0,
        "sample_bonus_rows": 0,
        "timing_samples_rows": 0,
        "ticks_with_timing_samples": 0,
    }


def _collect_rows(trace: TraceReader, issues: list[str]) -> list[TickRecord]:
    rows: list[TickRecord] = []
    previous_entry_end: int | None = None
    previous_offset: int | None = None
    for block_index, entry in enumerate(trace.footer.tick_blocks):
        if previous_offset is not None and int(entry.file_offset) <= previous_offset:
            issues.append(
                f"footer.tick_blocks[{block_index}].file_offset={int(entry.file_offset)} "
                f"must be greater than {previous_offset}",
            )
        previous_offset = int(entry.file_offset)
        if int(entry.start_tick) > int(entry.end_tick):
            issues.append(f"footer.tick_blocks[{block_index}] has start_tick after end_tick")
        if previous_entry_end is not None and int(entry.start_tick) <= previous_entry_end:
            issues.append(
                f"footer.tick_blocks[{block_index}] range starts at {int(entry.start_tick)} "
                f"after previous end {previous_entry_end}",
            )
        previous_entry_end = int(entry.end_tick)

        try:
            kind, chunk_start, chunk_end, payload = trace_io._chunk_payload_from_file(
                trace._handle,
                offset=int(entry.file_offset),
                expected_entry=entry,
            )
            if kind != CHUNK_KIND_TICK:
                raise TraceError("trace index points at non-tick chunk")
            if int(chunk_start) != int(entry.start_tick) or int(chunk_end) != int(entry.end_tick):
                raise TraceError("trace tick chunk range does not match footer index")
            trace_io._validate_wire_payload(
                payload,
                TickBlock,
                path=f"tick_block[{block_index}]",
            )
            block = msgspec.msgpack.decode(payload, type=TickBlock)
        except (TraceError, msgspec.DecodeError, msgspec.ValidationError) as exc:
            issues.append(f"tick block {block_index} is invalid: {exc}")
            continue
        if not block.ticks:
            issues.append(f"tick block {block_index} has no tick rows")
            continue
        block_first = int(block.ticks[0].tick_index)
        block_last = int(block.ticks[-1].tick_index)
        if int(block.start_tick) != block_first or int(block.end_tick) != block_last:
            issues.append(
                f"tick block {block_index} payload range={int(block.start_tick)}..{int(block.end_tick)} "
                f"does not match rows={block_first}..{block_last}",
            )
        if int(entry.start_tick) != int(block.start_tick) or int(entry.end_tick) != int(block.end_tick):
            issues.append(
                f"footer.tick_blocks[{block_index}] range={int(entry.start_tick)}..{int(entry.end_tick)} "
                f"does not match payload={int(block.start_tick)}..{int(block.end_tick)}",
            )
        rows.extend(block.ticks)
    return rows


def _validate_container_ranges(trace: TraceReader, rows: list[TickRecord], issues: list[str]) -> None:
    tick_indices = [int(row.tick_index) for row in rows]
    previous: int | None = None
    for tick in tick_indices:
        if previous is not None:
            if tick == previous:
                issues.append(f"duplicate tick_index {tick}")
            elif tick < previous:
                issues.append(f"out-of-order tick_index {tick} after {previous}")
            elif tick != previous + 1:
                issues.append(f"tick gap {previous + 1}..{tick - 1}")
        previous = tick

    actual_count = len(rows)
    if int(trace.footer.tick_count) != actual_count:
        issues.append(
            f"footer.tick_count={int(trace.footer.tick_count)} does not match decoded tick count {actual_count}",
        )
    if not tick_indices:
        return

    first_tick = tick_indices[0]
    last_tick = tick_indices[-1]
    if int(trace.footer.first_tick) != first_tick:
        issues.append(
            f"footer.first_tick={int(trace.footer.first_tick)} does not match first decoded tick {first_tick}",
        )
    if int(trace.footer.last_tick) != last_tick:
        issues.append(
            f"footer.last_tick={int(trace.footer.last_tick)} does not match last decoded tick {last_tick}",
        )

    meta_range = trace.meta.tick_range
    if int(meta_range.start_tick) != first_tick:
        issues.append(
            f"meta.tick_range.start_tick={int(meta_range.start_tick)} does not match first decoded tick {first_tick}",
        )
    if int(meta_range.end_tick) != last_tick:
        issues.append(
            f"meta.tick_range.end_tick={int(meta_range.end_tick)} does not match last decoded tick {last_tick}",
        )
    if int(meta_range.tick_count) != actual_count:
        issues.append(
            f"meta.tick_range.tick_count={int(meta_range.tick_count)} does not match decoded tick count {actual_count}",
        )


def summarize_trace_health(
    trace_path: Path,
    *,
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> BuiltinObject:
    path = Path(trace_path)
    if tick_start is not None and tick_end is not None and int(tick_start) > int(tick_end):
        raise ValueError(f"invalid tick window: start {int(tick_start)} is after end {int(tick_end)}")

    issues: list[str] = []
    try:
        trace = TraceReader(path, strict=False)
    except (OSError, TraceError) as exc:
        return _health_payload(
            trace_format_version=None,
            trace_schema_version=None,
            tick_start=tick_start,
            tick_end=tick_end,
            tick_indices=[],
            channels_present={},
            channel_row_counts={},
            metrics=_empty_metrics(),
            issues=[f"invalid trace container: {exc}"],
        )

    with trace:
        rows = _collect_rows(trace, issues)
        _validate_container_ranges(trace, rows, issues)

        validated_ticks: set[int] = set()
        for row in rows:
            try:
                validate_tick_record(row, meta=trace.meta)
            except TraceError as exc:
                issues.append(f"invalid tick record {int(row.tick_index)}: {exc}")
            else:
                validated_ticks.add(id(row))

        selected_rows = [
            row
            for row in rows
            if (tick_start is None or int(row.tick_index) >= int(tick_start))
            and (tick_end is None or int(row.tick_index) <= int(tick_end))
        ]
        selected_indices = [int(row.tick_index) for row in selected_rows]

        channels_present = {str(channel): len(selected_rows) for channel in TRACE_REQUIRED_CHANNELS}
        channel_row_counts: dict[str, int] = {
            "replay_step": len(selected_rows),
            "checkpoint": len(selected_rows),
            "sim_state": len(selected_rows),
            "entity_samples": len(selected_rows),
            "rng_stream": 0,
            "timing_samples": 0,
        }
        metrics = _empty_metrics()
        for row in selected_rows:
            metrics["ticks_with_dt_ms_i32"] = int(metrics["ticks_with_dt_ms_i32"]) + 1
            metrics["validated_tick_records"] = int(metrics["validated_tick_records"]) + int(id(row) in validated_ticks)
            metrics["replay_step_rows"] = int(metrics["replay_step_rows"]) + 1

            rng_rows = len(rng_stream_channel_required(row))
            metrics["rng_stream_rows"] = int(metrics["rng_stream_rows"]) + rng_rows
            channel_row_counts["rng_stream"] += rng_rows

            timing_rows = len(row.channels.timing_samples)
            metrics["timing_samples_rows"] = int(metrics["timing_samples_rows"]) + timing_rows
            metrics["ticks_with_timing_samples"] = int(metrics["ticks_with_timing_samples"]) + int(timing_rows > 0)
            channel_row_counts["timing_samples"] += timing_rows

            if sim_state_channel(row) is not None:
                metrics["sim_state_rows"] = int(metrics["sim_state_rows"]) + 1
            samples = entity_samples_channel(row)
            if samples is not None:
                metrics["sample_creature_rows"] = int(metrics["sample_creature_rows"]) + len(samples.creatures)
                metrics["sample_projectile_rows"] = int(metrics["sample_projectile_rows"]) + len(samples.projectiles)
                metrics["sample_secondary_projectile_rows"] = int(metrics["sample_secondary_projectile_rows"]) + len(
                    samples.secondary_projectiles,
                )
                metrics["sample_bonus_rows"] = int(metrics["sample_bonus_rows"]) + len(samples.bonuses)

        if not selected_rows:
            issues.append("trace window has no ticks")
        elif int(metrics["ticks_with_timing_samples"]) != len(selected_rows):
            issues.append(
                f"timing_samples missing for {len(selected_rows) - int(metrics['ticks_with_timing_samples'])} tick(s) in trace window",
            )
        if int(metrics["replay_step_rows"]) != len(selected_rows):
            issues.append(
                f"replay_step missing for {len(selected_rows) - int(metrics['replay_step_rows'])} tick(s) in trace window",
            )

        return _health_payload(
            trace_format_version=int(trace.meta.trace_format_version),
            trace_schema_version=int(trace.meta.trace_schema_version),
            tick_start=tick_start,
            tick_end=tick_end,
            tick_indices=selected_indices,
            channels_present=channels_present,
            channel_row_counts=channel_row_counts,
            metrics=metrics,
            issues=issues,
        )
