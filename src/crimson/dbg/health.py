from __future__ import annotations

from pathlib import Path

from .channel_helpers import (
    entity_samples_channel,
    rng_stream_channel_required,
    sim_state_channel,
    timing_samples_channel_required,
)
from .payloads import BuiltinObject, to_builtin_object
from .schema import TRACE_REQUIRED_CHANNELS
from .trace import TraceReader


def summarize_trace_health(
    trace_path: Path,
    *,
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> BuiltinObject:
    path = Path(trace_path)
    with TraceReader(path) as trace:
        channels_present: dict[str, int] = {}
        channel_row_counts: dict[str, int] = {
            "rng_stream": 0,
            "timing_samples": 0,
        }
        ticks_total = 0
        ticks_with_dt = 0
        rng_stream_rows = 0
        sim_state_rows = 0
        sample_creature_rows = 0
        sample_projectile_rows = 0
        sample_secondary_rows = 0
        sample_bonus_rows = 0
        timing_samples_rows = 0

        for tick in trace.iter_ticks(tick_start=tick_start, tick_end=tick_end):
            ticks_total += 1
            ticks_with_dt += 1
            for channel_name in TRACE_REQUIRED_CHANNELS:
                channels_present[channel_name] = int(channels_present.get(channel_name, 0)) + 1
                if channel_name == "rng_stream":
                    rows = len(rng_stream_channel_required(tick))
                    rng_stream_rows += rows
                    channel_row_counts[channel_name] += rows
                elif channel_name == "timing_samples":
                    rows = len(timing_samples_channel_required(tick))
                    timing_samples_rows += rows
                    channel_row_counts[channel_name] += rows
                elif channel_name == "sim_state":
                    if sim_state_channel(tick) is not None:
                        sim_state_rows += 1
                elif channel_name == "entity_samples":
                    samples = entity_samples_channel(tick)
                    if samples is not None:
                        sample_creature_rows += len(samples.creatures)
                        sample_projectile_rows += len(samples.projectiles)
                        sample_secondary_rows += len(samples.secondary_projectiles)
                        sample_bonus_rows += len(samples.bonuses)

        issues: list[str] = []
        if ticks_total == 0:
            issues.append("trace window has no ticks")
        for required_channel in TRACE_REQUIRED_CHANNELS:
            if channels_present.get(str(required_channel), 0) <= 0:
                issues.append(f"{required_channel} channel missing")
        if ticks_total > 0:
            for row_channel in ("rng_stream", "timing_samples"):
                if int(channel_row_counts.get(row_channel, 0)) <= 0:
                    issues.append(f"{row_channel} channel has no rows in trace window")

        window_start = tick_start
        window_end = tick_end
        meta_range = trace.meta.tick_range
        if ticks_total > 0:
            if window_start is None:
                window_start = int(meta_range.start_tick)
            if window_end is None:
                window_end = int(meta_range.end_tick)
        return to_builtin_object(
            {
                "trace_format_version": int(trace.meta.trace_format_version),
                "trace_schema_version": int(trace.meta.trace_schema_version),
                "tick_window": {
                    "requested_start": (None if tick_start is None else int(tick_start)),
                    "requested_end": (None if tick_end is None else int(tick_end)),
                    "actual_start": (None if window_start is None else int(window_start)),
                    "actual_end": (None if window_end is None else int(window_end)),
                    "ticks_in_window": int(ticks_total),
                },
                "channels_present": {str(key): int(value) for key, value in sorted(channels_present.items())},
                "channel_row_counts": {
                    str(key): int(value)
                    for key, value in sorted(channel_row_counts.items())
                },
                "metrics": {
                    "ticks_with_dt_ms_i32": int(ticks_with_dt),
                    "rng_stream_rows": int(rng_stream_rows),
                    "sim_state_rows": int(sim_state_rows),
                    "sample_creature_rows": int(sample_creature_rows),
                    "sample_projectile_rows": int(sample_projectile_rows),
                    "sample_secondary_projectile_rows": int(sample_secondary_rows),
                    "sample_bonus_rows": int(sample_bonus_rows),
                    "timing_samples_rows": int(timing_samples_rows),
                },
                "issues": issues,
                "ok_for_movement_root_cause": len(issues) == 0,
            },
            field="trace_health",
        )
