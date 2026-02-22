from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BeamSamplePlan:
    start: float
    stop: float
    span: float
    step: float
    count: int


def build_beam_sample_plan(
    *,
    dist: float,
    step: float,
    max_span: float = 256.0,
) -> BeamSamplePlan | None:
    resolved_dist = float(dist)
    resolved_step = float(step)
    resolved_max_span = max(0.0, float(max_span))

    if resolved_dist <= 1e-6:
        return None
    if resolved_step <= 1e-6:
        return None

    start = 0.0
    span = resolved_dist
    if resolved_max_span > 0.0 and resolved_dist > resolved_max_span:
        start = resolved_dist - resolved_max_span
        span = resolved_max_span

    count = 0
    offset = start
    while offset < resolved_dist:
        count += 1
        offset += resolved_step

    return BeamSamplePlan(
        start=float(start),
        stop=float(resolved_dist),
        span=float(span),
        step=float(resolved_step),
        count=int(count),
    )


def iter_beam_sample_offsets(plan: BeamSamplePlan) -> Iterator[float]:
    offset = float(plan.start)
    stop = float(plan.stop)
    step = float(plan.step)
    while offset < stop:
        yield float(offset)
        offset += step


__all__ = ["BeamSamplePlan", "build_beam_sample_plan", "iter_beam_sample_offsets"]
