from __future__ import annotations

import msgspec

from .presentation_step import DeterministicPresentationPlan
from .timing import FrameTiming
from .world_state import WorldEvents


class PresentationRngTrace(msgspec.Struct):
    draws_total: int = 0


class DeterministicStepResult(msgspec.Struct):
    dt_sim: float
    timing: FrameTiming
    events: WorldEvents
    presentation: DeterministicPresentationPlan
    presentation_rng_trace: PresentationRngTrace

