from __future__ import annotations

from grim.rand import CrandLike

from ..creatures.runtime import CREATURE_POOL_SIZE
from ..rng_caller_static import RngCallerStatic


def advance_gameplay_reset_rng(rng: CrandLike) -> list[float]:
    """Advance RNG through `gameplay_reset_state()` up to `terrain_generate_random()`.

    Native draws the score tag, one `anim_phase` per creature slot, then the score
    tag again. Returns the creature anim phases.
    """

    rng.rand_tagged(RngCallerStatic.GAMEPLAY_RESET_STATE_RANDOM_TAG)
    anim_phases = [
        float(rng.rand_tagged(RngCallerStatic.GAMEPLAY_RESET_STATE_CREATURE_ANIM_PHASE) % 31)
        for _ in range(CREATURE_POOL_SIZE)
    ]
    rng.rand_tagged(RngCallerStatic.GAMEPLAY_RESET_STATE_HIGHSCORE_RANDOM_TAG)
    return anim_phases
