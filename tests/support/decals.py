from __future__ import annotations

from collections.abc import Sequence

from crimson.effects import FxQueue
from crimson.projectiles.types import ProjectileHit
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.presentation_step import queue_projectile_decals_post_hit, queue_projectile_decals_pre_hit
from crimson.sim.state_types import PlayerState
from grim.rand import CrandLike


def queue_projectile_decals(
    *,
    state: GameplayState,
    players: Sequence[PlayerState],
    fx_queue: FxQueue,
    hits: list[ProjectileHit],
    rng: CrandLike,
    detail_preset: int,
    violence_disabled: int,
) -> None:
    """Queue each hit's decals with the pre/post-hit pair the world step runs per hit."""

    for hit in hits:
        post_ctx = queue_projectile_decals_pre_hit(
            state=state,
            players=players,
            fx_queue=fx_queue,
            hit=hit,
            rng=rng,
            detail_preset=detail_preset,
            violence_disabled=violence_disabled,
        )
        queue_projectile_decals_post_hit(
            state=state,
            fx_queue=fx_queue,
            post_ctx=post_ctx,
            rng=rng,
            detail_preset=detail_preset,
        )
