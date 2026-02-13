from __future__ import annotations

from .primary_beam import draw_beam_effect
from .primary_bullet import draw_bullet_trail
from .primary_plasma import draw_plasma_particles
from .primary_special import draw_plague_spreader, draw_pulse_gun, draw_splitter_or_blade
from .types import ProjectileDrawCtx

PRIMARY_PROJECTILE_DRAW_HANDLERS = (
    draw_bullet_trail,
    draw_plasma_particles,
    draw_beam_effect,
    draw_pulse_gun,
    draw_splitter_or_blade,
    draw_plague_spreader,
)


def draw_projectile_from_registry(ctx: ProjectileDrawCtx) -> bool:
    for handler in PRIMARY_PROJECTILE_DRAW_HANDLERS:
        if handler(ctx):
            return True
    return False


__all__ = ["draw_projectile_from_registry"]
