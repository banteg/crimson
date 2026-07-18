from __future__ import annotations

from ...math_parity import f32, x87_pc24_sub
from .effects_context import PerksUpdateEffectsCtx


def update_player_bonus_timers(ctx: PerksUpdateEffectsCtx) -> None:
    # Native `perks_update_effects` decrements per-player shield/fire-bullets/speed
    # timers before `player_update` reads them for this frame.
    dt = f32(float(ctx.dt))
    for player in ctx.players:
        if player.shield_timer <= 0.0:
            player.shield_timer = 0.0
        else:
            player.shield_timer = x87_pc24_sub(f32(float(player.shield_timer)), dt)

        if player.fire_bullets_timer <= 0.0:
            player.fire_bullets_timer = 0.0
        else:
            player.fire_bullets_timer = x87_pc24_sub(
                f32(float(player.fire_bullets_timer)),
                dt,
            )

        if player.speed_bonus_timer <= 0.0:
            player.speed_bonus_timer = 0.0
        else:
            player.speed_bonus_timer = x87_pc24_sub(
                f32(float(player.speed_bonus_timer)),
                dt,
            )
