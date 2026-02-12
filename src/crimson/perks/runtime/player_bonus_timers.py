from __future__ import annotations

from .effects_context import PerksUpdateEffectsCtx


def update_player_bonus_timers(ctx: PerksUpdateEffectsCtx) -> None:
    # Native `perks_update_effects` decrements per-player shield/fire-bullets/speed
    # timers before `player_update` reads them for this frame.
    for player in ctx.players:
        if player.shield_timer <= 0.0:
            player.shield_timer = 0.0
        else:
            player.shield_timer = float(player.shield_timer) - float(ctx.dt)

        if player.fire_bullets_timer <= 0.0:
            player.fire_bullets_timer = 0.0
        else:
            player.fire_bullets_timer = float(player.fire_bullets_timer) - float(ctx.dt)

        if player.speed_bonus_timer <= 0.0:
            player.speed_bonus_timer = 0.0
        else:
            player.speed_bonus_timer = float(player.speed_bonus_timer) - float(ctx.dt)
