from __future__ import annotations

from .apply_context import BonusApplyCtx


def apply_weapon_power_up(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.weapon_power_up)
    if old <= 0.0:
        ctx.register_global("weapon_power_up")
    ctx.state.bonuses.weapon_power_up = float(old + float(ctx.amount) * ctx.economist_multiplier)
    ctx.player.weapon_reset_latch = 0
    ctx.player.shot_cooldown = 0.0
    ctx.player.reload_active = False
    ctx.player.reload_timer = 0.0
    ctx.player.reload_timer_max = 0.0
    ctx.player.ammo = float(ctx.player.clip_size)
