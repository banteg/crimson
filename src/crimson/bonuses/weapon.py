from __future__ import annotations

from ..perks import PerkId
from ..perks.helpers import perk_active
from ..weapon_runtime.assign import weapon_assign_player
from .apply_context import BonusApplyCtx


def apply_weapon(ctx: BonusApplyCtx) -> None:
    weapon_id = int(ctx.amount)
    if perk_active(ctx.player, PerkId.ALTERNATE_WEAPON) and ctx.player.alt_weapon_id is None:
        ctx.player.alt_weapon_id = int(ctx.player.weapon_id)
        ctx.player.alt_clip_size = int(ctx.player.clip_size)
        ctx.player.alt_ammo = float(ctx.player.ammo)
        ctx.player.alt_reload_active = bool(ctx.player.reload_active)
        ctx.player.alt_reload_timer = float(ctx.player.reload_timer)
        ctx.player.alt_shot_cooldown = float(ctx.player.shot_cooldown)
        ctx.player.alt_reload_timer_max = float(ctx.player.reload_timer_max)
    weapon_assign_player(ctx.player, weapon_id, state=ctx.state)
