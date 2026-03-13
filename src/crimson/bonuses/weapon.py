from __future__ import annotations

from ..perks import PerkId
from ..perks.helpers import perk_active
from ..sim.state_types import WeaponSlot
from ..weapon_runtime.assign import weapon_assign_player
from ..weapons import WeaponId
from .apply_context import BonusApplyCtx


def apply_weapon(ctx: BonusApplyCtx) -> None:
    weapon_id = WeaponId(ctx.amount)
    if perk_active(ctx.player, PerkId.ALTERNATE_WEAPON) and ctx.player.alt_weapon is None:
        primary = ctx.player.weapon
        ctx.player.alt_weapon = WeaponSlot(
            weapon_id=primary.weapon_id,
            clip_size=int(primary.clip_size),
            ammo=float(primary.ammo),
            reload_active=bool(primary.reload_active),
            reload_timer=float(primary.reload_timer),
            reload_timer_max=float(primary.reload_timer_max),
            shot_cooldown=float(primary.shot_cooldown),
        )
    weapon_assign_player(ctx.player, weapon_id, state=ctx.state)
