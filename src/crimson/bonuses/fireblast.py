from __future__ import annotations

from ..projectiles import ProjectileTypeId
from ..weapon_runtime.spawn import owner_id_for_player, spawn_projectile_ring
from .apply_context import BonusApplyCtx


def apply_fireblast(ctx: BonusApplyCtx) -> None:
    origin_pos = ctx.origin_pos()
    owner_id = owner_id_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else -100
    ctx.state.bonus_spawn_guard = True
    spawn_projectile_ring(
        ctx.state,
        origin_pos,
        count=16,
        angle_offset=0.0,
        type_id=ProjectileTypeId.PLASMA_RIFLE,
        owner_id=int(owner_id),
        players=ctx.players,
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append("sfx_explosion_medium")
