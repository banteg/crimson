from __future__ import annotations

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..owner_ref import OwnerRef
from ..projectiles.types import ProjectileTemplateId
from ..weapon_runtime.spawn import owner_ref_for_player, spawn_projectile_ring
from .apply_context import BonusApplyCtx


def apply_fireblast(ctx: BonusApplyCtx) -> None:
    origin = ctx.origin_pos
    owner = owner_ref_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else OwnerRef.from_local_player(0)
    ctx.state.bonus_spawn_guard = True
    spawn_projectile_ring(
        ctx.state,
        origin,
        count=16,
        angle_offset=0.0,
        type_id=ProjectileTemplateId.PLASMA_RIFLE,
        owner=owner,
        owner_player_index=ctx.player.index,
        players=ctx.players,
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_MEDIUM, ctx.origin_pos))
