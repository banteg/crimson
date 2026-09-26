from __future__ import annotations

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..math_parity import native_chain_angle_from_delta, x87_pc24_sub
from ..owner_ref import OwnerRef
from ..projectiles.runtime.collision import creature_find_nearest_alive
from ..projectiles.types import ProjectileTemplateId
from ..weapon_runtime.spawn import owner_ref_for_player, projectile_spawn
from .apply_context import BonusApplyCtx


def apply_shock_chain(ctx: BonusApplyCtx) -> None:
    creatures = ctx.creatures
    if not creatures:
        return

    origin = ctx.origin_pos
    best_idx = creature_find_nearest_alive(
        creatures=creatures,
        origin=origin,
        preserve_bugs=bool(ctx.state.preserve_bugs),
    )

    if best_idx < 0:
        return

    target = creatures[best_idx]
    angle = native_chain_angle_from_delta(
        dx=x87_pc24_sub(target.pos.x, origin.x),
        dy=x87_pc24_sub(target.pos.y, origin.y),
    )
    owner = owner_ref_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else OwnerRef.from_local_player(0)

    ctx.state.bonus_spawn_guard = True
    ctx.state.shock_chain_links_left = 0x20
    ctx.state.shock_chain_projectile_id = projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=angle,
        type_id=ProjectileTemplateId.ION_RIFLE,
        owner=owner,
        owner_player_index=ctx.player.index,
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append(SfxRequest(SfxId.SHOCK_HIT_01, ctx.origin_pos))
