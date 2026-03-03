from __future__ import annotations

import math

from ...owner_ref import OwnerRef
from ...projectiles.types import ProjectileTemplateId
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.hook_types import PerkHooks
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_hot_tempered(ctx: PlayerPerkTickCtx) -> None:
    if not perk_active(ctx.player, PerkId.HOT_TEMPERED):
        ctx.player.hot_tempered_timer = 0.0
        return

    ctx.player.hot_tempered_timer += ctx.dt
    if ctx.player.hot_tempered_timer <= ctx.state.perk_intervals.hot_tempered:
        return

    owner = (
        ctx.owner_ref_for_player(ctx.player.index)
        if ctx.state.friendly_fire_enabled
        else OwnerRef.from_local_player(0)
    )
    for idx in range(8):
        type_id = ProjectileTemplateId.PLASMA_MINIGUN if ((idx & 1) == 0) else ProjectileTemplateId.PLASMA_RIFLE
        angle = float(idx) * (math.pi / 4.0)
        ctx.projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos=ctx.player_pos_before_move,
            angle=angle,
            type_id=type_id,
            owner=owner,
            owner_player_index=ctx.player.index,
        )
    ctx.state.sfx_queue.append("sfx_explosion_small")

    ctx.player.hot_tempered_timer -= ctx.state.perk_intervals.hot_tempered
    ctx.state.perk_intervals.hot_tempered = float(ctx.state.rng.rand() % 8) + 2.0


HOOKS = PerkHooks(
    perk_id=PerkId.HOT_TEMPERED,
    player_tick_steps=(tick_hot_tempered,),
)
