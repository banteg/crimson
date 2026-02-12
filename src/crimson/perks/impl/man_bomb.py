from __future__ import annotations

import math

from ...projectiles import ProjectileTypeId
from ..helpers import perk_active
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_man_bomb(ctx: PlayerPerkTickCtx) -> None:
    if not perk_active(ctx.player, PerkId.MAN_BOMB):
        ctx.player.man_bomb_timer = 0.0
        return

    ctx.player.man_bomb_timer += ctx.dt
    if ctx.player.man_bomb_timer > ctx.state.perk_intervals.man_bomb:
        owner_id = ctx.owner_id_for_player_projectiles(ctx.state, ctx.player.index)
        for idx in range(8):
            type_id = ProjectileTypeId.ION_MINIGUN if ((idx & 1) == 0) else ProjectileTypeId.ION_RIFLE
            angle = (float(ctx.state.rng.rand() % 50) * 0.01) + float(idx) * (math.pi / 4.0) - 0.25
            ctx.projectile_spawn(
                ctx.state,
                players=ctx.players,
                pos=ctx.player.pos,
                angle=angle,
                type_id=type_id,
                owner_id=owner_id,
            )
        ctx.state.sfx_queue.append("sfx_explosion_small")

        ctx.player.man_bomb_timer -= ctx.state.perk_intervals.man_bomb
        ctx.state.perk_intervals.man_bomb = 4.0

    if not ctx.stationary:
        ctx.player.man_bomb_timer = 0.0


HOOKS = PerkHooks(
    perk_id=PerkId.MAN_BOMB,
    player_tick_steps=(tick_man_bomb,),
)
