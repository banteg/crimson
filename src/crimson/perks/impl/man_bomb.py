from __future__ import annotations

import math

from ...projectiles.types import ProjectileTemplateId
from ...rng_caller_static import RngCallerStatic
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.hook_types import PerkHooks
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_man_bomb(ctx: PlayerPerkTickCtx) -> None:
    if not perk_active(ctx.player, PerkId.MAN_BOMB):
        ctx.player.man_bomb_timer = 0.0
        return

    ctx.player.man_bomb_timer += ctx.dt
    if ctx.player.man_bomb_timer > ctx.state.perk_intervals.man_bomb:
        owner = ctx.owner_ref_for_player_projectiles(ctx.state, ctx.player.index)
        for idx in range(8):
            type_id = ProjectileTemplateId.ION_MINIGUN if ((idx & 1) == 0) else ProjectileTemplateId.ION_RIFLE
            angle = (
                (float(ctx.state.rng.rand(caller=RngCallerStatic.PLAYER_UPDATE) % 50) * 0.01)
                + float(idx) * (math.pi / 4.0)
                - 0.25
            )
            ctx.projectile_spawn(
                ctx.state,
                players=ctx.players,
                pos=ctx.player.pos,
                angle=angle,
                type_id=type_id,
                owner=owner,
                owner_player_index=ctx.player.index,
            )
        ctx.state.sfx_queue.append("sfx_explosion_small")

        ctx.player.man_bomb_timer -= ctx.state.perk_intervals.man_bomb
        ctx.state.perk_intervals.man_bomb = 4.0


HOOKS = PerkHooks(
    perk_id=PerkId.MAN_BOMB,
    player_tick_steps=(tick_man_bomb,),
)
