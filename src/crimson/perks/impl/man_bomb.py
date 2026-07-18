from __future__ import annotations

import math

from grim.sfx_map import SfxId

from ...math_parity import f32, x87_pc24_add, x87_pc24_sub
from ...projectiles.types import ProjectileTemplateId
from ...rng_caller_static import RngCallerStatic
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.hook_types import PerkHooks
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_man_bomb(ctx: PlayerPerkTickCtx) -> None:
    if not perk_active(ctx.perk_player, PerkId.MAN_BOMB):
        ctx.player.man_bomb_timer = 0.0
        return

    ctx.player.man_bomb_timer = x87_pc24_add(
        float(ctx.player.man_bomb_timer),
        float(ctx.dt),
    )
    if ctx.player.man_bomb_timer > ctx.state.perk_intervals.man_bomb:
        owner = ctx.owner_ref_for_player_projectiles(ctx.state, ctx.player.index)
        for idx in range(8):
            type_id = ProjectileTemplateId.ION_MINIGUN if ((idx & 1) == 0) else ProjectileTemplateId.ION_RIFLE
            caller = (
                RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE
                if type_id is ProjectileTemplateId.ION_MINIGUN
                else RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE
            )
            angle = (
                (float(ctx.state.rng.rand_tagged(caller) % 50) * 0.01)
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
        ctx.state.sfx_queue.append(SfxId.EXPLOSION_SMALL)

        ctx.player.man_bomb_timer = x87_pc24_sub(
            float(ctx.player.man_bomb_timer),
            float(ctx.state.perk_intervals.man_bomb),
        )
        ctx.state.perk_intervals.man_bomb = f32(4.0)


HOOKS = PerkHooks(
    perk_id=PerkId.MAN_BOMB,
    player_tick_steps=(tick_man_bomb,),
)
