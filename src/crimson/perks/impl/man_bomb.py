from __future__ import annotations

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ...math_parity import NATIVE_QUARTER_PI, f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from ...projectiles.types import ProjectileTemplateId
from ...rng_caller_static import RngCallerStatic
from ..helpers import perk_active
from ..ids import PerkId
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
            # player_update 0x41394d: PC24 multiply, multiply, add, subtract.
            angle = x87_pc24_sub(
                x87_pc24_add(
                    x87_pc24_mul(float(ctx.state.rng.rand_tagged(caller) % 50), f32(0.01)),
                    x87_pc24_mul(float(idx), NATIVE_QUARTER_PI),
                ),
                0.25,
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
        ctx.state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_SMALL, ctx.player.pos))

        ctx.player.man_bomb_timer = x87_pc24_sub(
            float(ctx.player.man_bomb_timer),
            float(ctx.state.perk_intervals.man_bomb),
        )
        ctx.state.perk_intervals.man_bomb = f32(4.0)
