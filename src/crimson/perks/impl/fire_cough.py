from __future__ import annotations

from grim.color import RGBA
from grim.geom import Vec2
from grim.sfx_map import SfxId

from ...math_parity import (
    native_fire_muzzle_pos,
    native_shot_angle_from_jitter_draws,
    x87_pc24_add,
    x87_pc24_sub,
)
from ...projectiles.types import ProjectileTemplateId
from ...rng_caller_static import RngCallerStatic
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_fire_cough(ctx: PlayerPerkTickCtx) -> None:
    if not perk_active(ctx.perk_player, PerkId.FIRE_CAUGH):
        ctx.player.fire_cough_timer = 0.0
        return

    ctx.player.fire_cough_timer = x87_pc24_add(ctx.player.fire_cough_timer, ctx.dt)
    if ctx.player.fire_cough_timer <= ctx.state.perk_intervals.fire_cough:
        return

    owner = ctx.owner_ref_for_player_projectiles(ctx.state, ctx.player.index)
    ctx.state.sfx_queue.append(SfxId.AUTORIFLE_FIRE)
    ctx.state.sfx_queue.append(SfxId.PLASMAMINIGUN_FIRE)

    aim_heading = float(ctx.player.aim_heading)
    origin_pos = ctx.player_pos_before_move
    muzzle = native_fire_muzzle_pos(origin_pos, aim_heading)

    aim = ctx.player.aim
    dir_roll = ctx.state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_SPREAD_DIR)
    mag_roll = ctx.state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_SPREAD_MAG)
    angle = native_shot_angle_from_jitter_draws(
        aim=aim,
        player_pos=origin_pos,
        spread_heat=float(ctx.player.spread_heat),
        dir_draw=dir_roll,
        mag_draw=mag_roll,
    )
    ctx.projectile_spawn(
        ctx.state,
        players=[ctx.player],
        pos=muzzle,
        angle=angle,
        type_id=ProjectileTemplateId.FIRE_BULLETS,
        owner=owner,
        owner_player_index=ctx.player.index,
    )

    vel = Vec2.from_angle(aim_heading) * 25.0
    ctx.state.sprite_effects.spawn(pos=muzzle, vel=vel, scale=1.0, color=RGBA(0.5, 0.5, 0.5, 0.413))

    ctx.player.fire_cough_timer = x87_pc24_sub(
        ctx.player.fire_cough_timer,
        ctx.state.perk_intervals.fire_cough,
    )
    interval_roll = ctx.state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_INTERVAL_RESET)
    ctx.state.perk_intervals.fire_cough = float(interval_roll % 4) + 2.0
