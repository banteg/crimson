from __future__ import annotations

import math

from grim.color import RGBA
from grim.geom import Vec2

from ..projectiles import ProjectileTypeId
from .helpers import perk_active
from .hook_types import PerkHooks
from .ids import PerkId
from .player_tick_context import PlayerPerkTickCtx


def tick_fire_cough(ctx: PlayerPerkTickCtx) -> None:
    if not perk_active(ctx.player, PerkId.FIRE_CAUGH):
        ctx.player.fire_cough_timer = 0.0
        return

    ctx.player.fire_cough_timer += ctx.dt
    if ctx.player.fire_cough_timer <= ctx.state.perk_intervals.fire_cough:
        return

    owner_id = ctx.owner_id_for_player_projectiles(ctx.state, ctx.player.index)
    ctx.state.sfx_queue.append("sfx_autorifle_fire")
    ctx.state.sfx_queue.append("sfx_plasmaminigun_fire")

    aim_heading = float(ctx.player.aim_heading)
    muzzle = ctx.player.pos + Vec2.from_heading(aim_heading).rotated(-0.150915) * 16.0

    aim = ctx.player.aim
    dist = (aim - ctx.player.pos).length()
    max_offset = dist * float(ctx.player.spread_heat) * 0.5
    dir_angle = float(int(ctx.state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(ctx.state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    jitter = aim + Vec2.from_angle(dir_angle) * offset
    angle = (jitter - ctx.player.pos).to_heading()
    ctx.projectile_spawn(
        ctx.state,
        players=[ctx.player],
        pos=muzzle,
        angle=angle,
        type_id=ProjectileTypeId.FIRE_BULLETS,
        owner_id=owner_id,
    )

    vel = Vec2.from_angle(aim_heading) * 25.0
    ctx.state.sprite_effects.spawn(pos=muzzle, vel=vel, scale=1.0, color=RGBA(0.5, 0.5, 0.5, 0.413))

    ctx.player.fire_cough_timer -= ctx.state.perk_intervals.fire_cough
    ctx.state.perk_intervals.fire_cough = float(ctx.state.rng.rand() % 4) + 2.0


HOOKS = PerkHooks(
    perk_id=PerkId.FIRE_CAUGH,
    player_tick_steps=(tick_fire_cough,),
)
