from __future__ import annotations

from grim.geom import Vec2

from ..projectiles import ProjectileTypeId
from ..weapon_runtime.spawn import owner_id_for_player, projectile_spawn
from .apply_context import BonusApplyCtx


def apply_nuke(ctx: BonusApplyCtx) -> None:
    # `bonus_apply` (crimsonland.exe @ 0x00409890) starts screen shake via:
    #   camera_shake_pulses = 0x14;
    #   camera_shake_timer = 0.2f;
    ctx.state.camera_shake_pulses = 0x14
    ctx.state.camera_shake_timer = 0.2

    origin_pos = ctx.origin_pos()
    origin = origin_pos.pos
    rand = ctx.state.rng.rand

    bullet_count = int(rand()) & 3
    bullet_count += 4
    for _ in range(bullet_count):
        angle = float(int(rand()) % 0x274) * 0.01
        proj_id = projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos=origin,
            angle=float(angle),
            type_id=int(ProjectileTypeId.PISTOL),
            owner_id=-100,
        )
        if proj_id != -1:
            speed_scale = float(int(rand()) % 0x32) * 0.01 + 0.5
            ctx.state.projectiles.entries[proj_id].speed_scale *= float(speed_scale)

    for _ in range(2):
        angle = float(int(rand()) % 0x274) * 0.01
        projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos=origin,
            angle=float(angle),
            type_id=int(ProjectileTypeId.GAUSS_GUN),
            owner_id=-100,
        )

    ctx.state.effects.spawn_explosion_burst(
        pos=origin,
        scale=1.0,
        rand=rand,
        detail_preset=int(ctx.detail_preset),
    )

    creatures = ctx.creatures
    if creatures:
        prev_guard = bool(ctx.state.bonus_spawn_guard)
        ctx.state.bonus_spawn_guard = True
        for idx, creature in enumerate(creatures):
            # Native applies explosion damage to any active creature, including
            # those already in the death/corpse state (this shrinks corpses
            # faster via the hp<=0 path in creature_apply_damage).
            if not creature.active:
                continue
            delta = creature.pos - origin
            if abs(delta.x) > 256.0 or abs(delta.y) > 256.0:
                continue
            dist = delta.length()
            if dist < 256.0:
                damage = (256.0 - dist) * 5.0
                if ctx.apply_creature_damage is not None:
                    ctx.apply_creature_damage(
                        int(idx),
                        float(damage),
                        3,
                        Vec2(),
                        owner_id_for_player(ctx.player.index),
                    )
                else:
                    creature.hp -= float(damage)
        ctx.state.bonus_spawn_guard = prev_guard

    ctx.state.sfx_queue.append("sfx_explosion_large")
    ctx.state.sfx_queue.append("sfx_shockwave")
