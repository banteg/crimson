from __future__ import annotations

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ..math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sqrt, x87_pc24_sub
from ..owner_ref import OwnerRef
from ..projectiles.types import ProjectileTemplateId
from ..rng_caller_static import RngCallerStatic
from ..weapon_runtime.spawn import owner_ref_for_player, projectile_spawn
from .apply_context import BonusApplyCtx


def apply_nuke(ctx: BonusApplyCtx) -> None:
    # `bonus_apply` (crimsonland.exe @ 0x00409890) starts screen shake via:
    #   camera_shake_pulses = 0x14;
    #   camera_shake_timer = 0.2f;
    ctx.state.camera_shake_pulses = 0x14
    ctx.state.camera_shake_timer = 0.2

    origin = ctx.origin_pos
    rng = ctx.state.rng

    bullet_count = int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_BULLET_COUNT)) & 3
    bullet_count += 4
    for _ in range(bullet_count):
        angle = x87_pc24_mul(
            float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_ANGLE)) % 628),
            f32(0.01),
        )
        proj_id = projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos=origin,
            angle=float(angle),
            type_id=ProjectileTemplateId.PISTOL,
            owner=OwnerRef.from_local_player(0),
            owner_player_index=ctx.player.index,
        )
        if proj_id != -1:
            speed_scale = x87_pc24_add(
                x87_pc24_mul(
                    float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_SPEED_SCALE)) % 50),
                    f32(0.01),
                ),
                f32(0.5),
            )
            projectile = ctx.state.projectiles.entries[proj_id]
            projectile.speed_scale = x87_pc24_mul(projectile.speed_scale, speed_scale)

    gauss_angle_1 = x87_pc24_mul(
        float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_1)) % 628),
        f32(0.01),
    )
    projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=float(gauss_angle_1),
        type_id=ProjectileTemplateId.GAUSS_GUN,
        owner=OwnerRef.from_local_player(0),
        owner_player_index=ctx.player.index,
    )
    gauss_angle_2 = x87_pc24_mul(
        float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_2)) % 628),
        f32(0.01),
    )
    projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=float(gauss_angle_2),
        type_id=ProjectileTemplateId.GAUSS_GUN,
        owner=OwnerRef.from_local_player(0),
        owner_player_index=ctx.player.index,
    )

    ctx.state.effects.spawn_explosion_burst(
        pos=origin,
        scale=1.0,
        rng=ctx.state.rng,
        detail_preset=int(ctx.detail_preset),
    )

    creatures = ctx.creatures
    if creatures:
        creature_damage_runtime = ctx.creature_damage_runtime
        ctx.state.bonus_spawn_guard = True
        for idx, creature in enumerate(creatures):
            # Native applies explosion damage to any active creature, including
            # those already in the death/corpse state (this shrinks corpses
            # faster via the hp<=0 path in creature_apply_damage).
            if not creature.active:
                continue
            dx = x87_pc24_sub(creature.pos.x, origin.x)
            dy = x87_pc24_sub(creature.pos.y, origin.y)
            if abs(dx) > 256.0 or abs(dy) > 256.0:
                continue
            distance_sq = x87_pc24_add(x87_pc24_mul(dx, dx), x87_pc24_mul(dy, dy))
            distance = x87_pc24_sqrt(distance_sq)
            damage_base = x87_pc24_sub(256.0, distance)
            if damage_base > 0.0:
                damage = x87_pc24_mul(damage_base, 5.0)
                if creature_damage_runtime is not None:
                    creature_damage_runtime.apply_creature_damage(
                        int(idx),
                        float(damage),
                        3,
                        Vec2(),
                        owner_ref_for_player(ctx.player.index),
                    )
                else:
                    creature.hp = x87_pc24_sub(creature.hp, damage)
        ctx.state.bonus_spawn_guard = False

    ctx.state.sfx_queue.append(SfxId.EXPLOSION_LARGE)
    ctx.state.sfx_queue.append(SfxId.SHOCKWAVE)
