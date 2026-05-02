from __future__ import annotations

from grim.geom import Vec2
from grim.sfx_map import SfxId

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
        angle = float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_ANGLE)) % 628) * 0.01
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
            speed_scale = (
                float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_SPEED_SCALE)) % 50) * 0.01 + 0.5
            )
            ctx.state.projectiles.entries[proj_id].speed_scale *= float(speed_scale)

    gauss_angle_1 = float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_1)) % 628) * 0.01
    projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=float(gauss_angle_1),
        type_id=ProjectileTemplateId.GAUSS_GUN,
        owner=OwnerRef.from_local_player(0),
        owner_player_index=ctx.player.index,
    )
    gauss_angle_2 = float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_2)) % 628) * 0.01
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
        apply_creature_damage = ctx.apply_creature_damage
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
                if apply_creature_damage is not None:
                    apply_creature_damage(
                        int(idx),
                        float(damage),
                        3,
                        Vec2(),
                        owner_ref_for_player(ctx.player.index),
                    )
                else:
                    creature.hp -= float(damage)
        ctx.state.bonus_spawn_guard = prev_guard

    ctx.state.sfx_queue.append(SfxId.EXPLOSION_LARGE)
    ctx.state.sfx_queue.append(SfxId.SHOCKWAVE)
