from __future__ import annotations

import math
from typing import Callable, MutableSequence, Sequence

from grim.geom import Vec2

from ...math_parity import NATIVE_HALF_PI, f32
from ...perks import PerkId
from ...weapons import weapon_entry_for_projectile_type_id
from ..types import (
    CreatureDamageApplier,
    Damageable,
    MAIN_PROJECTILE_POOL_SIZE,
    PlayerDamageable,
    Projectile,
    ProjectileHit,
    ProjectileRuntimeState,
    ProjectileTypeId,
    _EffectsLike,
    _rng_zero,
)
from .behaviors import (
    PROJECTILE_BEHAVIOR_BY_TYPE_ID,
    _DEFAULT_BEHAVIOR,
    _PROJECTILE_HIT_PERK_HOOKS,
    _ProjectileHitInfo,
    _ProjectileHitPerkCtx,
    _ProjectileUpdateCtx,
)
from .collision import _apply_damage_to_creature, _hit_radius_for, _within_native_find_radius

class ProjectilePool:
    def __init__(self, *, size: int = MAIN_PROJECTILE_POOL_SIZE) -> None:
        self._entries = [Projectile() for _ in range(size)]

    @property
    def entries(self) -> list[Projectile]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def spawn(
        self,
        *,
        pos: Vec2,
        angle: float,
        type_id: int,
        owner_id: int,
        base_damage: float = 0.0,
        hits_players: bool = False,
    ) -> int:
        index = None
        for i, entry in enumerate(self._entries):
            if not entry.active:
                index = i
                break
        if index is None:
            index = len(self._entries) - 1
        entry = self._entries[index]

        entry.active = True
        entry.angle = angle
        entry.pos = pos
        entry.origin = pos
        entry.type_id = int(type_id)
        entry.life_timer = 0.4
        entry.reserved = 0.0
        entry.speed_scale = 1.0
        entry.base_damage = float(base_damage)
        weapon_entry = weapon_entry_for_projectile_type_id(entry.type_id)
        if weapon_entry is not None and weapon_entry.projectile_meta is not None:
            entry.base_damage = float(weapon_entry.projectile_meta)
        entry.owner_id = int(owner_id)
        entry.hits_players = bool(hits_players)

        if type_id == ProjectileTypeId.ION_MINIGUN:
            entry.hit_radius = 3.0
            entry.damage_pool = 1.0
            return index
        if type_id == ProjectileTypeId.ION_RIFLE:
            entry.hit_radius = 5.0
            entry.damage_pool = 1.0
            return index
        if type_id in (ProjectileTypeId.ION_CANNON, ProjectileTypeId.PLASMA_CANNON):
            entry.hit_radius = 10.0
        else:
            entry.hit_radius = 1.0
            if type_id == ProjectileTypeId.GAUSS_GUN:
                entry.damage_pool = 300.0
                return index
            if type_id == ProjectileTypeId.FIRE_BULLETS:
                entry.damage_pool = 240.0
                return index
            if type_id == ProjectileTypeId.BLADE_GUN:
                entry.damage_pool = 50.0
                return index
        entry.damage_pool = 1.0
        return index

    def iter_active(self) -> list[Projectile]:
        return [entry for entry in self._entries if entry.active]

    def update(
        self,
        dt: float,
        creatures: Sequence[Damageable],
        *,
        world_size: float,
        damage_scale_by_type: dict[int, float] | None = None,
        damage_scale_default: float = 1.0,
        ion_aoe_scale: float = 1.0,
        detail_preset: int = 5,
        rng: Callable[[], int] | None = None,
        runtime_state: ProjectileRuntimeState | None = None,
        players: Sequence[PlayerDamageable] | None = None,
        apply_player_damage: Callable[[int, float], None] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
        on_hit: Callable[[ProjectileHit], object | None] | None = None,
        on_hit_post: Callable[[ProjectileHit, object | None], None] | None = None,
    ) -> list[ProjectileHit]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.
        """

        if dt <= 0.0:
            return []

        barrel_greaser_active = False
        ion_gun_master_active = False
        ion_scale = float(ion_aoe_scale)
        poison_idx = int(PerkId.POISON_BULLETS)
        if players is not None:
            barrel_idx = int(PerkId.BARREL_GREASER)
            ion_idx = int(PerkId.ION_GUN_MASTER)
            for player in players:
                perk_counts = player.perk_counts

                if 0 <= barrel_idx < len(perk_counts) and int(perk_counts[barrel_idx]) > 0:
                    barrel_greaser_active = True
                if 0 <= ion_idx < len(perk_counts) and int(perk_counts[ion_idx]) > 0:
                    ion_gun_master_active = True
                if barrel_greaser_active and ion_gun_master_active:
                    break

        if ion_scale == 1.0 and ion_gun_master_active:
            ion_scale = 1.2

        def _owner_perk_active(owner_id: int, perk_idx: int) -> bool:
            if players is None:
                return False
            if owner_id == -100:
                player_index = 0
            elif owner_id < 0:
                player_index = -1 - int(owner_id)
            else:
                return False
            if not (0 <= player_index < len(players)):
                return False
            perk_counts = players[player_index].perk_counts
            return 0 <= perk_idx < len(perk_counts) and int(perk_counts[perk_idx]) > 0

        if damage_scale_by_type is None:
            damage_scale_by_type = {}

        if rng is None:
            rng = _rng_zero

        effects: _EffectsLike | None = None
        sfx_queue: MutableSequence[str] | None = None
        if runtime_state is not None:
            effects = runtime_state.effects
            sfx_queue = runtime_state.sfx_queue

        hits: list[ProjectileHit] = []
        margin = 64.0

        def _damage_scale(type_id: int) -> float:
            value = damage_scale_by_type.get(type_id)
            if value is None:
                return float(damage_scale_default)
            return float(value)

        def _damage_type_for() -> int:
            return 1

        ctx = _ProjectileUpdateCtx(
            pool=self,
            creatures=creatures,
            dt=float(dt),
            ion_scale=float(ion_scale),
            detail_preset=int(detail_preset),
            rng=rng,
            runtime_state=runtime_state,
            effects=effects,
            sfx_queue=sfx_queue,
            apply_creature_damage=apply_creature_damage,
        )

        def _reset_shock_chain_if_owner(index: int) -> None:
            if runtime_state is None:
                return
            if runtime_state.shock_chain_projectile_id != index:
                return
            runtime_state.shock_chain_projectile_id = -1
            runtime_state.shock_chain_links_left = 0

        for proj_index, proj in enumerate(self._entries):
            if not proj.active:
                continue
            behavior = PROJECTILE_BEHAVIOR_BY_TYPE_ID.get(int(proj.type_id), _DEFAULT_BEHAVIOR)

            if proj.life_timer <= 0.0:
                proj.active = False
                # Native `projectile_update` clears the active flag but still
                # runs this tick's life_timer branch, so expired ion projectiles
                # can apply one final linger AoE pass.

            if proj.life_timer < 0.4:
                if int(proj.type_id) in (int(ProjectileTypeId.ION_RIFLE), int(ProjectileTypeId.ION_MINIGUN)):
                    _reset_shock_chain_if_owner(proj_index)
                behavior.linger(ctx, proj)
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > world_size + margin
                or proj.pos.y > world_size + margin
            ):
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            steps = int(proj.base_damage)
            if steps <= 0:
                steps = 1
            if barrel_greaser_active and int(proj.owner_id) < 0:
                steps *= 2

            direction = Vec2.from_heading(float(proj.angle))
            acc = Vec2()
            step = 0
            while step < steps:
                step_scale = float(f32(float(dt) * 20.0 * float(proj.speed_scale) * 3.0))
                acc = Vec2(
                    float(f32(float(acc.x) + float(direction.x) * float(step_scale))),
                    float(f32(float(acc.y) + float(direction.y) * float(step_scale))),
                )

                if acc.length() >= 4.0 or steps <= step + 3:
                    move = acc
                    proj.pos = Vec2(
                        float(f32(float(proj.pos.x) + float(move.x))),
                        float(f32(float(proj.pos.y) + float(move.y))),
                    )
                    acc = Vec2()

                    hit_idx = None
                    owner_creature_idx = int(proj.owner_id)
                    for idx, creature in enumerate(creatures):
                        if not creature.active:
                            continue
                        if creature.hitbox_size <= 5.0:
                            continue
                        if _within_native_find_radius(
                            origin=proj.pos,
                            target=creature.pos,
                            radius=float(proj.hit_radius),
                            target_size=float(creature.size),
                        ):
                            hit_idx = idx
                            break

                    owner_collision = hit_idx is not None and int(hit_idx) == owner_creature_idx
                    if owner_collision:
                        # Native `creature_find_in_radius` does not skip owner id during
                        # search; owner hits are discarded after the first match instead of
                        # continuing to a later candidate in the same tick.
                        hit_idx = None

                    if hit_idx is None:
                        can_hit_players = True
                        if runtime_state is not None and int(proj_index) == int(runtime_state.shock_chain_projectile_id):
                            # Native skips `player_find_in_radius` for the currently tracked
                            # shock-chain projectile slot in this branch.
                            can_hit_players = False

                        if proj.hits_players and can_hit_players:
                            hit_player_idx = None
                            owner_id = int(proj.owner_id)
                            owner_player_index = -1 - owner_id if owner_id < 0 and owner_id != -100 else None
                            if players is not None:
                                for idx, player in enumerate(players):
                                    if owner_player_index is not None and idx == owner_player_index:
                                        continue
                                    if float(player.health) <= 0.0:
                                        continue
                                    if _within_native_find_radius(
                                        origin=proj.pos,
                                        target=player.pos,
                                        radius=float(proj.hit_radius),
                                        target_size=float(player.size),
                                    ):
                                        hit_player_idx = idx
                                        break

                            if hit_player_idx is None:
                                step += 3
                                continue

                            type_id = proj.type_id
                            assert players is not None
                            player = players[int(hit_player_idx)]
                            hit = ProjectileHit(
                                type_id=int(type_id),
                                origin=proj.origin,
                                hit=proj.pos,
                                target=player.pos,
                            )
                            hits.append(hit)
                            hit_ctx: object | None = None
                            if on_hit is not None:
                                hit_ctx = on_hit(hit)

                            proj.life_timer = 0.25
                            if apply_player_damage is not None:
                                apply_player_damage(int(hit_player_idx), 10.0)
                            else:
                                if float(player.shield_timer) <= 0.0:
                                    player.health -= 10.0

                            if on_hit_post is not None:
                                on_hit_post(hit, hit_ctx)

                            break

                        step += 3
                        continue

                    type_id = proj.type_id
                    creature = creatures[hit_idx]

                    perk_ctx = _ProjectileHitPerkCtx(
                        proj=proj,
                        creature=creature,
                        rng=rng,
                        owner_perk_active=_owner_perk_active,
                        poison_idx=poison_idx,
                    )
                    for hook in _PROJECTILE_HIT_PERK_HOOKS:
                        hook(perk_ctx)

                    if behavior.pre_hit_creature is not None:
                        behavior.pre_hit_creature(ctx, proj, int(hit_idx))

                    if runtime_state is not None:
                        owner_id = int(proj.owner_id)
                        if owner_id < 0:
                            shots_hit = runtime_state.shots_hit
                            player_index = 0 if owner_id == -100 else (-1 - owner_id)
                            if 0 <= player_index < len(shots_hit):
                                shots_hit[player_index] += 1

                    target = creature.pos
                    hit = ProjectileHit(
                        type_id=int(type_id),
                        origin=proj.origin,
                        hit=proj.pos,
                        target=target,
                    )
                    hits.append(hit)
                    hit_ctx: object | None = None
                    if on_hit is not None:
                        hit_ctx = on_hit(hit)

                    if proj.life_timer != 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        proj.life_timer = 0.25
                        jitter = rng() & 3
                        proj.pos = Vec2(
                            float(f32(float(proj.pos.x) + float(direction.x) * float(jitter))),
                            float(f32(float(proj.pos.y) + float(direction.y) * float(jitter))),
                        )

                    dist = proj.origin.distance_to(proj.pos)
                    if dist < 50.0:
                        dist = 50.0

                    if behavior.post_hit_creature is not None:
                        behavior.post_hit_creature(
                            ctx,
                            _ProjectileHitInfo(
                                proj_index=int(proj_index),
                                proj=proj,
                                hit_idx=int(hit_idx),
                                move=move,
                                target=target,
                            ),
                        )

                    damage_scale = _damage_scale(type_id)
                    damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95

                    if damage_amount > 0.0 and creature.hp > 0.0:
                        remaining = proj.damage_pool - 1.0
                        proj.damage_pool = remaining
                        # Native `projectile_update` writes both impulse components from the
                        # same cosine term (`cos(angle - pi/2) * speed_scale`).
                        impulse_axis = f32(math.cos(float(proj.angle) - NATIVE_HALF_PI) * float(proj.speed_scale))
                        impulse = Vec2(float(impulse_axis), float(impulse_axis))
                        damage_type = _damage_type_for()
                        if remaining <= 0.0:
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(damage_amount),
                                damage_type=damage_type,
                                impulse=impulse,
                                owner_id=int(proj.owner_id),
                                apply_creature_damage=apply_creature_damage,
                            )
                            if proj.life_timer != 0.25:
                                proj.life_timer = 0.25
                        else:
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(remaining),
                                damage_type=damage_type,
                                impulse=impulse,
                                owner_id=int(proj.owner_id),
                                apply_creature_damage=apply_creature_damage,
                            )
                            proj.damage_pool -= float(creature.hp)

                    # Native `projectile_update` has projectile-type specific freeze-hit
                    # handling. Non-Gauss/non-Fire-Bullets impacts emit a single shard
                    # here; Gauss/Fire-Bullets emits shards inside the six-iteration
                    # large-streak loop (presentation hook parity).
                    if (
                        runtime_state is not None
                        and float(runtime_state.bonuses.freeze) > 0.0
                        and effects is not None
                        and type_id not in (ProjectileTypeId.GAUSS_GUN, ProjectileTypeId.FIRE_BULLETS)
                    ):
                        shard_angle = float(float(proj.angle) - NATIVE_HALF_PI)
                        shard_angle += float(int(rng()) % 0x264) * 0.01
                        effects.spawn_freeze_shard(
                            pos=proj.pos,
                            angle=float(shard_angle),
                            rand=rng,
                            detail_preset=int(detail_preset),
                        )

                    if proj.damage_pool == 1.0 and proj.life_timer != 0.25:
                        proj.damage_pool = 0.0
                        proj.life_timer = 0.25

                    if proj.life_timer == 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        if on_hit_post is not None:
                            on_hit_post(hit, hit_ctx)
                        break

                    if proj.damage_pool <= 0.0:
                        if on_hit_post is not None:
                            on_hit_post(hit, hit_ctx)
                        break

                    if on_hit_post is not None:
                        on_hit_post(hit, hit_ctx)

                step += 3

        return hits

    def update_demo(
        self,
        dt: float,
        creatures: Sequence[Damageable],
        *,
        world_size: float,
        speed_by_type: dict[int, float],
        damage_by_type: dict[int, float],
    ) -> list[ProjectileHit]:
        """Update a small projectile subset for the demo view.
        """

        if dt <= 0.0:
            return []

        hits: list[ProjectileHit] = []
        margin = 64.0

        for proj in self._entries:
            if not proj.active:
                continue

            if proj.life_timer <= 0.0:
                proj.active = False
                continue

            if proj.life_timer < 0.4:
                if proj.type_id == ProjectileTypeId.ION_RIFLE:
                    damage = dt * 100.0
                    radius = 88.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                            creature.hp -= damage
                elif proj.type_id == ProjectileTypeId.ION_MINIGUN:
                    damage = dt * 40.0
                    radius = 60.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                            creature.hp -= damage
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > world_size + margin
                or proj.pos.y > world_size + margin
            ):
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            speed = speed_by_type.get(proj.type_id, 650.0) * proj.speed_scale
            direction = Vec2.from_heading(float(proj.angle))
            proj.pos = proj.pos + direction * (speed * dt)

            hit_idx = None
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = proj.hit_radius + creature_radius
                if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is None:
                continue

            creature = creatures[hit_idx]
            hits.append(
                ProjectileHit(
                    type_id=int(proj.type_id),
                    origin=proj.origin,
                    hit=proj.pos,
                    target=creature.pos,
                )
            )

            creature = creatures[hit_idx]
            creature.hp -= damage_by_type.get(proj.type_id, 10.0)

            proj.life_timer = 0.25

        return hits

