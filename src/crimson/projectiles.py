from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import math
from typing import Callable, Protocol

from .perks import PerkId


class Damageable(Protocol):
    x: float
    y: float
    hp: float


class PlayerDamageable(Protocol):
    pos_x: float
    pos_y: float
    health: float
    size: float


MAIN_PROJECTILE_POOL_SIZE = 0x60
SECONDARY_PROJECTILE_POOL_SIZE = 0x40


class ProjectileTypeId(IntEnum):
    PISTOL = 0x00
    ASSAULT_RIFLE = 0x01
    SHOTGUN = 0x02
    SAWED_OFF_SHOTGUN = 0x03
    SUBMACHINE_GUN = 0x04
    GAUSS_GUN = 0x05
    MEAN_MINIGUN = 0x06
    FLAMETHROWER = 0x07
    PLASMA_RIFLE = 0x09
    ROCKET_LAUNCHER = 0x0B
    PULSE_GUN = 0x12
    JACKHAMMER = 0x13
    ION_RIFLE = 0x14
    ION_MINIGUN = 0x15
    ION_CANNON = 0x16
    SHRINKIFIER = 0x17
    BLADE_GUN = 0x18
    SPIDER_PLASMA = 0x19
    PLASMA_CANNON = 0x1B
    SPLITTER_GUN = 0x1C
    GAUSS_SHOTGUN = 0x1D
    PLAGUE_SPREADER = 0x28
    FIRE_BULLETS = 0x2C


ROCKET_SPLASH_RADIUS = 90.0


def _rng_zero() -> int:
    return 0


CreatureDamageApplier = Callable[[int, float, int, float, float, int], None]


@dataclass(slots=True)
class Projectile:
    active: bool = False
    angle: float = 0.0
    pos_x: float = 0.0
    pos_y: float = 0.0
    origin_x: float = 0.0
    origin_y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    type_id: int = 0
    life_timer: float = 0.0
    reserved: float = 0.0
    speed_scale: float = 1.0
    damage_pool: float = 1.0
    hit_radius: float = 1.0
    base_damage: float = 0.0
    owner_id: int = 0
    hits_players: bool = False


@dataclass(slots=True)
class SecondaryProjectile:
    active: bool = False
    angle: float = 0.0
    speed: float = 0.0
    pos_x: float = 0.0
    pos_y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    type_id: int = 0
    owner_id: int = -100
    lifetime: float = 0.0
    target_id: int = -1


def _distance_sq(x0: float, y0: float, x1: float, y1: float) -> float:
    dx = x1 - x0
    dy = y1 - y0
    return dx * dx + dy * dy


def _hit_radius_for(creature: Damageable) -> float:
    """Approximate `creature_find_in_radius`/`creatures_apply_radius_damage` sizing.

    The native code compares `distance - radius < creature.size * 0.14285715 + 3.0`.
    """

    raw = getattr(creature, "size", None)
    if raw is None:
        size = 50.0
    else:
        size = float(raw)
    return max(0.0, size * 0.14285715 + 3.0)


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
        pos_x: float,
        pos_y: float,
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
        entry.pos_x = pos_x
        entry.pos_y = pos_y
        entry.origin_x = pos_x
        entry.origin_y = pos_y
        entry.vel_x = math.cos(angle) * 1.5
        entry.vel_y = math.sin(angle) * 1.5
        entry.type_id = int(type_id)
        entry.life_timer = 0.4
        entry.reserved = 0.0
        entry.speed_scale = 1.0
        entry.base_damage = float(base_damage)
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
        creatures: list[Damageable],
        *,
        world_size: float,
        damage_scale_by_type: dict[int, float] | None = None,
        damage_scale_default: float = 1.0,
        ion_aoe_scale: float = 1.0,
        rng: Callable[[], int] | None = None,
        runtime_state: object | None = None,
        players: list[PlayerDamageable] | None = None,
        apply_player_damage: Callable[[int, float], None] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
    ) -> list[tuple[int, float, float, float, float, float, float]]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.

        Returns a list of hit tuples: (type_id, origin_x, origin_y, hit_x, hit_y, target_x, target_y).
        """

        if dt <= 0.0:
            return []

        barrel_greaser_active = False
        if players is not None:
            perk_idx = int(PerkId.BARREL_GREASER)
            for player in players:
                perk_counts = getattr(player, "perk_counts", None)
                if (
                    isinstance(perk_counts, list)
                    and 0 <= perk_idx < len(perk_counts)
                    and int(perk_counts[perk_idx]) > 0
                ):
                    barrel_greaser_active = True
                    break

        if damage_scale_by_type is None:
            damage_scale_by_type = {}

        if rng is None:
            rng = _rng_zero

        hits: list[tuple[int, float, float, float, float, float, float]] = []
        margin = 64.0

        def _damage_scale(type_id: int) -> float:
            value = damage_scale_by_type.get(type_id)
            if value is None:
                return float(damage_scale_default)
            return float(value)

        def _damage_type_for(type_id: int, *, radius: bool = False) -> int:
            if radius:
                return 3
            if type_id in (ProjectileTypeId.ION_RIFLE, ProjectileTypeId.ION_MINIGUN, ProjectileTypeId.ION_CANNON):
                return 7
            if type_id in (ProjectileTypeId.FLAMETHROWER, ProjectileTypeId.FIRE_BULLETS):
                return 4
            return 1

        def _apply_damage_to_creature(
            creature_index: int,
            damage: float,
            *,
            damage_type: int,
            impulse_x: float,
            impulse_y: float,
            owner_id: int,
        ) -> None:
            if damage <= 0.0:
                return
            idx = int(creature_index)
            if not (0 <= idx < len(creatures)):
                return
            if apply_creature_damage is not None:
                apply_creature_damage(
                    idx,
                    float(damage),
                    int(damage_type),
                    float(impulse_x),
                    float(impulse_y),
                    int(owner_id),
                )
            else:
                creatures[idx].hp -= float(damage)

        def _apply_rocket_splash(x: float, y: float, owner_id: int, damage_scale: float) -> None:
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                if idx == owner_id:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = ROCKET_SPLASH_RADIUS + creature_radius
                if _distance_sq(x, y, creature.x, creature.y) > hit_r * hit_r:
                    continue
                dist = math.hypot(creature.x - x, creature.y - y)
                if dist < 50.0:
                    dist = 50.0
                damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95
                _apply_damage_to_creature(
                    idx,
                    damage_amount,
                    damage_type=_damage_type_for(int(ProjectileTypeId.ROCKET_LAUNCHER), radius=True),
                    impulse_x=0.0,
                    impulse_y=0.0,
                    owner_id=owner_id,
                )

        def _reset_shock_chain_if_owner(index: int) -> None:
            if runtime_state is None:
                return
            if getattr(runtime_state, "shock_chain_projectile_id", -1) != index:
                return
            setattr(runtime_state, "shock_chain_projectile_id", -1)
            setattr(runtime_state, "shock_chain_links_left", 0)

        def _try_spawn_shock_chain_link(index: int, hit_creature: int) -> None:
            if runtime_state is None:
                return
            if getattr(runtime_state, "shock_chain_projectile_id", -1) != index:
                return
            links_left = int(getattr(runtime_state, "shock_chain_links_left", 0) or 0)
            if links_left <= 0:
                return
            if not (0 <= hit_creature < len(creatures)):
                return

            origin = creatures[hit_creature]
            best_idx = -1
            best_dist = 0.0
            max_dist = 100.0
            for creature_id, creature in enumerate(creatures):
                if creature_id == hit_creature:
                    continue
                if creature.hp <= 0.0:
                    continue
                d = _distance_sq(origin.x, origin.y, creature.x, creature.y)
                if d > max_dist * max_dist:
                    continue
                if best_idx == -1 or d < best_dist:
                    best_idx = creature_id
                    best_dist = d

            setattr(runtime_state, "shock_chain_links_left", links_left - 1)
            if best_idx == -1:
                return

            target = creatures[best_idx]
            angle = math.atan2(target.y - origin.y, target.x - origin.x) + math.pi / 2.0

            set_guard = hasattr(runtime_state, "bonus_spawn_guard")
            if set_guard:
                setattr(runtime_state, "bonus_spawn_guard", True)
            proj_id = self.spawn(
                pos_x=proj.pos_x,
                pos_y=proj.pos_y,
                angle=angle,
                type_id=int(proj.type_id),
                owner_id=hit_creature,
                base_damage=proj.base_damage,
            )
            if set_guard:
                setattr(runtime_state, "bonus_spawn_guard", False)
            setattr(runtime_state, "shock_chain_projectile_id", proj_id)

        for proj_index, proj in enumerate(self._entries):
            if not proj.active:
                continue

            if proj.life_timer <= 0.0:
                _reset_shock_chain_if_owner(proj_index)
                proj.active = False
                continue

            if runtime_state is not None and getattr(runtime_state, "shock_chain_projectile_id", -1) == proj_index:
                pending_hit = int(getattr(proj, "reserved", 0.0) or 0.0)
                if pending_hit > 0:
                    proj.reserved = 0.0
                    _try_spawn_shock_chain_link(proj_index, pending_hit - 1)

            if proj.life_timer < 0.4:
                type_id = proj.type_id
                if type_id in (ProjectileTypeId.ION_RIFLE, ProjectileTypeId.ION_MINIGUN):
                    proj.life_timer -= dt
                    if type_id == ProjectileTypeId.ION_RIFLE:
                        damage = dt * 100.0
                        radius = ion_aoe_scale * 88.0
                    else:
                        damage = dt * 40.0
                        radius = ion_aoe_scale * 60.0
                    for creature_idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            _apply_damage_to_creature(
                                creature_idx,
                                damage,
                                damage_type=_damage_type_for(int(type_id)),
                                impulse_x=0.0,
                                impulse_y=0.0,
                                owner_id=int(proj.owner_id),
                            )
                elif type_id == ProjectileTypeId.ION_CANNON:
                    proj.life_timer -= dt * 0.7
                    damage = dt * 300.0
                    radius = ion_aoe_scale * 128.0
                    for creature_idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            _apply_damage_to_creature(
                                creature_idx,
                                damage,
                                damage_type=_damage_type_for(int(type_id)),
                                impulse_x=0.0,
                                impulse_y=0.0,
                                owner_id=int(proj.owner_id),
                            )
                elif type_id == ProjectileTypeId.GAUSS_GUN:
                    proj.life_timer -= dt * 0.1
                else:
                    proj.life_timer -= dt

                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            if (
                proj.pos_x < -margin
                or proj.pos_y < -margin
                or proj.pos_x > world_size + margin
                or proj.pos_y > world_size + margin
            ):
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            steps = int(proj.base_damage)
            if steps <= 0:
                steps = 1
            if barrel_greaser_active and int(proj.owner_id) < 0:
                steps *= 2

            dir_x = math.cos(proj.angle - math.pi / 2.0)
            dir_y = math.sin(proj.angle - math.pi / 2.0)

            acc_x = 0.0
            acc_y = 0.0
            step = 0
            while step < steps:
                acc_x += dir_x * dt * 20.0 * proj.speed_scale * 3.0
                acc_y += dir_y * dt * 20.0 * proj.speed_scale * 3.0

                if math.hypot(acc_x, acc_y) >= 4.0 or steps <= step + 3:
                    move_dx = acc_x
                    move_dy = acc_y
                    proj.pos_x += move_dx
                    proj.pos_y += move_dy
                    acc_x = 0.0
                    acc_y = 0.0

                    if proj.hits_players:
                        hit_player_idx = None
                        if players is not None:
                            for idx, player in enumerate(players):
                                if float(player.health) <= 0.0:
                                    continue
                                player_radius = _hit_radius_for(player)
                                hit_r = proj.hit_radius + player_radius
                                if _distance_sq(proj.pos_x, proj.pos_y, player.pos_x, player.pos_y) <= hit_r * hit_r:
                                    hit_player_idx = idx
                                    break

                        if hit_player_idx is None:
                            step += 3
                            continue

                        type_id = proj.type_id
                        hit_x = float(proj.pos_x)
                        hit_y = float(proj.pos_y)
                        player = players[int(hit_player_idx)] if players is not None else None
                        target_x = float(getattr(player, "pos_x", hit_x) if player is not None else hit_x)
                        target_y = float(getattr(player, "pos_y", hit_y) if player is not None else hit_y)
                        hits.append((type_id, proj.origin_x, proj.origin_y, hit_x, hit_y, target_x, target_y))

                        if proj.life_timer != 0.25 and type_id not in (
                            ProjectileTypeId.FIRE_BULLETS,
                            ProjectileTypeId.GAUSS_GUN,
                            ProjectileTypeId.BLADE_GUN,
                        ):
                            proj.life_timer = 0.25
                            jitter = rng() & 3
                            proj.pos_x += dir_x * float(jitter)
                            proj.pos_y += dir_y * float(jitter)

                        dist = math.hypot(proj.origin_x - proj.pos_x, proj.origin_y - proj.pos_y)
                        if dist < 50.0:
                            dist = 50.0

                        damage_scale = _damage_scale(type_id)
                        damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95
                        if damage_amount > 0.0:
                            if apply_player_damage is not None:
                                apply_player_damage(int(hit_player_idx), float(damage_amount))
                            elif players is not None:
                                players[int(hit_player_idx)].health -= float(damage_amount)

                        break

                    hit_idx = None
                    for idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        if idx == proj.owner_id:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = proj.hit_radius + creature_radius
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            hit_idx = idx
                            break

                    if hit_idx is None:
                        step += 3
                        continue

                    type_id = proj.type_id
                    creature = creatures[hit_idx]

                    if type_id == ProjectileTypeId.SPLITTER_GUN:
                        self.spawn(
                            pos_x=proj.pos_x,
                            pos_y=proj.pos_y,
                            angle=proj.angle - 1.0471976,
                            type_id=ProjectileTypeId.SPLITTER_GUN,
                            owner_id=hit_idx,
                            base_damage=proj.base_damage,
                            hits_players=proj.hits_players,
                        )
                        self.spawn(
                            pos_x=proj.pos_x,
                            pos_y=proj.pos_y,
                            angle=proj.angle + 1.0471976,
                            type_id=ProjectileTypeId.SPLITTER_GUN,
                            owner_id=hit_idx,
                            base_damage=proj.base_damage,
                            hits_players=proj.hits_players,
                        )

                    shots_hit = getattr(runtime_state, "shots_hit", None) if runtime_state is not None else None
                    if isinstance(shots_hit, list):
                        owner_id = int(proj.owner_id)
                        if owner_id < 0 and owner_id != -100:
                            player_index = -1 - owner_id
                            if 0 <= player_index < len(shots_hit):
                                shots_hit[player_index] += 1

                    hit_x = float(proj.pos_x)
                    hit_y = float(proj.pos_y)
                    target_x = float(creature.x)
                    target_y = float(creature.y)
                    hits.append((type_id, proj.origin_x, proj.origin_y, hit_x, hit_y, target_x, target_y))

                    if proj.life_timer != 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        proj.life_timer = 0.25
                        jitter = rng() & 3
                        proj.pos_x += dir_x * float(jitter)
                        proj.pos_y += dir_y * float(jitter)

                    dist = math.hypot(proj.origin_x - proj.pos_x, proj.origin_y - proj.pos_y)
                    if dist < 50.0:
                        dist = 50.0

                    if type_id in (ProjectileTypeId.ION_RIFLE, ProjectileTypeId.ION_MINIGUN):
                        if runtime_state is not None and getattr(runtime_state, "shock_chain_projectile_id", -1) == proj_index:
                            proj.reserved = float(int(hit_idx) + 1)
                    elif type_id == ProjectileTypeId.PLASMA_CANNON:
                        size = float(getattr(creature, "size", 50.0) or 50.0)
                        ring_radius = size * 0.5 + 1.0
                        for ring_idx in range(12):
                            ring_angle = float(ring_idx) * (math.pi / 6.0)
                            self.spawn(
                                pos_x=proj.pos_x + math.cos(ring_angle) * ring_radius,
                                pos_y=proj.pos_y + math.sin(ring_angle) * ring_radius,
                                angle=ring_angle,
                                type_id=8,
                                owner_id=-100,
                                base_damage=45.0,
                            )
                    elif type_id == ProjectileTypeId.SHRINKIFIER:
                        if hasattr(creature, "size"):
                            new_size = float(getattr(creature, "size", 50.0) or 50.0) * 0.65
                            setattr(creature, "size", new_size)
                            if new_size < 16.0:
                                _apply_damage_to_creature(
                                    hit_idx,
                                    float(creature.hp) + 1.0,
                                    damage_type=_damage_type_for(int(type_id)),
                                    impulse_x=0.0,
                                    impulse_y=0.0,
                                    owner_id=int(proj.owner_id),
                                )
                        proj.life_timer = 0.25
                    elif type_id == ProjectileTypeId.PULSE_GUN:
                        creature.x += move_dx * 3.0
                        creature.y += move_dy * 3.0
                    elif type_id == ProjectileTypeId.PLAGUE_SPREADER and hasattr(creature, "collision_flag"):
                        setattr(creature, "collision_flag", 1)
                    elif type_id == ProjectileTypeId.ROCKET_LAUNCHER:
                        damage_scale = _damage_scale(type_id)
                        _apply_rocket_splash(proj.pos_x, proj.pos_y, proj.owner_id, damage_scale)
                        proj.life_timer = 0.25
                        break

                    damage_scale = _damage_scale(type_id)
                    damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95

                    if damage_amount > 0.0 and creature.hp > 0.0:
                        remaining = proj.damage_pool - 1.0
                        proj.damage_pool = remaining
                        impulse_x = dir_x * float(proj.speed_scale)
                        impulse_y = dir_y * float(proj.speed_scale)
                        damage_type = _damage_type_for(int(type_id))
                        if remaining <= 0.0:
                            _apply_damage_to_creature(
                                hit_idx,
                                damage_amount,
                                damage_type=damage_type,
                                impulse_x=impulse_x,
                                impulse_y=impulse_y,
                                owner_id=int(proj.owner_id),
                            )
                            if proj.life_timer != 0.25:
                                proj.life_timer = 0.25
                        else:
                            hp_before = float(creature.hp)
                            _apply_damage_to_creature(
                                hit_idx,
                                remaining,
                                damage_type=damage_type,
                                impulse_x=impulse_x,
                                impulse_y=impulse_y,
                                owner_id=int(proj.owner_id),
                            )
                            proj.damage_pool -= hp_before

                    if proj.damage_pool == 1.0 and proj.life_timer != 0.25:
                        proj.damage_pool = 0.0
                        proj.life_timer = 0.25

                    if proj.life_timer == 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        break

                    if proj.damage_pool <= 0.0:
                        break

                step += 3

        return hits

    def update_demo(
        self,
        dt: float,
        creatures: list[Damageable],
        *,
        world_size: float,
        speed_by_type: dict[int, float],
        damage_by_type: dict[int, float],
        rocket_splash_radius: float = 90.0,
    ) -> list[tuple[int, float, float, float, float, float, float]]:
        """Update a small projectile subset for the demo view.

        Returns a list of hit tuples: (type_id, origin_x, origin_y, hit_x, hit_y, target_x, target_y).
        """

        if dt <= 0.0:
            return []

        hits: list[tuple[int, float, float, float, float, float, float]] = []
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
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            creature.hp -= damage
                elif proj.type_id == ProjectileTypeId.ION_MINIGUN:
                    damage = dt * 40.0
                    radius = 60.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            creature.hp -= damage
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            if (
                proj.pos_x < -margin
                or proj.pos_y < -margin
                or proj.pos_x > world_size + margin
                or proj.pos_y > world_size + margin
            ):
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            speed = speed_by_type.get(proj.type_id, 650.0) * proj.speed_scale
            direction_x = math.cos(proj.angle - math.pi / 2.0)
            direction_y = math.sin(proj.angle - math.pi / 2.0)
            proj.pos_x += direction_x * speed * dt
            proj.pos_y += direction_y * speed * dt

            hit_idx = None
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = proj.hit_radius + creature_radius
                if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is None:
                continue

            hit_x = float(proj.pos_x)
            hit_y = float(proj.pos_y)
            creature = creatures[hit_idx]
            hits.append((proj.type_id, proj.origin_x, proj.origin_y, hit_x, hit_y, float(creature.x), float(creature.y)))

            if proj.type_id == 0x0B:
                dmg = damage_by_type.get(proj.type_id, 32.0)
                for creature in creatures:
                    if creature.hp <= 0.0:
                        continue
                    creature_radius = _hit_radius_for(creature)
                    hit_r = rocket_splash_radius + creature_radius
                    if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                        creature.hp -= dmg
                proj.life_timer = 0.25
                continue

            creature = creatures[hit_idx]
            creature.hp -= damage_by_type.get(proj.type_id, 10.0)

            proj.life_timer = 0.25

        return hits


class SecondaryProjectilePool:
    def __init__(self, *, size: int = SECONDARY_PROJECTILE_POOL_SIZE) -> None:
        self._entries = [SecondaryProjectile() for _ in range(size)]

    @property
    def entries(self) -> list[SecondaryProjectile]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def spawn(
        self,
        *,
        pos_x: float,
        pos_y: float,
        angle: float,
        type_id: int,
        owner_id: int = -100,
        time_to_live: float = 2.0,
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
        entry.angle = float(angle)
        entry.type_id = int(type_id)
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.owner_id = int(owner_id)
        entry.target_id = -1

        if entry.type_id == 3:
            entry.vel_x = 0.0
            entry.vel_y = 0.0
            entry.speed = float(time_to_live)
            entry.lifetime = 0.0
            return index

        # Effects.md: vel = cos/sin(angle - PI/2) * 90 (190 for type 2).
        base_speed = 90.0
        if entry.type_id == 2:
            base_speed = 190.0
        vx = math.cos(angle - math.pi / 2.0) * base_speed
        vy = math.sin(angle - math.pi / 2.0) * base_speed
        entry.vel_x = vx
        entry.vel_y = vy
        entry.speed = float(time_to_live)
        entry.lifetime = 0.0
        return index

    def iter_active(self) -> list[SecondaryProjectile]:
        return [entry for entry in self._entries if entry.active]

    def update_pulse_gun(
        self,
        dt: float,
        creatures: list[Damageable],
        *,
        apply_creature_damage: CreatureDamageApplier | None = None,
    ) -> None:
        """Update the secondary projectile pool subset (types 1/2/4 + detonation type 3)."""

        if dt <= 0.0:
            return

        def _apply_damage_to_creature(creature_index: int, damage: float, *, owner_id: int) -> None:
            if damage <= 0.0:
                return
            idx = int(creature_index)
            if not (0 <= idx < len(creatures)):
                return
            if apply_creature_damage is not None:
                apply_creature_damage(idx, float(damage), 3, 0.0, 0.0, int(owner_id))
            else:
                creatures[idx].hp -= float(damage)

        for entry in self._entries:
            if not entry.active:
                continue

            if entry.type_id == 3:
                entry.lifetime += dt * 3.0
                t = entry.lifetime
                if t > 1.0:
                    entry.active = False

                scale = entry.speed
                radius = scale * t * 80.0
                damage = dt * scale * 700.0
                for creature_idx, creature in enumerate(creatures):
                    if creature.hp <= 0.0:
                        continue
                    creature_radius = _hit_radius_for(creature)
                    hit_r = radius + creature_radius
                    if _distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                        _apply_damage_to_creature(creature_idx, damage, owner_id=int(entry.owner_id))
                continue

            if entry.type_id not in (1, 2, 4):
                continue

            # Move.
            entry.pos_x += entry.vel_x * dt
            entry.pos_y += entry.vel_y * dt

            # Update velocity + countdown.
            speed_mag = math.hypot(entry.vel_x, entry.vel_y)
            if entry.type_id == 1:
                if speed_mag < 500.0:
                    factor = 1.0 + dt * 3.0
                    entry.vel_x *= factor
                    entry.vel_y *= factor
                entry.speed -= dt
            elif entry.type_id == 4:
                if speed_mag < 600.0:
                    factor = 1.0 + dt * 4.0
                    entry.vel_x *= factor
                    entry.vel_y *= factor
                entry.speed -= dt
            else:
                # Type 2: homing projectile.
                target_id = entry.target_id
                if not (0 <= target_id < len(creatures)) or creatures[target_id].hp <= 0.0:
                    best_idx = -1
                    best_dist = 0.0
                    for idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        d = _distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y)
                        if best_idx == -1 or d < best_dist:
                            best_idx = idx
                            best_dist = d
                    entry.target_id = best_idx
                    target_id = best_idx

                if 0 <= target_id < len(creatures):
                    target = creatures[target_id]
                    dx = target.x - entry.pos_x
                    dy = target.y - entry.pos_y
                    dist = math.hypot(dx, dy)
                    if dist > 1e-6:
                        angle = math.atan2(dy, dx) + math.pi / 2.0
                        entry.angle = angle
                        dir_x = math.cos(angle - math.pi / 2.0)
                        dir_y = math.sin(angle - math.pi / 2.0)
                        entry.vel_x += dir_x * dt * 800.0
                        entry.vel_y += dir_y * dt * 800.0
                        if 350.0 < math.hypot(entry.vel_x, entry.vel_y):
                            entry.vel_x -= dir_x * dt * 800.0
                            entry.vel_y -= dir_y * dt * 800.0

                entry.speed -= dt * 0.5

            # projectile_update uses creature_find_in_radius(..., 8.0, ...)
            hit_idx: int | None = None
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = 8.0 + creature_radius
                if _distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is not None:
                damage = 150.0
                if entry.type_id == 1:
                    damage = entry.speed * 50.0 + 500.0
                elif entry.type_id == 2:
                    damage = entry.speed * 20.0 + 80.0
                elif entry.type_id == 4:
                    damage = entry.speed * 20.0 + 40.0
                _apply_damage_to_creature(hit_idx, damage, owner_id=int(entry.owner_id))

                det_scale = 0.5
                if entry.type_id == 1:
                    det_scale = 1.0
                elif entry.type_id == 2:
                    det_scale = 0.35
                elif entry.type_id == 4:
                    det_scale = 0.25

                entry.type_id = 3
                entry.vel_x = 0.0
                entry.vel_y = 0.0
                entry.speed = det_scale
                entry.lifetime = 0.0
                continue

            if entry.speed <= 0.0:
                entry.type_id = 3
                entry.vel_x = 0.0
                entry.vel_y = 0.0
                entry.speed = 0.5
                entry.lifetime = 0.0
