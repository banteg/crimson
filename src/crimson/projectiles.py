from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable, Protocol


class Damageable(Protocol):
    x: float
    y: float
    hp: float


MAIN_PROJECTILE_POOL_SIZE = 0x60
SECONDARY_PROJECTILE_POOL_SIZE = 0x40


def _rng_zero() -> int:
    return 0


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

        if type_id == 0x16:
            entry.hit_radius = 3.0
            entry.damage_pool = 1.0
            return index
        if type_id == 0x15:
            entry.hit_radius = 5.0
            entry.damage_pool = 1.0
            return index
        if type_id in (0x17, 0x1C):
            entry.hit_radius = 10.0
        else:
            entry.hit_radius = 1.0
            if type_id == 6:
                entry.damage_pool = 300.0
                return index
            if type_id == 0x2D:
                entry.damage_pool = 240.0
                return index
            if type_id == 0x19:
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
    ) -> list[tuple[int, float, float, float, float]]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.

        Returns a list of hit tuples: (type_id, origin_x, origin_y, hit_x, hit_y).
        """

        if dt <= 0.0:
            return []

        if damage_scale_by_type is None:
            damage_scale_by_type = {}

        if rng is None:
            rng = _rng_zero

        hits: list[tuple[int, float, float, float, float]] = []
        margin = 64.0

        def _damage_scale(type_id: int) -> float:
            value = damage_scale_by_type.get(type_id)
            if value is None:
                return float(damage_scale_default)
            return float(value)

        for proj in self._entries:
            if not proj.active:
                continue

            if proj.life_timer <= 0.0:
                proj.active = False
                continue

            if proj.life_timer < 0.4:
                type_id = proj.type_id
                if type_id in (0x15, 0x16):
                    proj.life_timer -= dt
                    if type_id == 0x15:
                        damage = dt * 100.0
                        radius = ion_aoe_scale * 88.0
                    else:
                        damage = dt * 40.0
                        radius = ion_aoe_scale * 60.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            creature.hp -= damage
                elif type_id == 0x17:
                    proj.life_timer -= dt * 0.7
                    damage = dt * 300.0
                    radius = ion_aoe_scale * 128.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if _distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            creature.hp -= damage
                elif type_id == 6:
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

            dir_x = math.cos(proj.angle - math.pi / 2.0)
            dir_y = math.sin(proj.angle - math.pi / 2.0)

            acc_x = 0.0
            acc_y = 0.0
            step = 0
            while step < steps:
                acc_x += dir_x * dt * 20.0 * proj.speed_scale * 3.0
                acc_y += dir_y * dt * 20.0 * proj.speed_scale * 3.0

                if math.hypot(acc_x, acc_y) >= 4.0 or steps <= step + 3:
                    proj.pos_x += acc_x
                    proj.pos_y += acc_y
                    acc_x = 0.0
                    acc_y = 0.0

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
                        step += 3
                        continue

                    hits.append((proj.type_id, proj.origin_x, proj.origin_y, proj.pos_x, proj.pos_y))

                    dist = math.hypot(proj.origin_x - proj.pos_x, proj.origin_y - proj.pos_y)
                    if dist < 50.0:
                        dist = 50.0

                    damage_amount = ((100.0 / dist) * _damage_scale(proj.type_id) * 30.0 + 10.0) * 0.95
                    if damage_amount > 0.0:
                        creature = creatures[hit_idx]
                        if creature.hp > 0.0:
                            proj.damage_pool -= 1.0
                            if proj.damage_pool <= 0.0:
                                creature.hp -= damage_amount
                                if proj.life_timer != 0.25:
                                    proj.life_timer = 0.25
                            else:
                                # Pierce budget behavior is complex; keep it conservative.
                                creature.hp -= proj.damage_pool
                                proj.damage_pool -= max(0.0, creature.hp)

                    if proj.life_timer != 0.25 and proj.type_id not in (0x2D, 6, 0x19):
                        proj.life_timer = 0.25
                        jitter = rng() & 3
                        proj.pos_x += dir_x * float(jitter)
                        proj.pos_y += dir_y * float(jitter)

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
    ) -> list[tuple[int, float, float, float, float]]:
        """Update a small projectile subset for the demo view.

        Returns a list of hit tuples: (type_id, origin_x, origin_y, hit_x, hit_y).
        """

        if dt <= 0.0:
            return []

        hits: list[tuple[int, float, float, float, float]] = []
        margin = 64.0

        for proj in self._entries:
            if not proj.active:
                continue

            if proj.life_timer <= 0.0:
                proj.active = False
                continue

            if proj.life_timer < 0.4:
                if proj.type_id == 0x15:
                    damage = dt * 100.0
                    radius = 88.0
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

            hits.append((proj.type_id, proj.origin_x, proj.origin_y, proj.pos_x, proj.pos_y))

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

    def update_pulse_gun(self, dt: float, creatures: list[Damageable]) -> None:
        """Update the secondary projectile pool subset (types 1/2/4 + detonation type 3)."""

        if dt <= 0.0:
            return

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
                for creature in creatures:
                    if creature.hp <= 0.0:
                        continue
                    creature_radius = _hit_radius_for(creature)
                    hit_r = radius + creature_radius
                    if _distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                        creature.hp -= damage
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
            hit = False
            hit_creature: Damageable | None = None
            for creature in creatures:
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = 8.0 + creature_radius
                if _distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                    hit = True
                    hit_creature = creature
                    break
            if hit:
                damage = 150.0
                if entry.type_id == 1:
                    damage = entry.speed * 50.0 + 500.0
                elif entry.type_id == 2:
                    damage = entry.speed * 20.0 + 80.0
                elif entry.type_id == 4:
                    damage = entry.speed * 20.0 + 40.0
                if hit_creature is not None:
                    hit_creature.hp -= damage

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
