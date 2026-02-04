from __future__ import annotations

import math

from ..effects import FxQueue
from ..gameplay import GameplayState, PlayerState, perk_active
from ..perks import PerkId
from ..projectiles import ProjectileTypeId
from .world_defs import ION_TYPES
from .world_state import ProjectileHit


def queue_projectile_decals(
    *,
    state: GameplayState,
    players: list[PlayerState],
    hits: list[ProjectileHit],
    fx_queue: FxQueue,
    detail_preset: int,
    fx_toggle: int,
) -> None:
    rand = state.rng.rand
    detail_preset = int(detail_preset)
    fx_toggle = int(fx_toggle)

    freeze_active = float(state.bonuses.freeze) > 0.0
    bloody = bool(players) and perk_active(players[0], PerkId.BLOODY_MESS_QUICK_LEARNER)

    for type_id, origin_x, origin_y, hit_x, hit_y, target_x, target_y in hits:
        type_id = int(type_id)

        base_angle = math.atan2(float(hit_y) - float(origin_y), float(hit_x) - float(origin_x))

        # Native: Gauss Gun + Fire Bullets spawn a distinct "streak" of large terrain decals.
        if type_id in (int(ProjectileTypeId.GAUSS_GUN), int(ProjectileTypeId.FIRE_BULLETS)):
            dir_x = math.cos(base_angle)
            dir_y = math.sin(base_angle)
            for _ in range(6):
                dist = float(int(rand()) % 100) * 0.1
                if dist > 4.0:
                    dist = float(int(rand()) % 0x5A + 10) * 0.1
                if dist > 7.0:
                    dist = float(int(rand()) % 0x50 + 0x14) * 0.1
                fx_queue.add_random(
                    pos_x=float(target_x) + dir_x * dist * 20.0,
                    pos_y=float(target_y) + dir_y * dist * 20.0,
                    rand=rand,
                )
        elif type_id in ION_TYPES:
            pass
        elif not freeze_active:
            for _ in range(3):
                spread = float(int(rand()) % 0x14 - 10) * 0.1
                angle = base_angle + spread
                dir_x = math.cos(angle) * 20.0
                dir_y = math.sin(angle) * 20.0
                fx_queue.add_random(pos_x=float(target_x), pos_y=float(target_y), rand=rand)
                fx_queue.add_random(
                    pos_x=float(target_x) + dir_x * 1.5,
                    pos_y=float(target_y) + dir_y * 1.5,
                    rand=rand,
                )
                fx_queue.add_random(
                    pos_x=float(target_x) + dir_x * 2.0,
                    pos_y=float(target_y) + dir_y * 2.0,
                    rand=rand,
                )
                fx_queue.add_random(
                    pos_x=float(target_x) + dir_x * 2.5,
                    pos_y=float(target_y) + dir_y * 2.5,
                    rand=rand,
                )

        if bloody:
            lo = -30
            hi = 30
            while lo > -60:
                span = hi - lo
                for _ in range(2):
                    dx = float(int(rand()) % span + lo)
                    dy = float(int(rand()) % span + lo)
                    fx_queue.add_random(
                        pos_x=float(target_x) + dx,
                        pos_y=float(target_y) + dy,
                        rand=rand,
                    )
                lo -= 10
                hi += 10

        # Native hit path: spawn transient blood splatter particles and only
        # bake decals into the terrain once those particles expire.
        if bloody:
            for _ in range(8):
                spread = float((int(rand()) & 0x1F) - 0x10) * 0.0625
                state.effects.spawn_blood_splatter(
                    pos_x=float(hit_x),
                    pos_y=float(hit_y),
                    angle=base_angle + spread,
                    age=0.0,
                    rand=rand,
                    detail_preset=detail_preset,
                    fx_toggle=fx_toggle,
                )
            state.effects.spawn_blood_splatter(
                pos_x=float(hit_x),
                pos_y=float(hit_y),
                angle=base_angle + math.pi,
                age=0.0,
                rand=rand,
                detail_preset=detail_preset,
                fx_toggle=fx_toggle,
            )
            continue

        if freeze_active:
            continue

        for _ in range(2):
            state.effects.spawn_blood_splatter(
                pos_x=float(hit_x),
                pos_y=float(hit_y),
                angle=base_angle,
                age=0.0,
                rand=rand,
                detail_preset=detail_preset,
                fx_toggle=fx_toggle,
            )
            if (int(rand()) & 7) == 2:
                state.effects.spawn_blood_splatter(
                    pos_x=float(hit_x),
                    pos_y=float(hit_y),
                    angle=base_angle + math.pi,
                    age=0.0,
                    rand=rand,
                    detail_preset=detail_preset,
                    fx_toggle=fx_toggle,
                )

