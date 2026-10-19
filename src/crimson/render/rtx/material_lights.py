"""Bounded ground illumination from visible weapon emitters; no flashlight/night ambient."""

from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ...math_parity import native_fire_muzzle_pos
from ...projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from ...weapons import WeaponId

if TYPE_CHECKING:
    from ..frame import RenderFrame

MAX_MATERIAL_LIGHTS = 16


class MaterialLight(msgspec.Struct, frozen=True):
    pos: Vec2
    radius: float
    rgb: tuple[float, float, float]
    height: float = 18.0
    direction: Vec2 = Vec2()
    length: float = 0.0


_BEAMS = {
    ProjectileTemplateId.ION_RIFLE: ((0.55, 0.82, 1.45), 195.0),
    ProjectileTemplateId.ION_MINIGUN: ((0.50, 0.78, 1.35), 160.0),
    ProjectileTemplateId.ION_CANNON: ((0.65, 0.90, 1.65), 240.0),
    ProjectileTemplateId.GAUSS_GUN: ((0.45, 0.85, 1.60), 175.0),
    ProjectileTemplateId.FIRE_BULLETS: ((1.40, 0.68, 0.20), 155.0),
}
_ORBS = {
    ProjectileTemplateId.PLASMA_CANNON: ((0.75, 1.05, 1.65), 250.0),
    ProjectileTemplateId.PLASMA_RIFLE: ((0.62, 0.92, 1.40), 175.0),
    ProjectileTemplateId.PLASMA_MINIGUN: ((0.52, 0.80, 1.20), 125.0),
    ProjectileTemplateId.SPIDER_PLASMA: ((0.35, 1.25, 0.42), 140.0),
}


def collect_material_lights(frame: RenderFrame) -> list[MaterialLight]:
    lights: list[MaterialLight] = []
    for player in frame.players:
        gain = max(0.0, min(1.0, float(player.muzzle_flash_alpha)))
        if gain <= 0.02 or player.health <= 0.0:
            continue
        rgb = (1.6, 1.0, 0.4)
        if player.weapon.weapon_id in (
            WeaponId.ION_RIFLE,
            WeaponId.ION_MINIGUN,
            WeaponId.ION_CANNON,
            WeaponId.ION_SHOTGUN,
        ):
            rgb = (0.55, 0.8, 1.45)
        elif player.weapon.weapon_id in (
            WeaponId.PLASMA_RIFLE,
            WeaponId.PLASMA_CANNON,
            WeaponId.PLASMA_MINIGUN,
            WeaponId.PLASMA_SHOTGUN,
            WeaponId.MULTI_PLASMA,
        ):
            rgb = (0.7, 0.95, 1.4)
        elif player.weapon.weapon_id in (WeaponId.GAUSS_GUN, WeaponId.GAUSS_SHOTGUN):
            rgb = (0.45, 0.85, 1.55)
        lights.append(
            MaterialLight(
                native_fire_muzzle_pos(player.pos, player.aim_heading),
                180.0,
                (rgb[0] * gain, rgb[1] * gain, rgb[2] * gain),
                height=28.0,
            ),
        )
    for proj in frame.state.projectiles.entries:
        if not proj.active:
            continue
        gain = max(0.0, min(1.0, proj.life_timer * 2.5))
        beam = _BEAMS.get(proj.type_id)
        orb = _ORBS.get(proj.type_id)
        if gain <= 0.02 or (beam is None and orb is None):
            continue
        if beam is not None:
            rgb, radius = beam
            direction, distance = (proj.pos - proj.origin).normalized_with_length()
            span = min(distance, 320.0 if proj.type_id == ProjectileTemplateId.GAUSS_GUN else 256.0)
        else:
            assert orb is not None
            rgb, radius = orb
            direction, span = Vec2(), 0.0
        lights.append(
            MaterialLight(
                proj.pos - direction * (span * 0.5),
                radius,
                (rgb[0] * gain, rgb[1] * gain, rgb[2] * gain),
                direction=direction,
                length=span,
            ),
        )
    for sec in frame.state.secondary_projectiles.entries:
        if not sec.active or sec.type_id != SecondaryProjectileTypeId.DETONATION:
            continue
        gain = max(0.0, 1.0 - sec.detonation_t) ** 1.35
        if gain > 0.02:
            lights.append(
                MaterialLight(
                    sec.pos,
                    360.0 * max(0.35, sec.detonation_scale),
                    (1.75 * gain, 1.05 * gain, 0.38 * gain),
                    height=34.0,
                ),
            )
    # Stable sort; prefer nearby energetic emitters over bright offscreen shots.
    center = frame.players[0].pos if frame.players else frame.camera * -1.0
    lights.sort(
        key=lambda light: (
            max(light.rgb) / (1.0 + (light.pos - center).length_sq() / (light.radius + light.length * 0.5) ** 2)
        ),
        reverse=True,
    )
    return lights[:MAX_MATERIAL_LIGHTS]
