"""Shared finite weapon sources, with independent illumination and reflection budgets."""

from __future__ import annotations

import math
from heapq import nsmallest
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ...effects import Particle, ParticleStyleId
from ...math_parity import native_fire_muzzle_pos
from ...perks import PerkId
from ...projectiles.types import Projectile
from ...projectiles.types import ProjectileTemplateId as PT
from ...projectiles.types import SecondaryProjectileTypeId as ST
from ...weapons import WEAPON_BY_ID, WeaponId
from ..beam_profiles import STREAK_SCALES
from ..ion_arcs import ion_arc_targets
from ..laser_sight import laser_sight_geometry

if TYPE_CHECKING:
    from ..frame import RenderFrame

from .explosion_shell import explosion_shell

MAX_ILLUMINATION_SOURCES = 16
MAX_REFLECTION_SOURCES = 16
# The independently selected sets share one upload; overlapping sources occur only once.
MAX_MATERIAL_LIGHTS = MAX_ILLUMINATION_SOURCES + MAX_REFLECTION_SOURCES


class MaterialLight(msgspec.Struct, frozen=True):
    """A luminous disc, tapered segment, or annulus, not necessarily a lamp.

    RGB is linear source radiance. Radius bounds illumination, source_width is
    the reflection footprint in world units, and gains control the two responses.
    Unless specified, reflections use the same finite support as illumination.
    """

    pos: Vec2
    radius: float
    rgb: tuple[float, float, float]
    height: float = 18.0
    direction: Vec2 = Vec2()
    length: float = 0.0
    source_width: float = 3.0
    illumination_gain: float = 1.0
    reflection_gain: float = 1.0
    reflection_radius: float | None = None
    broad_illumination: bool = False
    # Positive radius selects an annulus; its width remains source_width.
    ring_radius: float = 0.0
    reflection_tail: float = 0.18
    beam_profile: tuple[float, float, float] | None = None
    beam_ion: bool = False
    # Artistic scattering response, independent of ground/creature illumination.
    smoke_gain: float = 1.0

    @property
    def reflection_reach(self) -> float:
        return self.radius if self.reflection_radius is None else self.reflection_radius

    @property
    def response(self) -> tuple[float, float, float, float]:
        """Common shader packing: diffuse gain, specular gain, support, source width."""
        return (self.illumination_gain, self.reflection_gain, self.reflection_reach, self.source_width)


class ProjectileEmission(msgspec.Struct, frozen=True):
    rgb: tuple[float, float, float]
    radius: float
    width: float
    height: float = 18.0
    illumination: float = 1.0
    reflection: float = 1.0
    reach: float = 180.0
    tail: float = 0.0
    fade_power: float = 1.0
    broad_illumination: bool = False


_TRACER = ProjectileEmission(
    (0.22, 0.21, 0.18), 60.0, 0.65, height=28.0, illumination=0.0, reach=100.0, tail=math.inf, fade_power=2.2,
)
# Art-directed radiance, not calibrated watts. The visible source remains native.
PROJECTILE_EMISSIONS: dict[PT, ProjectileEmission] = {
    PT.PISTOL: _TRACER,
    PT.ASSAULT_RIFLE: _TRACER,
    PT.SHOTGUN: _TRACER,
    PT.SUBMACHINE_GUN: _TRACER,
    PT.SPLITTER_GUN: _TRACER,
    PT.GAUSS_GUN: ProjectileEmission(
        (0.054, 0.102, 0.192), 75.0, 1.0, height=40.0, illumination=0.15, reach=150.0, tail=math.inf, fade_power=2.2,
    ),
    PT.ION_RIFLE: ProjectileEmission((0.55, 0.82, 1.45), 195.0, 3.0, height=24.0, illumination=6.0, reach=195.0, tail=256.0, broad_illumination=True),
    PT.ION_MINIGUN: ProjectileEmission((0.50, 0.78, 1.35), 160.0, 2.0, height=24.0, illumination=4.0, reach=160.0, tail=256.0, broad_illumination=True),
    PT.ION_CANNON: ProjectileEmission((0.65, 0.90, 1.65), 240.0, 5.0, height=24.0, illumination=8.0, reach=240.0, tail=256.0, broad_illumination=True),
    PT.FIRE_BULLETS: ProjectileEmission((1.40, 0.68, 0.20), 155.0, 3.0, height=24.0, illumination=4.0, reach=155.0, tail=256.0, broad_illumination=True),
    PT.PLASMA_MINIGUN: ProjectileEmission((0.72, 0.37, 0.08), 100.0, 2.0, illumination=2.4, reach=125.0, tail=4.2, broad_illumination=True),
    PT.PLASMA_RIFLE: ProjectileEmission((1.1, 0.57, 0.12), 140.0, 5.0, illumination=3.2, reach=175.0, tail=17.5, broad_illumination=True),
    PT.PLASMA_CANNON: ProjectileEmission((1.5, 0.76, 0.16), 190.0, 9.0, illumination=4.0, reach=250.0, tail=44.2, broad_illumination=True),
    PT.SPIDER_PLASMA: ProjectileEmission((0.08, 0.65, 0.025), 100.0, 2.0, illumination=0.5, reach=140.0, tail=4.2),
    PT.SHRINKIFIER: ProjectileEmission((0.06, 0.03, 0.18), 65.0, 2.0, illumination=0.15, reach=120.0, tail=4.2),
    PT.PULSE_GUN: ProjectileEmission((0.025, 0.24, 0.04), 75.0, 5.0, illumination=0.15, reach=130.0),
}
_PLASMA = {PT.PLASMA_MINIGUN, PT.PLASMA_RIFLE, PT.PLASMA_CANNON, PT.SPIDER_PLASMA, PT.SHRINKIFIER}


def projectile_source(proj: Projectile) -> MaterialLight | None:
    profile = PROJECTILE_EMISSIONS.get(proj.type_id)
    if not proj.active or profile is None or proj.life_timer <= 0.0:
        return None
    gain = min(1.0, proj.life_timer * 2.5) ** profile.fade_power
    direction, distance = (proj.pos - proj.origin).normalized_with_length()
    span = min(distance, profile.tail)
    rgb, width = profile.rgb, profile.width
    if proj.type_id in _PLASMA:
        # The sprite's short tail follows its stored heading and speed scale.
        direction = Vec2.from_heading(proj.angle)
        span = min(distance, profile.tail * proj.speed_scale)
        if proj.life_timer < 0.4:
            # All five plasma variants switch to the same untinted warm 56px glow.
            rgb, width, span = (1.1, 0.57, 0.12), 5.0, 0.0
    elif proj.type_id == PT.PULSE_GUN:
        width = min(18.0, max(1.0, distance * 0.035))
        if proj.life_timer < 0.4:
            rgb, width = (0.7, 0.36, 0.08), 5.0
    beam_scale = STREAK_SCALES.get(proj.type_id)
    beam_profile = None
    if beam_scale is not None:
        if direction.length_sq() == 0:
            direction = Vec2.from_heading(proj.angle)
        beam_profile = (16. * beam_scale, min(beam_scale * 3.1, 9.), 1.35 if proj.type_id == PT.FIRE_BULLETS else 1.05)
    return MaterialLight(
        proj.pos - direction * (span * 0.5),
        profile.radius,
        (rgb[0] * gain, rgb[1] * gain, rgb[2] * gain),
        height=profile.height,
        direction=direction,
        length=span,
        source_width=width,
        illumination_gain=profile.illumination,
        broad_illumination=profile.broad_illumination,
        reflection_gain=profile.reflection,
        reflection_radius=profile.reach,
        beam_profile=beam_profile,
        beam_ion=beam_scale is not None and proj.type_id != PT.FIRE_BULLETS,
    )


def ion_arc_sources(
    frame: RenderFrame, projectile: Projectile, *, view_center: Vec2 | None = None,
) -> list[MaterialLight]:
    """Light up to four visible arc segments and their contact glows per impact.

    The existing beam source remains independent. These do not inherit its 4x
    ground gain or ambient dip. No extra render pass is introduced; arcs compete
    within the existing illumination/reflection source limits.
    """
    targets = [creature.pos for creature in ion_arc_targets(frame, projectile)
               if projectile.pos.distance_to(creature.pos) > 1e-3]
    if not targets:
        return []
    # Bound allocation/sorting work before entering the shared source selector.
    # Rank by distance to the visible segment, with endpoint distance breaking
    # ties at a shared impact point. All connections remain in the artwork.
    center = projectile.pos if view_center is None else view_center

    def rank(target: Vec2) -> tuple[float, float]:
        delta = target - projectile.pos
        offset = center - projectile.pos
        along = max(0., min(1., (offset.x * delta.x + offset.y * delta.y) / delta.length_sq()))
        return (offset - delta * along).length_sq(), (target - center).length_sq()

    targets = nsmallest(4, targets, key=rank)
    profile = PROJECTILE_EMISSIONS[projectile.type_id]
    energy = min(1.0, projectile.life_timer * 2.5)
    rgb = (profile.rgb[0] * energy, profile.rgb[1] * energy, profile.rgb[2] * energy)
    width = STREAK_SCALES[projectile.type_id] * 1.5
    sources: list[MaterialLight] = []
    for target in targets:
        direction, length = (target - projectile.pos).normalized_with_length()
        sources.append(MaterialLight(
            (projectile.pos + target) * .5, 100., rgb, height=18.,
            direction=direction, length=length, source_width=width,
            illumination_gain=.75, reflection_gain=.5, reflection_radius=120.,
            reflection_tail=1., broad_illumination=True,
        ))
        sources.append(MaterialLight(
            target, 60., rgb, height=18., source_width=width * 1.5,
            illumination_gain=.25, reflection_gain=.25, reflection_radius=90.,
            broad_illumination=True,
        ))
    return sources


def _flame_sources(frame: RenderFrame) -> list[MaterialLight]:
    # Bound dense streams spatially instead of allocating one light per particle.
    cells: dict[tuple[int, int, ParticleStyleId], list[Particle]] = {}
    for p in frame.state.particles.entries:
        if p.active and p.style_id != ParticleStyleId.BUBBLEGUN and p.color_a > 0.02:
            key = (math.floor(p.pos.x / 64), math.floor(p.pos.y / 64), p.style_id)
            cells.setdefault(key, []).append(p)
    result = []
    for particles in cells.values():
        weight = sum(p.color_a for p in particles)
        pos = sum((p.pos * p.color_a for p in particles), Vec2()) / weight
        direction = sum((p.vel * p.color_a for p in particles), Vec2()).normalized()
        # Approximate the warm atlas modulated by the particle's evolving tint.
        rgb = tuple(
            sum(((p.color_r, p.color_g, p.color_b)[c] ** 2.2 * tint + aura) * p.color_a for p in particles) * 0.45
            for c, tint, aura in ((0, 1.0, 0.06), (1, 0.52, 0.03), (2, 0.11, 0.006))
        )
        scale = min(1.0, 1.8 / max(max(rgb), 0.001))
        result.append(
            MaterialLight(
                pos,
                110.0,
                (rgb[0] * scale, rgb[1] * scale, rgb[2] * scale),
                height=20.0,
                broad_illumination=True,
                direction=direction,
                length=28.0 if direction.length_sq() > 0.0 else 0.0,
                source_width=5.0,
                reflection_radius=140.0,
            ),
        )
    return result


def _distance_sq(source: MaterialLight, point: Vec2) -> float:
    if source.ring_radius > 0.0:
        return ((point - source.pos).length() - source.ring_radius) ** 2
    axis = source.direction.normalized() if source.direction.length_sq() > .0001 else Vec2()
    delta = point - source.pos
    along = max(-source.length * 0.5, min(source.length * 0.5, delta.x * axis.x + delta.y * axis.y))
    return (point - source.pos - axis * along).length_sq()


def select_material_lights(sources: list[MaterialLight], *, view_center: Vec2) -> list[MaterialLight]:
    """Select each response independently, then mask unselected channels in their union."""

    def score(index: int, *, reflection: bool) -> float:
        source = sources[index]
        gain = source.reflection_gain if reflection else source.illumination_gain
        radius = source.reflection_reach if reflection else source.radius
        return max(source.rgb) * gain / (1.0 + _distance_sq(source, view_center) / max(1.0, radius * radius))

    illumination = sorted(
        (i for i in range(len(sources)) if score(i, reflection=False) > 0.0),
        key=lambda i: score(i, reflection=False),
        reverse=True,
    )[:MAX_ILLUMINATION_SOURCES]
    reflection = sorted(
        (i for i in range(len(sources)) if score(i, reflection=True) > 0.0),
        key=lambda i: score(i, reflection=True),
        reverse=True,
    )[:MAX_REFLECTION_SOURCES]
    lit, reflected = set(illumination), set(reflection)
    return [
        msgspec.structs.replace(
            source,
            illumination_gain=source.illumination_gain if i in lit else 0.0,
            reflection_gain=source.reflection_gain if i in reflected else 0.0,
        )
        for i, source in enumerate(sources)
        if i in lit or i in reflected
    ]


def collect_material_lights(frame: RenderFrame, *, view_center: Vec2) -> list[MaterialLight]:
    sources: list[MaterialLight] = []
    for player in frame.players:
        if PerkId.RADIOACTIVE in frame.state.perks:
            # Follow the visible aura, including its native post-death presence.
            pulse = ((math.sin(frame.elapsed_ms * .001) + 1.) * .1875 + .25) / .4375
            sources.append(MaterialLight(
                player.pos, 100., (.10, .70, .07), height=18., source_width=13.,
                illumination_gain=3.8 * pulse, reflection_gain=.8 * pulse,
                reflection_radius=100., broad_illumination=True,
            ))
        if player.health > 0.0 and PerkId.SHARPSHOOTER in frame.state.perks:
            near, far, _ = laser_sight_geometry(player.pos, player.aim_heading)
            # The native sight is red at the gun and black at its far end.
            # Reverse the source axis so the shared taper is brightest near the gun.
            direction, length = (near - far).normalized_with_length()
            sources.append(MaterialLight(
                (near + far) * 0.5, 40.0, (1.3, 0.0, 0.0), height=28.0,
                direction=direction, length=length, source_width=1.2,
                illumination_gain=0.0, reflection_gain=1.0, reflection_radius=100.0,
                reflection_tail=0.0,
            ))
        gain = max(0.0, min(1.0, float(player.muzzle_flash_alpha)))
        if gain <= 0.02 or player.health <= 0.0:
            continue
        weapon = WEAPON_BY_ID[player.weapon.weapon_id]
        # Match the visible muzzle pass, including weapons which suppress that sprite.
        if int(weapon.flags or 0) & 8:
            continue
        energetic = (
            player.weapon.weapon_id
            in (
                WeaponId.PLASMA_RIFLE,
                WeaponId.PLASMA_MINIGUN,
                WeaponId.PLASMA_CANNON,
                WeaponId.PLASMA_SHOTGUN,
                WeaponId.MULTI_PLASMA,
                WeaponId.ION_CANNON,
            )
            or player.fire_bullets_timer > 0.0
        )
        # muzzleFlash is warm artwork, even when the gun's projectile is blue.
        sources.append(
            MaterialLight(
                native_fire_muzzle_pos(player.pos, player.aim_heading),
                130.0 if energetic else 65.0,
                (1.6 * gain, 1.0 * gain, 0.4 * gain),
                height=28.0,
                source_width=4.0,
                illumination_gain=0.8 if energetic else 0.12,
                broad_illumination=energetic,
                reflection_gain=0.6,
                reflection_radius=140.0,
            ),
        )
    for projectile in frame.state.projectiles.entries:
        source = projectile_source(projectile)
        if source is not None:
            sources.append(source)
            sources.extend(ion_arc_sources(frame, projectile, view_center=view_center))
    for sec in frame.state.secondary_projectiles.entries:
        if not sec.active:
            continue
        if sec.type_id == ST.DETONATION:
            t = max(0.0, min(1.0, sec.detonation_t))
            gain = (1.0 - t) ** 1.35
            if gain > 0.02:
                sources.append(
                    MaterialLight(
                        sec.pos,
                        360.0 * max(0.35, sec.detonation_scale),
                        (1.75 * gain, 1.05 * gain, 0.38 * gain),
                        height=34.0,
                        broad_illumination=True,
                        source_width=3.0 + 28.0 * t * sec.detonation_scale,
                    ),
                )
        elif sec.type_id in (ST.ROCKET, ST.HOMING_ROCKET, ST.ROCKET_MINIGUN):
            if frame.config is not None and not frame.config.display.flame_glow_enabled:
                continue
            scale = {ST.ROCKET: 1.0, ST.HOMING_ROCKET: 0.7, ST.ROCKET_MINIGUN: 0.4}[sec.type_id]
            direction = Vec2.from_heading(sec.angle)
            sources.append(
                MaterialLight(
                    sec.pos - direction * 12.0,
                    110.0 * scale,
                    (0.9 * scale, 0.47 * scale, 0.1 * scale),
                    height=22.0,
                    smoke_gain=6.0,
                    broad_illumination=True,
                    direction=direction,
                    length=6.0 * scale,
                    source_width=5.0 * scale,
                    reflection_radius=140.0,
                ),
            )
    for visual in frame.state.effects.explosion_visuals:
        shell = explosion_shell(visual.age, visual.scale) if visual.ring_spawned else None
        if shell is not None:
            scale = max(0.1, visual.scale)
            sources.append(MaterialLight(
                visual.pos, 85.0 * scale,
                (0.60 * shell.energy, 0.39 * shell.energy, 0.18 * shell.energy),
                height=16.0 * scale, ring_radius=shell.radius, source_width=8.0 * scale,
                illumination_gain=1.8, reflection_gain=0.65, reflection_radius=100.0 * scale,
                broad_illumination=True,
            ))
        if not visual.emit_light or not visual.fireballs or visual.age < 0.0 or visual.age >= visual.lifetime:
            continue
        # Keep the flash fast, sustain the visible fireball, then fade with its
        # retimed alpha. Height is art-directed: native sprites have no Z data.
        t = visual.age
        fade = min(1.0, max(0.0, 1.0 - t / visual.lifetime) / 0.75)
        gain = 0.2 * math.exp(-t / 0.08) + 0.8 * fade ** 1.1
        rise = min(t / 0.8, 1.0)
        rise = rise * rise * (3.0 - 2.0 * rise)
        scale = max(0.1, visual.scale)
        sources.append(
            MaterialLight(
                visual.pos,
                330.0 * scale,
                (1.8 * gain, 0.92 * gain, 0.3 * gain),
                height=(12.0 + 68.0 * rise) * scale,
                source_width=visual.fireball_radius,
                illumination_gain=6.0,
                reflection_gain=1.2,
                broad_illumination=True,
            ),
        )
    sources.extend(_flame_sources(frame))
    return select_material_lights(sources, view_center=view_center)
