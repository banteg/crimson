"""Shared finite weapon sources, with independent illumination and reflection budgets.

Every source carries an ident, the same from frame to frame: its kind and slot. A volley's co-located shots light as
one source. Selection fades a source in or out over SLEW_TICKS of game time when it wins or loses its place in a
budget (LightSelection), so crossing the cutoff never pops.
"""

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
# The independently selected sets share one upload; overlapping sources occur only once. Sources fading out of a
# budget still upload until they reach zero, within the same bound.
MAX_MATERIAL_LIGHTS = MAX_ILLUMINATION_SOURCES + MAX_REFLECTION_SOURCES
# Shots of one kind whose heads and tails both lie within this many world units light as one source.
VOLLEY_UNITS = 28.0
# Ticks (1/60 s of game time) over which a source fades into or out of a budget.
SLEW_TICKS = 6
# Source idents: the kind in the top byte, its slot below.
IDENT_PLAYER, IDENT_SHOT, IDENT_ARC, IDENT_SECONDARY, IDENT_EXPLOSION, IDENT_FLAME = range(1, 7)


def source_ident(kind: int, number: int) -> int:
    return kind << 24 | number & 0xffffff


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
    # A segment's radiance at its tail, relative to its head: every receiver weights the segment by a linear ramp
    # from it (source_geometry.glsl's segmentRadiance), 1 for a uniform segment.
    reflection_tail: float = 0.18
    beam_profile: tuple[float, float, float] | None = None
    beam_ion: bool = False
    # Artistic scattering response, independent of ground/creature illumination.
    smoke_gain: float = 1.0
    # Which source this is, the same from frame to frame (source_ident): selection fades by it.
    ident: int = -1

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


def projectile_source(proj: Projectile, ident: int = -1) -> MaterialLight | None:
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
        # A streak's stamps fade in from nothing at its tail.
        **({"reflection_tail": 0.0} if beam_profile is not None else {}),
        ident=ident,
    )


class ContactGlow(msgspec.Struct, frozen=True):
    """An ion arc's round glow where it meets a creature, drawn on the ground (contact_glow.frag) instead of taking
    a light: it is always a disc, and a crowd of them would otherwise crowd out the lights."""

    pos: Vec2
    radius: float
    rgb: tuple[float, float, float]


def _ion_arc_targets(
    frame: RenderFrame, projectile: Projectile, view_center: Vec2 | None,
) -> tuple[list[Vec2], tuple[float, float, float]]:
    """Up to four visible arc targets per impact and the arcs' color."""
    targets = [creature.pos for creature in ion_arc_targets(frame, projectile)
               if projectile.pos.distance_to(creature.pos) > 1e-3]
    if not targets:
        return [], (0., 0., 0.)
    # Bound allocation/sorting work before entering the shared source selector.
    # Rank by distance to the visible segment, with endpoint distance breaking
    # ties at a shared impact point. All connections remain in the artwork.
    center = projectile.pos if view_center is None else view_center

    def rank(target: Vec2) -> tuple[float, float]:
        delta = target - projectile.pos
        offset = center - projectile.pos
        along = max(0., min(1., (offset.x * delta.x + offset.y * delta.y) / delta.length_sq()))
        return (offset - delta * along).length_sq(), (target - center).length_sq()

    profile = PROJECTILE_EMISSIONS[projectile.type_id]
    energy = min(1.0, projectile.life_timer * 2.5)
    return nsmallest(4, targets, key=rank), (profile.rgb[0] * energy, profile.rgb[1] * energy, profile.rgb[2] * energy)


def ion_arc_sources(
    frame: RenderFrame, projectile: Projectile, *, view_center: Vec2 | None = None, ident: int = -1,
) -> list[MaterialLight]:
    """Light up to four visible arc segments per impact; their contacts glow (ion_contact_glows).

    The existing beam source remains independent and does not lend the arcs its
    4x ground gain. Arcs compete within the existing illumination/reflection
    source limits; `ident` numbers them from the projectile's.
    """
    targets, rgb = _ion_arc_targets(frame, projectile, view_center)
    if not targets:
        return []
    width = STREAK_SCALES[projectile.type_id] * 1.5
    sources: list[MaterialLight] = []
    for k, target in enumerate(targets):
        direction, length = (target - projectile.pos).normalized_with_length()
        sources.append(MaterialLight(
            (projectile.pos + target) * .5, 100., rgb, height=18.,
            direction=direction, length=length, source_width=width,
            illumination_gain=.75, reflection_gain=.5, reflection_radius=120.,
            reflection_tail=1., broad_illumination=True, ident=ident + k if ident >= 0 else -1,
        ))
    return sources


def ion_contact_glows(frame: RenderFrame, *, view_center: Vec2) -> list[ContactGlow]:
    """Every visible ion arc's contact glow: a 60-unit disc on its creature, in the arc's color."""
    glows = []
    for projectile in frame.state.projectiles.entries:
        targets, rgb = _ion_arc_targets(frame, projectile, view_center)
        glows += [ContactGlow(target, 60., rgb) for target in targets]
    return glows


def _flame_sources(frame: RenderFrame) -> list[MaterialLight]:
    # Bound dense streams spatially instead of allocating one light per particle.
    cells: dict[tuple[int, int, ParticleStyleId], list[Particle]] = {}
    for p in frame.state.particles.entries:
        if p.active and p.style_id != ParticleStyleId.BUBBLEGUN and p.color_a > 0.02:
            key = (math.floor(p.pos.x / 64), math.floor(p.pos.y / 64), p.style_id)
            cells.setdefault(key, []).append(p)
    result = []
    for (cell_x, cell_y, style), particles in cells.items():
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
                ident=source_ident(IDENT_FLAME, (cell_x & 0x3ff) << 14 | (cell_y & 0x3ff) << 4 | int(style) & 0xf),
            ),
        )
    return result


def _distance_sq(source: MaterialLight, point: Vec2, *, reflection: bool = True) -> float:
    """From the point to where the source reaches it, as the shaders place it: an annulus's nearest point; a segment's
    nearest point for reflections, its energy centroid for illumination (source_geometry.glsl's illuminationSource),
    which a streak's dark tail at the muzzle does not pull back."""
    if source.ring_radius > 0.0:
        return ((point - source.pos).length() - source.ring_radius) ** 2
    axis = source.direction.normalized() if source.direction.length_sq() > .0001 else Vec2()
    if not reflection:
        tail = source.reflection_tail
        return (point - source.pos - axis * (source.length * (1. - tail) / (6. * (1. + tail)))).length_sq()
    delta = point - source.pos
    along = max(-source.length * 0.5, min(source.length * 0.5, delta.x * axis.x + delta.y * axis.y))
    return (point - source.pos - axis * along).length_sq()


class LightSelection(msgspec.Struct):
    """Each source's place in the two budgets, by ident: a weight that moves toward 1 while it is selected and 0 while
    it is not, by 1 / SLEW_TICKS per tick of the run's clock. A source seen for the first time starts where it
    belongs, so a new shot lights at once; a rewind or a gap over a second starts over."""

    illumination: dict[int, float] = msgspec.field(default_factory=dict)
    reflection: dict[int, float] = msgspec.field(default_factory=dict)
    elapsed_ms: float = -1.
    ticks: float = 0.

    def advance(self, elapsed_ms: float) -> None:
        gap = elapsed_ms - self.elapsed_ms
        if self.elapsed_ms < 0. or gap < 0. or gap > 1000.:
            self.reset()
            gap = 0.
        self.elapsed_ms, self.ticks = elapsed_ms, gap * 60. / 1000.

    def reset(self) -> None:
        self.illumination.clear()
        self.reflection.clear()
        self.elapsed_ms, self.ticks = -1., 0.

    def slew(self, sources: list[MaterialLight], chosen: set[int], *, reflection: bool) -> dict[int, float]:
        weights = self.reflection if reflection else self.illumination
        step = self.ticks / SLEW_TICKS
        out: dict[int, float] = {}
        present = set()
        for i, source in enumerate(sources):
            present.add(source.ident)
            target = 1. if i in chosen else 0.
            weight = weights.get(source.ident, target)
            weight = min(target, weight + step) if target > weight else max(target, weight - step)
            weights[source.ident] = weight
            if weight > 0.:
                out[i] = weight
        for ident in [ident for ident in weights if ident not in present]:
            del weights[ident]
        return out


def select_material_lights(
    sources: list[MaterialLight], *, view_center: Vec2, selection: LightSelection | None = None,
) -> list[MaterialLight]:
    """Select each response independently, then mask unselected channels in their union.

    Ties go to the lower ident. With a selection, sources fade in and out of the budgets (LightSelection). The union
    comes brightest first (both responses' delivered scores summed) and holds at most MAX_MATERIAL_LIGHTS: the faintest
    fading sources give way."""

    def score(index: int, *, reflection: bool) -> float:
        source = sources[index]
        gain = source.reflection_gain if reflection else source.illumination_gain
        radius = source.reflection_reach if reflection else source.radius
        distance_sq = _distance_sq(source, view_center, reflection=reflection)
        return max(source.rgb) * gain / (1.0 + distance_sq / max(1.0, radius * radius))

    def chosen(reflection: bool, limit: int) -> set[int]:
        scores = [score(i, reflection=reflection) for i in range(len(sources))]
        ranked = sorted((i for i in range(len(sources)) if scores[i] > 0.0), key=lambda i: (-scores[i], sources[i].ident))
        return set(ranked[:limit])

    lit_set, reflected_set = chosen(False, MAX_ILLUMINATION_SOURCES), chosen(True, MAX_REFLECTION_SOURCES)
    if selection is None:
        lit, reflected = dict.fromkeys(lit_set, 1.), dict.fromkeys(reflected_set, 1.)
    else:
        lit = selection.slew(sources, lit_set, reflection=False)
        reflected = selection.slew(sources, reflected_set, reflection=True)
    order = sorted(set(lit) | set(reflected), key=lambda i: (
        -(score(i, reflection=False) * lit.get(i, 0.) + score(i, reflection=True) * reflected.get(i, 0.)),
        sources[i].ident,
    ))[:MAX_MATERIAL_LIGHTS]
    return [
        msgspec.structs.replace(
            sources[i],
            illumination_gain=sources[i].illumination_gain * lit.get(i, 0.),
            reflection_gain=sources[i].reflection_gain * reflected.get(i, 0.),
        )
        for i in order
    ]


def merge_volleys(shots: list[MaterialLight]) -> list[MaterialLight]:
    """Shots of one kind whose heads and tails both lie within VOLLEY_UNITS as one source, as a shotgun's pellets or a
    burst leave the muzzle: their radiance adds, so a volley fanning out splits without changing its total light. The
    merged source keeps one shot's width (every body's shadow margin follows the widest source) and the lowest ident.
    """
    def ends(light: MaterialLight) -> tuple[Vec2, Vec2]:
        half = light.direction * (light.length * .5)
        return light.pos + half, light.pos - half

    def kind(light: MaterialLight) -> tuple:
        return (light.radius, light.height, light.beam_profile, light.broad_illumination, light.reflection_tail,
                light.illumination_gain, light.reflection_gain)

    clusters: list[list[MaterialLight]] = []
    # Clusters by the cell of their first shot's head, searched in the 3x3 cells around a shot's own.
    buckets: dict[tuple, list[int]] = {}
    for light in shots:
        head, tail = ends(light)
        cell = (math.floor(head.x / VOLLEY_UNITS), math.floor(head.y / VOLLEY_UNITS))
        found = None
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                for c in buckets.get((kind(light), cell[0] + dx, cell[1] + dy), ()):
                    first_head, first_tail = ends(clusters[c][0])
                    if (head - first_head).length() <= VOLLEY_UNITS and (tail - first_tail).length() <= VOLLEY_UNITS \
                            and (found is None or c < found):
                        found = c
        if found is None:
            buckets.setdefault((kind(light), *cell), []).append(len(clusters))
            clusters.append([light])
        else:
            clusters[found].append(light)
    merged = []
    for cluster in clusters:
        if len(cluster) == 1:
            merged.append(cluster[0])
            continue
        weights = [max(max(light.rgb), 1e-6) for light in cluster]
        total = sum(weights)
        head = sum((ends(light)[0] * w for light, w in zip(cluster, weights, strict=True)), Vec2()) / total
        tail = sum((ends(light)[1] * w for light, w in zip(cluster, weights, strict=True)), Vec2()) / total
        direction, length = (head - tail).normalized_with_length()
        merged.append(msgspec.structs.replace(
            cluster[0],
            pos=(head + tail) * .5,
            direction=direction if length > 1e-3 else cluster[0].direction,
            length=length,
            rgb=tuple(sum(light.rgb[c] for light in cluster) for c in range(3)),
            ident=min(light.ident for light in cluster),
        ))
    return merged


def collect_material_lights(frame: RenderFrame, *, view_center: Vec2) -> list[MaterialLight]:
    sources: list[MaterialLight] = []
    for number, player in enumerate(frame.players):
        if PerkId.RADIOACTIVE in frame.state.perks:
            # Follow the visible aura, including its native post-death presence.
            pulse = ((math.sin(frame.elapsed_ms * .001) + 1.) * .1875 + .25) / .4375
            sources.append(MaterialLight(
                player.pos, 100., (.10, .70, .07), height=18., source_width=13.,
                illumination_gain=3.8 * pulse, reflection_gain=.8 * pulse,
                reflection_radius=100., broad_illumination=True, ident=source_ident(IDENT_PLAYER, number * 4),
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
                reflection_tail=0.0, ident=source_ident(IDENT_PLAYER, number * 4 + 1),
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
                ident=source_ident(IDENT_PLAYER, number * 4 + 2),
            ),
        )
    shots: list[MaterialLight] = []
    for slot, projectile in enumerate(frame.state.projectiles.entries):
        if not projectile.active:
            continue
        # A slot's next shot is another source, even on the next frame: its spawn point tells them apart.
        number = slot | (math.floor(projectile.origin.x) & 0x7f) << 7 | (math.floor(projectile.origin.y) & 0x7f) << 14
        source = projectile_source(projectile, ident=source_ident(IDENT_SHOT, number))
        if source is not None:
            shots.append(source)
            sources.extend(ion_arc_sources(frame, projectile, view_center=view_center,
                                           ident=source_ident(IDENT_ARC, number * 4)))
    sources.extend(merge_volleys(shots))
    for slot, sec in enumerate(frame.state.secondary_projectiles.entries):
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
                        ident=source_ident(IDENT_SECONDARY, slot),
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
                    ident=source_ident(IDENT_SECONDARY, slot),
                ),
            )
    for visual in frame.state.effects.explosion_visuals:
        # An explosion keeps its spot for its whole life: its position names it.
        spot = (math.floor(visual.pos.x) & 0x7ff) << 12 | (math.floor(visual.pos.y) & 0x7ff) << 1
        shell = (
            explosion_shell(visual.age, visual.scale) if visual.emit_light and visual.ring_spawned else None
        )
        if shell is not None:
            scale = max(0.1, visual.scale)
            sources.append(MaterialLight(
                visual.pos, 85.0 * scale,
                (0.60 * shell.energy, 0.39 * shell.energy, 0.18 * shell.energy),
                height=16.0 * scale, ring_radius=shell.radius, source_width=8.0 * scale,
                illumination_gain=1.8, reflection_gain=0.65, reflection_radius=100.0 * scale,
                broad_illumination=True, ident=source_ident(IDENT_EXPLOSION, spot),
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
                ident=source_ident(IDENT_EXPLOSION, spot | 1),
            ),
        )
    sources.extend(_flame_sources(frame))
    selection = frame.light_selection
    if selection is not None:
        selection.advance(frame.elapsed_ms)
    return select_material_lights(sources, view_center=view_center, selection=selection)
