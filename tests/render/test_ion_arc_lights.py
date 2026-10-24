from __future__ import annotations

import msgspec
import pytest

from crimson.creatures.runtime import CreatureState
from crimson.perks import PerkId
from crimson.projectiles.types import Projectile
from crimson.projectiles.types import ProjectileTemplateId as PT
from crimson.render.ion_arcs import ion_arc_targets
from crimson.render.rtx.material_lights import (
    IDENT_ARC,
    MAX_MATERIAL_LIGHTS,
    collect_material_lights,
    ion_arc_sources,
    ion_contact_glows,
    source_ident,
)
from grim.geom import Vec2
from tests.render.test_material_lights import frame


def scene(kind=PT.ION_RIFLE, life=.3):
    snapshot = frame()
    shot = Projectile(active=True, type_id=kind, life_timer=life, pos=Vec2(100, 100), origin=Vec2(0, 100))
    snapshot.state.projectiles.entries[0] = shot
    snapshot.creatures.entries[1] = CreatureState(active=True, pos=Vec2(160, 100), size=50, death_timer=16.)
    return snapshot, shot


@pytest.mark.parametrize('kind', [PT.ION_RIFLE, PT.ION_MINIGUN, PT.ION_CANNON])
def test_arc_sources_follow_visible_targets_and_fade(kind):
    snapshot, shot = scene(kind)
    snapshot.creatures.entries[1].pos = Vec2(125, 100)
    lights = ion_arc_sources(snapshot, shot)
    assert len(lights) == 1
    segment, = lights
    assert segment.pos == Vec2(112.5, 100)
    assert segment.direction == Vec2(1, 0) and segment.length == 25
    assert segment.reflection_tail == 1
    assert segment.illumination_gain > 0 and segment.reflection_gain > 0
    assert segment.beam_profile is None and not segment.beam_ion
    # The contact is a ground glow in the arc's color, not a light.
    glow, = ion_contact_glows(snapshot, view_center=Vec2(100, 100))
    assert glow.pos == Vec2(125, 100) and glow.rgb == segment.rgb
    faded = ion_arc_sources(snapshot, msgspec.structs.replace(shot, life_timer=.15))
    assert faded[0].rgb == pytest.approx(tuple(c * .5 for c in segment.rgb))
    collected = collect_material_lights(snapshot, view_center=Vec2(100, 100))
    assert msgspec.structs.replace(segment, ident=source_ident(IDENT_ARC, 0)) in collected


@pytest.mark.parametrize('life', [0., -.1, .4, .5])
def test_no_arc_light_outside_impact_phase(life):
    snapshot, shot = scene(life=life)
    assert not ion_arc_sources(snapshot, shot)


def test_no_arcs_for_fire_inactive_or_coincident_targets():
    snapshot, shot = scene(PT.FIRE_BULLETS)
    assert not ion_arc_sources(snapshot, shot)
    snapshot, shot = scene()
    shot.active = False
    assert not ion_arc_sources(snapshot, shot)
    shot.active = True
    snapshot.creatures.entries[1].pos = shot.pos
    assert not ion_arc_sources(snapshot, shot)


def test_target_policy_slot_zero_death_boundary_and_perk():
    snapshot, shot = scene()
    template = snapshot.creatures.entries[1]
    # Probe either side of the same strict boundary used by the visible pass.
    boundary = 88 + 50 * .14285715 + 3
    for index, offset in enumerate((20, boundary - .001, boundary + .001, boundary + 10), start=0):
        snapshot.creatures.entries[index] = msgspec.structs.replace(template, pos=shot.pos + Vec2(offset, 0))
    assert list(ion_arc_targets(snapshot, shot)) == [snapshot.creatures.entries[1]]
    snapshot.state.perks[PerkId.ION_GUN_MASTER] = 1
    assert list(ion_arc_targets(snapshot, shot)) == snapshot.creatures.entries[1:4]
    snapshot.creatures.entries[2].death_timer = 5
    snapshot.creatures.entries[3].active = False
    assert list(ion_arc_targets(snapshot, shot)) == [snapshot.creatures.entries[1]]


def test_crowd_energy_is_bounded_and_global_slots_unchanged():
    snapshot, shot = scene()
    template = snapshot.creatures.entries[1]
    energies = []
    for count in (1, 4, 40):
        for index in range(1, count + 1):
            snapshot.creatures.entries[index] = msgspec.structs.replace(template, pos=Vec2(125, 100 + index * .01))
        sources = ion_arc_sources(snapshot, shot)
        assert len(sources) <= 8
        energies.append(tuple(sum(s.rgb[2] * getattr(s, gain) for s in sources) for gain in ('illumination_gain', 'reflection_gain')))
        assert len(collect_material_lights(snapshot, view_center=shot.pos)) <= MAX_MATERIAL_LIGHTS
    assert energies[1] == pytest.approx(tuple(c * 4 for c in energies[0]))
    assert energies[2] == pytest.approx(energies[1])


def test_dense_arc_selection_follows_view_center():
    snapshot, shot = scene(PT.ION_CANNON)
    template = snapshot.creatures.entries[1]
    for i in range(1, 9):
        snapshot.creatures.entries[i] = msgspec.structs.replace(template, pos=Vec2(100 + (60 if i <= 4 else -60), 100 + i))
    right = ion_arc_sources(snapshot, shot, view_center=Vec2(180, 100))
    left = ion_arc_sources(snapshot, shot, view_center=Vec2(20, 100))
    assert all(source.pos.x > 100 for source in right)
    assert all(source.pos.x < 100 for source in left)
