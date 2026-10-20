from __future__ import annotations

import math

import pytest

from crimson.perks import PerkId
from crimson.render.laser_sight import laser_sight_geometry
from crimson.render.rtx.material_lights import collect_material_lights
from grim.geom import Vec2
from tests.render.test_material_lights import frame


@pytest.mark.parametrize('heading', [0., math.pi / 2, math.pi, -1.23, 8.5])
def test_sight_reflection_matches_visible_segment_and_fades_away_from_gun(heading):
    snapshot = frame()
    snapshot.players[:] = snapshot.players[:1]
    player = snapshot.players[0]
    player.pos = Vec2(300, 240)
    player.aim_heading = heading
    snapshot.state.perks[int(PerkId.SHARPSHOOTER)] = 1
    light, = collect_material_lights(snapshot, view_center=player.pos)
    near, far, _ = laser_sight_geometry(player.pos, heading)
    assert (light.pos + light.direction * (light.length / 2) - near).length() < 1e-6
    assert (light.pos - light.direction * (light.length / 2) - far).length() < 1e-6
    assert light.illumination_gain == 0
    assert light.reflection_gain > 0
    assert light.reflection_tail == 0
    assert light.rgb[0] > 0 and light.rgb[1:] == (0, 0)


def test_only_living_players_with_sharpshooter_have_sight_reflections():
    snapshot = frame()
    assert collect_material_lights(snapshot, view_center=Vec2()) == []
    snapshot.state.perks[int(PerkId.SHARPSHOOTER)] = 1
    assert len(collect_material_lights(snapshot, view_center=Vec2())) == 2
    snapshot.players[1].health = 0
    assert len(collect_material_lights(snapshot, view_center=Vec2())) == 1
    snapshot.players[0].health = -1
    assert collect_material_lights(snapshot, view_center=Vec2()) == []
