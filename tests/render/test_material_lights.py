from __future__ import annotations

from typing import Any, cast

import pytest

from crimson.creatures.runtime import CreaturePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.material_lights import MAX_MATERIAL_LIGHTS, collect_material_lights
from crimson.render.rtx.mode import RtxRenderMode
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def frame() -> RenderFrame:
    return RenderFrame(
        config=None, camera=Vec2(), ground=None, state=GameplayState(),
        players=[PlayerState(index=0, pos=Vec2(0, 0)), PlayerState(index=1, pos=Vec2(900, 0))],
        creatures=CreaturePool(), resources=cast(Any, None), elapsed_ms=0, bonus_anim_phase=0, rtx_mode=RtxRenderMode.RTX,
    )


def test_light_budget_follows_view_not_player_order() -> None:
    snapshot = frame()
    for i, projectile in enumerate(snapshot.state.projectiles.entries[:MAX_MATERIAL_LIGHTS * 2]):
        projectile.active = True
        projectile.type_id = ProjectileTemplateId.PLASMA_RIFLE
        projectile.life_timer = .4
        projectile.pos = Vec2(10 * i, 0)
    right = collect_material_lights(snapshot, view_center=Vec2(900, 0))
    snapshot.players.reverse()
    assert collect_material_lights(snapshot, view_center=Vec2(900, 0)) == right
    left = collect_material_lights(snapshot, view_center=Vec2(0, 0))
    assert len(right) == len(left) == MAX_MATERIAL_LIGHTS
    assert min(light.pos.x for light in right) > max(light.pos.x for light in left)


def test_muzzle_radiance_fades_linearly() -> None:
    snapshot = frame()
    player = snapshot.players[0]
    player.muzzle_flash_alpha = 1
    bright = collect_material_lights(snapshot, view_center=Vec2())[0]
    player.muzzle_flash_alpha = .5
    faded = collect_material_lights(snapshot, view_center=Vec2())[0]
    assert faded.rgb == pytest.approx(tuple(channel * .5 for channel in bright.rgb))


@pytest.mark.parametrize("kind, height", [(ProjectileTemplateId.ION_RIFLE, 40.), (ProjectileTemplateId.PLASMA_RIFLE, 18.)])
def test_projectile_emitter_height_preserves_beam_reflection_offset(kind, height) -> None:
    snapshot = frame()
    projectile = snapshot.state.projectiles.entries[0]
    projectile.active = True
    projectile.type_id = kind
    projectile.life_timer = .4
    projectile.origin = Vec2(10, 20)
    projectile.pos = Vec2(110, 20)
    light = collect_material_lights(snapshot, view_center=Vec2(60, 20))[0]
    assert light.height == height
    assert light.length == (100 if kind == ProjectileTemplateId.ION_RIFLE else 0)
