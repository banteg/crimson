from __future__ import annotations

import math
from typing import Any, cast

import msgspec
import pytest

from crimson.perks import PerkId
from crimson.render.rtx.material_lights import collect_material_lights
from crimson.render.rtx.perk_lighting import PerkLighting, monster_vision_sources
from crimson.render.world.viewport import ViewTransform
from grim.geom import Vec2
from tests.render.test_material_lights import frame


def test_monster_vision_keeps_all_sources_and_offscreen_support() -> None:
    snapshot = frame()
    snapshot.state.perks[PerkId.MONSTER_VISION] = 1
    view = ViewTransform(Vec2(-100, -100), Vec2(2, 2), Vec2(200, 100), Vec2(400, 200))
    for c in snapshot.creatures.entries:
        c.active = True
        c.pos = Vec2(150, 150)
        c.death_timer = 16
    assert len(monster_vision_sources(snapshot, view)) == len(snapshot.creatures.entries)
    a, b, c, d, e = snapshot.creatures.entries[:5]
    a.pos = Vec2(41, 150)  # Center outside, finite radius still overlaps.
    b.pos = Vec2(40, 150)  # Finite support ends at the view edge.
    c.active = False
    d.death_timer = -10
    e.death_timer = -5
    sources = monster_vision_sources(snapshot, view, entity_alpha=.5)
    assert len(sources) == len(snapshot.creatures.entries) - 3
    assert sources[0].pos == a.pos
    assert sources[1].alpha == .25  # Native death fade times the scene transition.
    assert all(s.alpha == .5 for s in sources[2:])


def test_monster_vision_does_not_displace_weapon_lights() -> None:
    snapshot = frame()
    snapshot.players[0].muzzle_flash_alpha = 1
    baseline = collect_material_lights(snapshot, view_center=Vec2())
    snapshot.state.perks[PerkId.MONSTER_VISION] = 1
    for c in snapshot.creatures.entries:
        c.active = True
        c.pos = Vec2()
    assert collect_material_lights(snapshot, view_center=Vec2()) == baseline


def test_empty_or_diagnostic_monster_vision_never_allocates(mocker) -> None:
    snapshot = frame()
    lighting = PerkLighting()
    allocate = mocker.patch.object(PerkLighting, "_ensure")
    view = ViewTransform(Vec2(), Vec2(1, 1), Vec2(100, 100), Vec2(100, 100))
    # No ground access or native calls are needed until an eligible source exists.
    lighting.prepare(cast(Any, None), snapshot, view)
    snapshot.state.perks[PerkId.MONSTER_VISION] = 1
    lighting.prepare(cast(Any, None), snapshot, view)
    c = snapshot.creatures.entries[0]
    c.active = True
    c.pos = Vec2(50, 50)
    lighting.prepare(cast(Any, None), snapshot, view, entity_alpha=0)
    lighting.prepare(cast(Any, None), snapshot, view, debug=9)  # Ambient excludes dynamic perks.
    c.pos = Vec2(1000, 1000)
    lighting.prepare(cast(Any, None), snapshot, view)
    allocate.assert_not_called()
    assert lighting.target is None and not lighting.active


@pytest.mark.parametrize("seconds", [0, math.pi / 2, math.pi * 1.5, 91.2])
def test_radioactive_uses_native_aura_phase_range_and_postdeath_presence(seconds) -> None:
    snapshot = frame()
    snapshot.state.perks[PerkId.RADIOACTIVE] = 1
    snapshot.players[1].health = 0
    snapshot = msgspec.structs.replace(snapshot, elapsed_ms=seconds * 1000)
    sources = collect_material_lights(snapshot, view_center=Vec2())
    assert len(sources) == 2
    pulse = ((math.sin(seconds) + 1) * .1875 + .25) / .4375
    for source in sources:
        assert source.radius == source.reflection_reach == 100
        assert source.rgb == (.1, .7, .07)
        assert source.height == 18 and source.source_width == 13
        assert source.illumination_gain == pytest.approx(3.8 * pulse)
        assert source.reflection_gain == pytest.approx(.8 * pulse)


@pytest.mark.parametrize("analytic", [False, True])
def test_analytic_aura_preserves_alpha_order_status_textures_and_classic(mocker, headless_resources, analytic):
    from crimson.creatures.spawn import CreatureFlags
    from crimson.render.rtx.materials import MaterialGroundRenderer
    from crimson.render.world import draw
    from grim.assets import TextureId
    from grim.raylib_api import rl_rectangle
    from tests.support.creature_draw_capture import render_ctx_for_creatures
    from tests.support.factories import make_creature_state

    creature = make_creature_state(pos=Vec2(50, 50), death_timer=-5)
    creature.plague_infected = True
    creature.flags |= CreatureFlags.POISONED
    render_ctx = render_ctx_for_creatures(headless_resources, [creature])
    tex = headless_resources.texture(TextureId.PARTICLES)
    ground = MaterialGroundRenderer(tex, tex, tex)
    render_ctx = msgspec.structs.replace(render_ctx, frame=msgspec.structs.replace(render_ctx.frame, ground=ground))
    aura = object()
    mocker.patch.object(PerkLighting, "ensure_aura_shader", return_value=aura)
    shader = aura if analytic else None
    calls = []

    def begin(value):
        nonlocal shader
        shader = value

    def end():
        nonlocal shader
        shader = None

    def sprite(_tex, src, dst, _origin, _rotation, tint):
        calls.append((shader, (src.x, src.y, src.width, src.height), dst.width, (tint.r, tint.g, tint.b, tint.a)))

    mocker.patch.object(draw.rl, "begin_shader_mode", side_effect=begin)
    mocker.patch.object(draw.rl, "end_shader_mode", side_effect=end)
    mocker.patch.object(draw.rl, "draw_texture_pro", side_effect=sprite)
    blend = mocker.patch.object(draw.rl, "begin_blend_mode")
    ctx = draw.WorldDrawContext(
        entity_alpha=.5, particles_texture=tex, monster_vision=True, monster_vision_analytic=analytic,
        monster_vision_src=rl_rectangle(10, 20, 62, 62), poison_src=rl_rectangle(90, 100, 62, 62),
    )
    draw.draw_creature_overlays(render_ctx, creature, screen=Vec2(50, 50), death_timer=-5, ctx=ctx)
    assert [row[2:] for row in calls] == [
        (90, (255, 255, 0, 64)), (80, (0, 0, 0, 64)), (60, (255, 0, 0, 64)),
    ]
    assert calls[0][1] == ((0, 0, tex.width, tex.height) if analytic else (10, 20, 62, 62))
    assert calls[1][1] == calls[2][1] == (90, 100, 62, 62)
    assert calls[0][0] is (aura if analytic else None)
    assert calls[1][0] is calls[2][0] is headless_resources.alpha_test.shader
    assert shader is (aura if analytic else None)
    blend.assert_not_called()  # Original ordinary alpha blend, never additive green-aura semantics.
