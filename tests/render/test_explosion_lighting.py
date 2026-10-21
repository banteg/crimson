from __future__ import annotations

import msgspec
import pytest

from crimson.effects import EffectPool
from crimson.effects_atlas import EffectId
from crimson.render.rtx.material_lights import collect_material_lights
from crimson.render.rtx.shockwaves import PressureFront, ShockwaveRenderer, collect_pressure_fronts
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import ViewTransform
from grim.geom import Vec2
from grim.rand import Crand
from tests.render.test_material_lights import frame


def burst(pool: EffectPool, *, detail: int = 5, emit_light: bool = True) -> int:
    rng = Crand(123)
    pool.spawn_explosion_burst(
        pos=Vec2(100, 120), scale=1, rng=rng, detail_preset=detail, preserve_bugs=False, emit_light=emit_light,
    )
    return rng.state


@pytest.mark.parametrize("detail", [1, 3, 5])
def test_one_explosion_light_survives_flash_and_does_not_depend_on_detail(detail) -> None:
    snapshot = frame()
    burst(snapshot.state.effects, detail=detail)
    lights = collect_material_lights(snapshot, view_center=Vec2(100, 120))
    assert len(lights) == 1
    assert lights[0].rgb == (1.8, 0.92, 0.3)
    assert lights[0].illumination_gain > 0 and lights[0].reflection_gain > 0
    snapshot.state.effects.update(0.4)
    faded = collect_material_lights(snapshot, view_center=Vec2(100, 120))
    assert len(faded) == 2
    fireball = next(light for light in faded if light.ring_radius == 0)
    assert 0 < fireball.rgb[0] < lights[0].rgb[0]
    snapshot.state.effects.update(1.01)
    assert collect_material_lights(snapshot, view_center=Vec2()) == []
    assert snapshot.state.effects.explosion_visuals == []


def test_light_metadata_does_not_change_native_effects_or_rng_and_can_opt_out() -> None:
    a, b = EffectPool(), EffectPool()
    assert burst(a) == burst(b, emit_light=False)
    assert msgspec.to_builtins(a.entries) == msgspec.to_builtins(b.entries)
    assert not b.explosion_visuals[0].emit_light
    snapshot = frame()
    snapshot.state.effects = b
    assert collect_material_lights(snapshot, view_center=Vec2()) == []
    a.reset()
    assert a.explosion_visuals == []


def test_only_semantic_explosion_shell_is_refracted_and_outlives_native_ring() -> None:
    snapshot = frame()
    pool = snapshot.state.effects
    burst(pool)
    pool.update(0.2)
    ctx = WorldRenderCtx(snapshot, ViewTransform(Vec2(10, 20), Vec2(2, 3), Vec2(200, 200), Vec2(400, 600)))
    fronts = collect_pressure_fronts(ctx)
    assert len(fronts) == 1
    assert fronts[0].center == Vec2(220, 420)
    assert fronts[0].radius.x > 0 and fronts[0].radius.y == pytest.approx(fronts[0].radius.x * 1.5)
    ring = pool.explosion_visuals[0].ring
    assert ring is not None
    pool.update(0.3)
    assert pool.explosion_visuals[0].active_ring is None
    assert collect_pressure_fronts(ctx)[0].radius.x > fronts[0].radius.x
    pool.update(0.21)
    assert collect_pressure_fronts(ctx) == []
    pool.reset()
    pool.spawn(EffectId.RING, Vec2(), 5, preserve_bugs=False)
    assert collect_pressure_fronts(ctx) == []


def test_pressure_front_preserves_hdr_and_unaffected_pixels(raylib_context) -> None:
    import struct

    from grim.edr import load_float_render_texture
    from grim.raylib_api import rl
    from grim.texture_mode import texture_mode

    renderer = ShockwaveRenderer()
    target = load_float_render_texture(96, 64)
    try:
        with texture_mode(target):
            rl.clear_background(rl.BLACK)
            for x in range(96):
                rl.draw_rectangle(x, 0, 1, 64, rl.Color(40 + x, 50, 60, 255))
            rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
            for _ in range(3):
                rl.draw_rectangle(3, 3, 8, 8, rl.WHITE)
            rl.end_blend_mode()
        assert renderer.apply(target.texture, [], out_size=Vec2(96, 64)).id == target.texture.id
        assert renderer.target is None
        before = rl.load_image_from_texture(target.texture)
        output = renderer.apply(target.texture, [PressureFront(Vec2(48, 32), Vec2(20, 20), 1)], out_size=Vec2(96, 64))
        after = rl.load_image_from_texture(output)
        try:
            assert before.format == after.format == rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R16G16B16A16
            # Read half floats directly: this pass must not clamp to SDR.
            raw_a = bytes(rl.ffi.buffer(before.data, 96 * 64 * 8))
            raw_b = bytes(rl.ffi.buffer(after.data, 96 * 64 * 8))
            a = struct.unpack("<" + "e" * (96 * 64 * 4), raw_a)
            b = struct.unpack("<" + "e" * (96 * 64 * 4), raw_b)
            assert max(b) > 2.5
            # Away from the front, preserve both image orientation and brightness.
            for x, y in ((5, 5), (90, 50), (48, 32)):
                k = (y * 96 + x) * 4
                assert b[k : k + 3] == pytest.approx(a[k : k + 3], abs=0.002)
            assert max(abs(x - y) for x, y in zip(a, b, strict=True)) > 0.005
        finally:
            rl.unload_image(before)
            rl.unload_image(after)
        renderer.close()
        assert renderer.shader is None and renderer.target is None
    finally:
        renderer.close()
        rl.unload_render_texture(target)


def test_freeing_ring_ends_ownership_before_same_kind_slot_reuse() -> None:
    pool = EffectPool()
    burst(pool)
    pool.update(0.2)
    visual = pool.explosion_visuals[0]
    ring = visual.active_ring
    assert ring is not None
    index = next(i for i, entry in enumerate(pool.entries) if entry is ring)
    pool.free(index)
    reused = pool.spawn(EffectId.RING, Vec2(), 5, preserve_bugs=False)
    assert reused is ring
    assert visual.ring is None and visual.active_ring is None


def test_effect_pool_deepcopy_preserves_ring_ownership_without_live_aliases() -> None:
    import copy

    pool = EffectPool()
    burst(pool)
    pool.update(0.2)
    clone = copy.deepcopy(pool)
    original = pool.explosion_visuals[0].active_ring
    copied = clone.explosion_visuals[0].active_ring
    assert copied is not None and original is not None and copied is not original
    assert any(copied is entry for entry in clone.entries)
    copied_sprite = clone.explosion_visuals[0].fireballs[0]
    original_sprite = pool.explosion_visuals[0].fireballs[0]
    assert copied_sprite.native is not original_sprite.native
    assert any(copied_sprite.native is entry for entry in clone.entries)
    assert copied_sprite.initial is not original_sprite.initial
    assert all(copied is not entry for entry in pool.entries)
    clone.update(0.3)
    assert clone.explosion_visuals[0].active_ring is None
    assert pool.explosion_visuals[0].active_ring is original


def test_rising_light_tracks_retained_visible_fireball_after_native_expiry() -> None:
    snapshot = frame()
    pool = snapshot.state.effects
    burst(pool)
    visual = pool.explosion_visuals[0]
    assert len(visual.fireballs) == 4
    initial = collect_material_lights(snapshot, view_center=Vec2())[0]
    assert initial.height == 12
    pool.update(.8)
    assert all(sprite.native is None for sprite in visual.fireballs)
    assert all(sprite.sample(visual.fireball_age).color.a > .4 for sprite in visual.fireballs)
    risen = collect_material_lights(snapshot, view_center=Vec2())[0]
    assert risen.height == 80
    assert risen.source_width > initial.source_width
    assert risen.rgb[0] > .3
    pool.update(.61)
    assert pool.explosion_visuals == []
    assert collect_material_lights(snapshot, view_center=Vec2()) == []


def test_rocket_burst_keeps_native_lifetime_and_no_archived_fireballs() -> None:
    pool = EffectPool()
    burst(pool, emit_light=False)
    assert pool.explosion_visuals[0].fireballs == []
    pool.update(.71)
    assert pool.explosion_visuals == []


def test_no_invisible_lamp_when_fireball_allocation_is_exhausted() -> None:
    snapshot = frame()
    burst(snapshot.state.effects)
    snapshot.state.effects.explosion_visuals[0].fireballs.clear()
    assert collect_material_lights(snapshot, view_center=Vec2()) == []


def test_shell_light_pressure_and_sprite_share_expanding_profile() -> None:
    from crimson.render.rtx.explosion_shell import explosion_shell

    snapshot = frame()
    burst(snapshot.state.effects)
    visual = snapshot.state.effects.explosion_visuals[0]
    assert explosion_shell(0, 1) is None and explosion_shell(.71, 1) is None
    previous_radius = 0.0
    previous_energy = 2.0
    for age in (.05, .15, .35, .5, .69):
        visual.age = age
        shell = explosion_shell(age, visual.scale)
        assert shell is not None
        light = next(s for s in collect_material_lights(snapshot, view_center=visual.pos) if s.ring_radius > 0)
        assert light.ring_radius == shell.radius > previous_radius
        assert 0 < shell.energy <= previous_energy
        assert light.rgb == pytest.approx((.6 * shell.energy, .39 * shell.energy, .18 * shell.energy))
        assert light.length == 0 and light.source_width == 8 and light.height == 16
        assert 0 < shell.alpha <= .36
        previous_radius, previous_energy = shell.radius, shell.energy
    visual.ring_spawned = False
    assert all(s.ring_radius == 0 for s in collect_material_lights(snapshot, view_center=visual.pos))


@pytest.mark.parametrize("age", [.05, .2, .5, .69])
def test_rocket_burst_omits_shell_light_and_refraction_but_keeps_detonation(age) -> None:
    from crimson.projectiles.types import SecondaryProjectileTypeId

    snapshot = frame()
    burst(snapshot.state.effects, emit_light=False)
    snapshot.state.effects.update(age)
    ctx = WorldRenderCtx(snapshot, ViewTransform(Vec2(), Vec2(1, 1), Vec2(200, 200), Vec2(200, 200)))
    assert collect_pressure_fronts(ctx) == []
    assert collect_material_lights(snapshot, view_center=Vec2()) == []

    detonation = snapshot.state.secondary_projectiles.entries[0]
    detonation.active = True
    detonation.type_id = SecondaryProjectileTypeId.DETONATION
    detonation.pos = Vec2(100, 120)
    detonation.detonation_t = .2
    detonation.detonation_scale = 1
    lights = collect_material_lights(snapshot, view_center=Vec2())
    assert len(lights) == 1 and lights[0].ring_radius == 0
    assert lights[0].illumination_gain > 0 and lights[0].reflection_gain > 0


@pytest.mark.parametrize("rtx, emit_light, rings", [(True, False, 0), (False, False, 1), (True, True, 1)])
def test_rocket_ring_is_hidden_only_in_rtx_while_nuke_shell_remains(
    rtx, emit_light, rings, headless_window, headless_resources, mocker,
) -> None:
    from crimson.render.rtx.mode import RtxRenderMode
    from crimson.render.world import effects
    from tests.support.creature_draw_capture import render_ctx_for_creatures

    ctx = render_ctx_for_creatures(headless_resources, [])
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=RtxRenderMode.RTX if rtx else RtxRenderMode.CLASSIC,
    ))
    pool = ctx.frame.state.effects
    burst(pool, emit_light=emit_light)
    pool.update(.2)
    select = mocker.spy(effects, "effect_cell_src_inset")
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert sum(call.args[1] == EffectId.RING for call in select.call_args_list) == rings

    # A separate ring, such as freeze/shield, must never inherit the exclusion.
    unrelated = pool.spawn(EffectId.RING, Vec2(200, 200), 5, preserve_bugs=False)
    assert unrelated is not None
    unrelated.age = 0
    select.reset_mock()
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert sum(call.args[1] == EffectId.RING for call in select.call_args_list) == rings + 1
