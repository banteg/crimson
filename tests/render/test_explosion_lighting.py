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
    assert len(faded) == 1 and 0 < faded[0].rgb[0] < lights[0].rgb[0]
    snapshot.state.effects.update(0.31)
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


def test_only_semantic_explosion_ring_is_refracted_and_reused_slot_is_ignored() -> None:
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
    ring.effect_id = EffectId.BURST
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
    assert all(copied is not entry for entry in pool.entries)
    clone.update(0.3)
    assert clone.explosion_visuals[0].active_ring is None
    assert pool.explosion_visuals[0].active_ring is original
