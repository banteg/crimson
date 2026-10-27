from __future__ import annotations

import msgspec
import numpy as np
import pytest

from crimson.creatures.anim import CREATURE_ANIM, creature_anim_select_frame
from crimson.render.rtx.heat_heads import heat_head_color
from crimson.render.rtx.heat_vision import (
    BODY_OPACITY,
    TRAIL_HALF_LIFE_S,
    HeatVision,
    heat_visibility,
    heat_warmth,
)
from crimson.render.world.draw import _NATIVE_CREATURE_SPRITE_DRAW_ORDER
from crimson.render.world.viewport import ViewTransform
from grim.assets import TextureId, load_runtime_resources, unload_runtime_resources
from grim.color import RGBA
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.texture_mode import texture_mode
from tests.render.test_ground_materials import pixels
from tests.render.test_material_lights import frame


def test_hidden_evil_aliens_show_in_full_and_corpses_cool() -> None:
    snapshot = frame()
    alien = snapshot.creatures.entries[0]
    # Hidden Evil's faintest alien: Monster Vision is the only way to see it.
    alien.active, alien.death_timer, alien.tint = True, 16.0, RGBA(.1, .7, .51, .04)
    assert heat_visibility(alien, snapshot, entity_alpha=1.0) == heat_warmth(alien, snapshot) == 1.0
    alien.death_timer = -5.0
    assert heat_warmth(alien, snapshot) == .5
    assert heat_visibility(alien, snapshot, entity_alpha=.5) == .25
    assert heat_warmth(alien, snapshot) == .5  # a scene fade dims the heat, never cools it


def test_frozen_monsters_show_no_heat_until_the_ice_fades() -> None:
    snapshot = frame()
    spider = snapshot.creatures.entries[0]
    spider.active, spider.death_timer = True, 16.0
    snapshot.state.bonuses.freeze = 4.0
    assert heat_visibility(spider, snapshot, entity_alpha=1.0) == heat_warmth(spider, snapshot) == 0.0
    snapshot.state.bonuses.freeze = .5  # thawing with the ice's own fade
    assert heat_visibility(spider, snapshot, entity_alpha=1.0) == heat_warmth(spider, snapshot) == pytest.approx(.5)


def trail_texels(heat: HeatVision) -> list[float]:
    assert heat.trail is not None
    return [p[0] for p in pixels(heat.trail)]


def test_trails_fade_by_game_time_and_restart_on_rewind(raylib_context) -> None:
    snapshot = frame()
    spider = snapshot.creatures.entries[0]
    spider.active, spider.death_timer, spider.pos, spider.size = True, 16.0, Vec2(64, 64), 40.0
    heat = HeatVision()
    try:
        heat.update(snapshot, ground_size=Vec2(128, 128))
        fresh = max(trail_texels(heat))
        assert fresh > .9
        spider.active = False
        half_life = msgspec.structs.replace(snapshot, elapsed_ms=TRAIL_HALF_LIFE_S * 1000)
        heat.update(half_life, ground_size=Vec2(128, 128))
        assert max(trail_texels(heat)) == pytest.approx(fresh / 2, rel=.02)
        heat.update(half_life, ground_size=Vec2(128, 128))  # a paused frame keeps the trail
        assert max(trail_texels(heat)) == pytest.approx(fresh / 2, rel=.02)
        for halves in (2, 3):
            cooled = msgspec.structs.replace(snapshot, elapsed_ms=halves * TRAIL_HALF_LIFE_S * 1000)
            heat.update(cooled, ground_size=Vec2(128, 128))
            assert max(trail_texels(heat)) == pytest.approx(fresh / 2**halves, rel=.02)
        heat.update(snapshot, ground_size=Vec2(128, 128))  # a rewind starts over
        assert max(trail_texels(heat)) == 0.0
    finally:
        heat.close()


def test_trails_follow_the_camera_and_fade_with_the_scene(raylib_context) -> None:
    snapshot = frame()
    spider = snapshot.creatures.entries[0]
    spider.active, spider.death_timer, spider.pos, spider.size = True, 16.0, Vec2(48, 32), 40.0
    heat = HeatVision()
    target = load_float_render_texture(64, 64)
    # The screen shows world x 16..80: the spider sits at screen x 32.
    view = ViewTransform(Vec2(-16, 0), Vec2(1, 1), Vec2(64, 64), Vec2(64, 64))

    def composite(entity_alpha: float) -> list[float]:
        with texture_mode(target):
            rl.clear_background(rl.BLANK)
            heat.draw_trails(view, ground_size=Vec2(128, 128), entity_alpha=entity_alpha, restore_shader=None)
        return [p[0] for p in pixels(target)]

    try:
        heat.update(snapshot, ground_size=Vec2(128, 128))
        full = composite(1.0)
        peak = max(full)
        assert full.index(peak) % 64 in (31, 32)
        # Stored heat ignores the transition; the composite fades with the scene (gamma-encoded output).
        assert max(composite(.1)) == pytest.approx(peak * .1 ** (1 / 2.2), rel=.02)
        assert max(composite(1.0)) == pytest.approx(peak)
    finally:
        rl.unload_render_texture(target)
        heat.close()


def test_first_heat_frame_keeps_sprites_queued_for_the_enclosing_target(raylib_context) -> None:
    snapshot = frame()
    heat = HeatVision()
    target = load_float_render_texture(16, 16)
    try:
        with texture_mode(target):
            rl.clear_background(rl.BLANK)
            rl.draw_rectangle(0, 0, 16, 16, rl.WHITE)  # still in rlgl's batch
            heat.update(snapshot, ground_size=Vec2(128, 128))  # allocates the trail buffer
        assert all(p[0] == 1.0 for p in pixels(target))
    finally:
        rl.unload_render_texture(target)
        heat.close()


def test_every_monster_living_cycle_has_stable_heat(raylib_context, assets_dir) -> None:
    """Real atlas poses must not make an unchanged living monster flash hot/cold."""
    resources = load_runtime_resources(assets_dir)
    heat = HeatVision()

    def texels(texture):
        image = rl.load_image_from_texture(texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
            data = bytes(rl.ffi.buffer(image.data, image.width * image.height * 4))
            return np.frombuffer(data, dtype=np.uint8).reshape(image.height, image.width, 4)
        finally:
            rl.unload_image(image)

    try:
        # Follow the actual body-pass list: troopers are player artwork, not monsters.
        for type_id in _NATIVE_CREATURE_SPRITE_DRAW_ORDER:
            info = CREATURE_ANIM[type_id]
            texture = resources.texture(TextureId[type_id.name])
            alpha = texels(texture)[:, :, 3]
            target = rl.load_render_texture(texture.width, texture.height)
            try:
                with texture_mode(target):
                    rl.clear_background(rl.Color(15, 18, 25, 255))
                    with heat.body_scope(texture=texture, restore_shader=None):
                        w, h = texture.width // 8, texture.height // 8
                        for index in range(64):
                            x, y = index % 8 * w, index // 8 * h
                            head_x, head_y = heat_head_color(type_id, index)
                            rl.draw_texture_pro(
                                texture, rl_rectangle(x, y, w, h), rl_rectangle(x, y, w, h), rl_vector2(0, 0),
                                0, rl.Color(255, head_x, head_y, round(BODY_OPACITY * 255)),
                            )
                rgb = texels(target.texture)[::-1, :, :3].astype(float) / 255
            finally:
                rl.unload_render_texture(target)
            luminance = rgb @ np.array([.2126, .7152, .0722])
            means = []
            contrasts = []
            w, h = texture.width // 8, texture.height // 8
            for phase in range(32):
                index = creature_anim_select_frame(phase, base_frame=info.base, mirror_long=info.mirror)
                x, y = index % 8 * w, index // 8 * h
                mask = alpha[y:y + h, x:x + w] > 127
                body = luminance[y:y + h, x:x + w][mask]
                means.append(body.mean())
                contrasts.append(np.quantile(body, .9) - np.quantile(body, .1))
            # Includes the loop seam and the mirrored species' turnaround.
            # The previous square-opening heat exceeded .10 for the alien.
            jumps = np.abs(np.roll(means, -1) - means)
            assert jumps.max() < .025, (type_id.name, means)
            # Stability must retain cool extremities and bright internal detail,
            # rather than flattening the entire creature to one temperature.
            assert np.mean(contrasts) > .45, (type_id.name, contrasts)
        expected = {int(resources.texture(TextureId[kind.name]).id) for kind in _NATIVE_CREATURE_SPRITE_DRAW_ORDER}
        assert set(heat.densities) == expected
        heat.close()
        assert not heat.densities
    finally:
        heat.close()
        unload_runtime_resources(resources)
