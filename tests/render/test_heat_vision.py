from __future__ import annotations

import msgspec
import pytest

from crimson.render.rtx.heat_vision import FROZEN_WARMTH, TRAIL_HALF_LIFE_S, HeatVision, heat_visibility, heat_warmth
from crimson.render.world.viewport import ViewTransform
from grim.color import RGBA
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode
from tests.render.test_ground_materials import pixels
from tests.render.test_material_lights import frame


def test_hidden_evil_aliens_show_in_full_and_corpses_cool() -> None:
    snapshot = frame()
    alien = snapshot.creatures.entries[0]
    # Hidden Evil's faintest alien: Monster Vision is the only way to see it.
    alien.active, alien.death_timer, alien.tint = True, 16.0, RGBA(.1, .7, .51, .04)
    assert heat_visibility(alien, entity_alpha=1.0) == heat_warmth(alien, snapshot, entity_alpha=1.0) == 1.0
    alien.death_timer = -5.0
    assert heat_warmth(alien, snapshot, entity_alpha=1.0) == .5
    assert heat_visibility(alien, entity_alpha=.5) == .25


def test_freeze_cools_monsters_without_hiding_them() -> None:
    snapshot = frame()
    spider = snapshot.creatures.entries[0]
    spider.active, spider.death_timer = True, 16.0
    snapshot.state.bonuses.freeze = 4.0
    assert heat_visibility(spider, entity_alpha=1.0) == 1.0
    assert heat_warmth(spider, snapshot, entity_alpha=1.0) == pytest.approx(FROZEN_WARMTH)
    snapshot.state.bonuses.freeze = .5  # thawing with the ice's own fade
    assert FROZEN_WARMTH < heat_warmth(spider, snapshot, entity_alpha=1.0) < 1.0



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
