from __future__ import annotations

from pathlib import Path

import crimson.world.render_resources as render_resources_mod
from crimson.effects import FxQueueEntry
from crimson.sim.terrain_fx import TerrainFxBatch
from crimson.sim.terrain_generate import terrain_generate
from crimson.terrain_slots import DEFAULT_TERRAIN_SLOTS
from grim.assets import TextureId
from grim.color import RGBA
from grim.config import default_crimson_cfg
from grim.rand import Crand
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.world_runtime import WorldRuntimeHost


def _build_world(assets_dir: Path) -> WorldRuntimeHost:
    return WorldRuntimeHost(assets_dir=assets_dir)


def test_apply_terrain_setup_keeps_sim_rng_state(assets_dir: Path, monkeypatch) -> None:
    runtime = _build_world(assets_dir)
    tex = rl.Texture()

    def _texture(_self, _texture_id: TextureId) -> rl.Texture:
        return tex

    monkeypatch.setattr(type(runtime.render_resources), "registry_texture", _texture, raising=True)
    before_rng_state = int(runtime.world.state.rng.state)
    setup = terrain_generate(Crand(1337), DEFAULT_TERRAIN_SLOTS)

    runtime.apply_terrain_setup(setup)
    runtime.apply_terrain_setup(setup)

    assert int(runtime.world.state.rng.state) == before_rng_state
    assert runtime.render_resources.ground is not None
    assert runtime.render_resources.ground._scheduled_layers is setup.layers
    assert runtime.terrain_setup is setup


def test_apply_terrain_setup_updates_render_cache_without_touching_sim_rng(assets_dir: Path, monkeypatch) -> None:
    runtime = _build_world(assets_dir)
    before_rng_state = int(runtime.world.state.rng.state)
    base = rl.Texture()
    overlay = rl.Texture()
    detail = rl.Texture()
    textures = {
        TextureId.TER_Q1_BASE: base,
        TextureId.TER_Q1_OVERLAY: overlay,
        TextureId.TER_Q2_OVERLAY: detail,
    }

    def _texture(_self, texture_id: TextureId) -> rl.Texture:
        texture = textures.get(texture_id)
        assert texture is not None
        return texture

    monkeypatch.setattr(type(runtime.render_resources), "registry_texture", _texture, raising=True)

    setup = terrain_generate(Crand(before_rng_state), (0, 1, 3))
    runtime.apply_terrain_setup(setup)

    assert int(runtime.world.state.rng.state) == before_rng_state
    assert runtime.render_resources.ground is not None
    assert runtime.render_resources.ground._scheduled_layers is setup.layers
    assert runtime.render_resources.ground.texture is base
    assert runtime.render_resources.ground.overlay is overlay
    assert runtime.render_resources.ground.overlay_detail is detail


def test_reset_keeps_the_ground_and_its_setup(assets_dir: Path) -> None:
    runtime = _build_world(assets_dir)
    texture = rl.Texture()
    ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)
    runtime.render_resources.ground = ground
    setup = terrain_generate(Crand(7), DEFAULT_TERRAIN_SLOTS)
    runtime.terrain_setup = setup

    runtime.reset(seed=4242, player_count=1)

    assert int(runtime.world.state.rng.state) == 4242
    assert runtime.render_resources.ground is ground
    assert ground._scheduled_layers is None
    assert runtime.terrain_setup is setup


def test_process_ground_pending_does_not_live_sync_texture_scale_from_config(assets_dir: Path) -> None:
    world = _build_world(assets_dir)
    texture = rl.Texture()
    ground = GroundRenderer(
        texture=texture,
        overlay=texture,
        overlay_detail=texture,
        texture_scale=1.0,
    )
    world.render_resources.ground = ground
    config = default_crimson_cfg()
    config.display.texture_scale = 0.5
    world.render_resources.config = config

    world.render_resources.process_ground_pending()

    assert float(ground.texture_scale) == 1.0


def test_consume_terrain_fx_batch_defers_baking_to_draw_even_when_ground_ready(assets_dir: Path, mocker) -> None:
    runtime = _build_world(assets_dir)
    texture = rl.Texture()
    ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)
    ground.render_target = rl.RenderTexture()
    ground._render_target_ready = True
    runtime.render_resources.ground = ground
    runtime.render_resources.fx_textures = render_resources_mod.FxQueueTextures(particles=texture, bodyset=texture)
    batch = TerrainFxBatch(
        decals=(
            FxQueueEntry(
                effect_id=3,
                rotation=0.0,
                pos=runtime.world.players[0].pos,
                width=20.0,
                height=20.0,
                color=RGBA(1.0, 1.0, 1.0, 1.0),
            ),
        ),
    )
    bake_terrain_fx_batch = mocker.patch.object(render_resources_mod, "bake_terrain_fx_batch")

    runtime.render_resources.consume_terrain_fx_batch(batch)

    bake_terrain_fx_batch.assert_not_called()
    assert runtime.render_resources._pending_terrain_fx_batches == [batch]


def test_process_ground_pending_flushes_buffered_terrain_fx_batches(assets_dir: Path, mocker) -> None:
    runtime = _build_world(assets_dir)
    texture = rl.Texture()
    ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)
    runtime.render_resources.ground = ground
    runtime.render_resources.fx_textures = render_resources_mod.FxQueueTextures(particles=texture, bodyset=texture)
    batch = TerrainFxBatch(
        decals=(
            FxQueueEntry(
                effect_id=4,
                rotation=0.1,
                pos=runtime.world.players[0].pos,
                width=18.0,
                height=18.0,
                color=RGBA(0.9, 0.9, 0.9, 1.0),
            ),
        ),
    )
    bake_terrain_fx_batch = mocker.patch.object(render_resources_mod, "bake_terrain_fx_batch")

    runtime.render_resources.consume_terrain_fx_batch(batch)

    bake_terrain_fx_batch.assert_not_called()
    assert runtime.render_resources._pending_terrain_fx_batches == [batch]

    ground.render_target = rl.RenderTexture()
    ground._render_target_ready = True

    runtime.render_resources.process_ground_pending()

    bake_terrain_fx_batch.assert_called_once()
    assert bake_terrain_fx_batch.call_args.kwargs["batch"] == batch
    assert runtime.render_resources._pending_terrain_fx_batches == []
