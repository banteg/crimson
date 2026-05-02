from __future__ import annotations

from pathlib import Path

import crimson.world.render_resources as render_resources_mod
from crimson.sim.terrain_fx import TerrainDecalFx, TerrainFxBatch
from crimson.terrain_slots import DEFAULT_TERRAIN_SLOTS
from grim.assets import TextureId
from grim.color import RGBA
from grim.config import default_crimson_cfg
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.world_runtime import WorldRuntimeHost


def _build_world(assets_dir: Path) -> WorldRuntimeHost:
    return WorldRuntimeHost(assets_dir=assets_dir)


def test_apply_terrain_setup_keeps_sim_rng_state(assets_dir: Path, monkeypatch) -> None:
    world = _build_world(assets_dir)
    tex = rl.Texture()

    def _texture(_self, _texture_id: TextureId) -> rl.Texture:
        return tex

    monkeypatch.setattr(type(world.render_resources), "registry_texture", _texture, raising=True)
    before_rng_state = int(world.sim_world.state.rng.state)

    world.apply_terrain_setup(
        terrain_slots=DEFAULT_TERRAIN_SLOTS,
        seed=1337,
    )

    assert int(world.sim_world.state.rng.state) == before_rng_state
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._scheduled_seed or -1) == 1337


def test_apply_terrain_setup_updates_render_cache_without_touching_sim_rng(assets_dir: Path, monkeypatch) -> None:
    world = _build_world(assets_dir)
    before_rng_state = int(world.sim_world.state.rng.state)
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

    monkeypatch.setattr(type(world.render_resources), "registry_texture", _texture, raising=True)

    world.apply_terrain_setup(terrain_slots=(0, 1, 3), seed=before_rng_state)

    assert int(world.sim_world.state.rng.state) == before_rng_state
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._scheduled_seed or -1) == before_rng_state
    assert world.render_resources.ground.texture is base
    assert world.render_resources.ground.overlay is overlay
    assert world.render_resources.ground.overlay_detail is detail


def test_reset_schedules_terrain_from_sim_seed_without_advancing_rng(assets_dir: Path) -> None:
    world = _build_world(assets_dir)
    texture = rl.Texture()
    world.render_resources.ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)

    world.reset(seed=4242, player_count=1)

    assert int(world.sim_world.state.rng.state) == 4242
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._scheduled_seed or -1) == 4242


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


def test_reset_syncs_world_size_across_sim_and_render_ownership(assets_dir: Path) -> None:
    world = _build_world(assets_dir)
    texture = rl.Texture()
    world.render_resources.ground = GroundRenderer(
        texture=texture,
        overlay=texture,
        overlay_detail=texture,
        width=1024,
        height=1024,
    )
    world.world_size = 2048.0

    world.reset(seed=4242, player_count=1)

    assert float(world.sim_world.world_size) == 2048.0
    assert float(world.render_resources.world_size) == 2048.0
    assert float(world.terrain_runtime.world_size) == 2048.0
    assert world.render_resources.ground is not None
    assert int(world.render_resources.ground.width) == 2048
    assert int(world.render_resources.ground.height) == 2048


def test_consume_terrain_fx_batch_bakes_immediately_when_ground_ready(assets_dir: Path, mocker) -> None:
    world = _build_world(assets_dir)
    texture = rl.Texture()
    ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)
    ground.render_target = rl.RenderTexture()
    ground._render_target_ready = True
    world.render_resources.ground = ground
    world.render_resources.fx_textures = render_resources_mod.FxQueueTextures(particles=texture, bodyset=texture)
    batch = TerrainFxBatch(
        decals=(
            TerrainDecalFx(
                effect_id=3,
                rotation=0.0,
                pos=world.sim_world.players[0].pos,
                width=20.0,
                height=20.0,
                color=RGBA(1.0, 1.0, 1.0, 1.0),
            ),
        ),
    )
    bake_terrain_fx_batch = mocker.patch.object(render_resources_mod, "bake_terrain_fx_batch")

    world.render_resources.consume_terrain_fx_batch(batch)

    bake_terrain_fx_batch.assert_called_once()
    assert bake_terrain_fx_batch.call_args.kwargs["batch"] == batch
    assert world.render_resources._pending_terrain_fx_batches == []


def test_process_ground_pending_flushes_buffered_terrain_fx_batches(assets_dir: Path, mocker) -> None:
    world = _build_world(assets_dir)
    texture = rl.Texture()
    ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)
    world.render_resources.ground = ground
    world.render_resources.fx_textures = render_resources_mod.FxQueueTextures(particles=texture, bodyset=texture)
    batch = TerrainFxBatch(
        decals=(
            TerrainDecalFx(
                effect_id=4,
                rotation=0.1,
                pos=world.sim_world.players[0].pos,
                width=18.0,
                height=18.0,
                color=RGBA(0.9, 0.9, 0.9, 1.0),
            ),
        ),
    )
    bake_terrain_fx_batch = mocker.patch.object(render_resources_mod, "bake_terrain_fx_batch")

    world.render_resources.consume_terrain_fx_batch(batch)

    bake_terrain_fx_batch.assert_not_called()
    assert world.render_resources._pending_terrain_fx_batches == [batch]

    ground.render_target = rl.RenderTexture()
    ground._render_target_ready = True

    world.render_resources.process_ground_pending()

    bake_terrain_fx_batch.assert_called_once()
    assert bake_terrain_fx_batch.call_args.kwargs["batch"] == batch
    assert world.render_resources._pending_terrain_fx_batches == []
