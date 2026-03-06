from __future__ import annotations

from pathlib import Path

from crimson.terrain_slots import DEFAULT_TERRAIN_SLOTS
from grim.assets import TextureId
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.world_runtime import WorldRuntimeHost


def _build_world(assets_dir: Path) -> WorldRuntimeHost:
    return WorldRuntimeHost(assets_dir=assets_dir)


def test_apply_bootstrap_terrain_keeps_sim_rng_state(assets_dir: Path, monkeypatch) -> None:
    world = _build_world(assets_dir)
    tex = rl.Texture()

    def _load_texture(_self, _texture_id: TextureId) -> rl.Texture:
        return tex

    monkeypatch.setattr(type(world.render_resources), "load_texture", _load_texture, raising=True)
    before_rng_state = int(world.sim_world.state.rng.state)

    world.apply_bootstrap_terrain(
        terrain_slots=DEFAULT_TERRAIN_SLOTS,
        seed=1337,
        layers=3,
    )

    assert int(world.sim_world.state.rng.state) == before_rng_state
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._pending_generate_seed or -1) == 1337


def test_set_terrain_slots_updates_render_cache_without_touching_sim_rng(assets_dir: Path, monkeypatch) -> None:
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

    def _load_texture(_self, texture_id: TextureId) -> rl.Texture | None:
        return textures.get(texture_id)

    monkeypatch.setattr(type(world.render_resources), "load_texture", _load_texture, raising=True)

    world.set_terrain_slots(terrain_slots=(0, 1, 3))

    assert int(world.sim_world.state.rng.state) == before_rng_state
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._pending_generate_seed or -1) == before_rng_state
    assert world.render_resources.ground.texture is base
    assert world.render_resources.ground.overlay is overlay
    assert world.render_resources.ground.overlay_detail is detail


def test_reset_schedules_terrain_from_sim_seed_without_advancing_rng(assets_dir: Path) -> None:
    world = _build_world(assets_dir)
    world.render_resources.ground = GroundRenderer(texture=rl.Texture())

    world.reset(seed=4242, player_count=1)

    assert int(world.sim_world.state.rng.state) == 4242
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._pending_generate_seed or -1) == 4242


def test_reset_syncs_world_size_across_sim_and_render_ownership(assets_dir: Path) -> None:
    world = _build_world(assets_dir)
    world.render_resources.ground = GroundRenderer(texture=rl.Texture(), width=1024, height=1024)
    world.world_size = 2048.0

    world.reset(seed=4242, player_count=1)

    assert float(world.sim_world.world_size) == 2048.0
    assert float(world.render_resources.world_size) == 2048.0
    assert float(world.terrain_runtime.world_size) == 2048.0
    assert world.render_resources.ground is not None
    assert int(world.render_resources.ground.width) == 2048
    assert int(world.render_resources.ground.height) == 2048
