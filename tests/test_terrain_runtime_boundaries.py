from __future__ import annotations

from pathlib import Path

from crimson.terrain_assets import TerrainTextureId
from crimson.world.terrain_runtime import DEFAULT_TERRAIN_IDS, normalize_terrain_ids
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.world_runtime import WorldRuntimeHost


def _build_world(assets_dir: Path) -> WorldRuntimeHost:
    return WorldRuntimeHost(assets_dir=assets_dir)


def test_apply_bootstrap_terrain_keeps_sim_rng_state(assets_dir: Path, monkeypatch) -> None:
    world = _build_world(assets_dir)
    tex = rl.Texture()

    def _load_texture(_self, _name: str, *, cache_path: str) -> rl.Texture:
        _ = cache_path
        return tex

    monkeypatch.setattr(type(world.render_resources), "load_texture", _load_texture, raising=True)
    before_rng_state = int(world.sim_world.state.rng.state)

    world.apply_bootstrap_terrain(
        terrain_ids=(
            int(TerrainTextureId.Q1_BASE),
            int(TerrainTextureId.Q1_OVERLAY),
            int(TerrainTextureId.Q1_BASE),
        ),
        seed=1337,
        layers=3,
    )

    assert int(world.sim_world.state.rng.state) == before_rng_state
    assert world.render_resources.ground is not None
    assert bool(world.render_resources.ground.generation_pending())
    assert int(world.render_resources.ground._pending_generate_seed or -1) == 1337


def test_set_terrain_updates_render_cache_without_touching_sim_rng(assets_dir: Path, monkeypatch) -> None:
    world = _build_world(assets_dir)
    before_rng_state = int(world.sim_world.state.rng.state)
    base = rl.Texture()
    overlay = rl.Texture()
    detail = rl.Texture()

    def _load_texture(_self, name: str, *, cache_path: str) -> rl.Texture | None:
        _ = cache_path
        if name == "base":
            return base
        if name == "overlay":
            return overlay
        if name == "detail":
            return detail
        return None

    monkeypatch.setattr(type(world.render_resources), "load_texture", _load_texture, raising=True)

    world.set_terrain(
        base_key="base",
        overlay_key="overlay",
        base_path="base.paq",
        overlay_path="overlay.paq",
        detail_key="detail",
        detail_path="detail.paq",
    )

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


def test_normalize_terrain_ids_falls_back_to_defaults_on_invalid_rows() -> None:
    assert normalize_terrain_ids(None) == DEFAULT_TERRAIN_IDS
    assert normalize_terrain_ids((9999, 1, 2)) == DEFAULT_TERRAIN_IDS
    assert normalize_terrain_ids((int(TerrainTextureId.Q1_BASE),)) == DEFAULT_TERRAIN_IDS  # type: ignore[arg-type]
