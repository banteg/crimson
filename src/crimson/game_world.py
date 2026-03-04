from __future__ import annotations

import random
from pathlib import Path
from typing import cast

import msgspec

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl

from .creatures.anim import creature_corpse_frame_for_type
from .render.frame import RenderFrame
from .render.rtx.mode import RtxRenderMode
from .render.world import WorldRenderer
from .sim.world_state import WorldState
from .world import AudioBridge, RenderResources, SimWorldState, TerrainRuntime


class GameWorld(msgspec.Struct):
    assets_dir: Path
    world_size: float = 1024.0
    demo_mode_active: bool = False
    difficulty_level: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    texture_cache: PaqTextureCache | None = None
    config: CrimsonConfig | None = None
    audio: AudioState | None = None
    audio_rng: random.Random | None = None
    rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC
    sim_world: SimWorldState = cast(SimWorldState, None)
    render_resources: RenderResources = cast(RenderResources, None)
    audio_bridge: AudioBridge = cast(AudioBridge, None)
    terrain_runtime: TerrainRuntime = cast(TerrainRuntime, None)
    renderer: WorldRenderer = cast(WorldRenderer, None)
    camera: Vec2 = Vec2(-1.0, -1.0)
    lan_player_rings_enabled: bool = False
    lan_local_aim_indicators_only: bool = False
    lan_local_player_slot_index: int = 0

    def sync_audio_bridge_state(self) -> None:
        self.audio_bridge.sync(
            audio=self.audio,
            audio_rng=self.audio_rng,
            demo_mode_active=bool(self.demo_mode_active),
        )

    def _sync_world_size_ownership(self) -> None:
        world_size = float(self.world_size)
        self.sim_world.world_size = world_size
        self.render_resources.world_size = world_size
        self.terrain_runtime.world_size = world_size
        ground = self.render_resources.ground
        if ground is not None:
            side = max(0, int(world_size))
            ground.width = side
            ground.height = side

    def __post_init__(self) -> None:
        self.sim_world = SimWorldState(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
            preserve_bugs=bool(self.preserve_bugs),
        )
        self.render_resources = RenderResources(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            texture_cache=self.texture_cache,
            config=self.config,
        )
        self.audio_bridge = AudioBridge(
            demo_mode_active=bool(self.demo_mode_active),
            reflex_boost_timer_source=lambda: float(self.sim_world.state.bonuses.reflex_boost),
            audio=self.audio,
            audio_rng=self.audio_rng,
        )
        self.terrain_runtime = TerrainRuntime(
            world_size=float(self.world_size),
            render_resources=self.render_resources,
        )
        self._sync_world_size_ownership()
        self.sync_audio_bridge_state()
        self.camera = Vec2(-1.0, -1.0)
        self.renderer = WorldRenderer(self)
        player_count = 1
        if self.config is not None:
            player_count = self.config.player_count
        self.reset(player_count=max(1, min(4, player_count)))

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_pos: Vec2 | None = None,
    ) -> None:
        self._sync_world_size_ownership()
        self.sim_world.demo_mode_active = bool(self.demo_mode_active)
        self.sim_world.hardcore = bool(self.hardcore)
        self.sim_world.difficulty_level = int(self.difficulty_level)
        self.sim_world.preserve_bugs = bool(self.preserve_bugs)
        self.sim_world.reset(
            seed=int(seed),
            player_count=int(player_count),
            spawn_pos=spawn_pos,
        )
        self.render_resources.fx_queue.clear()
        self.render_resources.fx_queue_rotated.clear()
        self.camera = Vec2(-1.0, -1.0)
        if self.render_resources.ground is not None:
            # Terrain generation seed should be stable across headless/interactive and must not
            # advance the authoritative gameplay RNG stream.
            terrain_seed = int(self.sim_world.state.rng.state)
            self.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed, layers=3)

    def load_world_state(self, world_state: WorldState) -> None:
        """Atomically swap the authoritative world-state backing references."""
        self.sim_world.load_world_state(world_state)

    def _load_texture(self, name: str, *, cache_path: str) -> rl.Texture | None:
        return self.render_resources.load_texture(name, cache_path=cache_path)

    def sync_ground_settings(self) -> None:
        self.render_resources.config = self.config
        self.render_resources.sync_ground_settings()

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_ids: tuple[int, int, int],
        seed: int,
        layers: int = 3,
    ) -> None:
        """Apply a deterministic terrain selection/seed without consuming gameplay RNG."""
        self.terrain_runtime.apply_bootstrap_terrain(
            terrain_ids=terrain_ids,
            seed=int(seed),
            layers=int(layers),
        )

    def set_terrain(
        self,
        *,
        base_key: str,
        overlay_key: str,
        base_path: str,
        overlay_path: str,
        detail_key: str | None = None,
        detail_path: str | None = None,
    ) -> None:
        self.terrain_runtime.set_terrain(
            base_key=base_key,
            overlay_key=overlay_key,
            base_path=base_path,
            overlay_path=overlay_path,
            detail_key=detail_key,
            detail_path=detail_path,
        )
        terrain_seed = int(self.sim_world.state.rng.state)
        self.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed, layers=3)

    def open(self) -> None:
        self.render_resources.texture_cache = self.texture_cache
        self.render_resources.config = self.config
        self.render_resources.open(terrain_seed=int(self.sim_world.state.rng.state))
        self.texture_cache = self.render_resources.texture_cache

    def close(self) -> None:
        self.render_resources.close()
        self.sim_world.close_session()

    def _bake_fx_queues(self) -> None:
        self.render_resources.bake_fx_queues(corpse_frame_for_type=self._corpse_frame_for_type)

    @staticmethod
    def _corpse_frame_for_type(type_id: int) -> int:
        return creature_corpse_frame_for_type(type_id)

    def draw(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        # Bake decals into the ground render target as part of the render pass,
        # matching `fx_queue_render()` placement in `gameplay_render_world`.
        self._bake_fx_queues()
        self.renderer.draw(
            render_frame=self.build_render_frame(),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def build_render_frame(self) -> RenderFrame:
        return self.render_resources.build_render_frame(
            state=self.sim_world.state,
            players=self.sim_world.players,
            creatures=self.sim_world.creatures,
            camera=self.camera,
            demo_mode_active=bool(self.demo_mode_active),
            elapsed_ms=float(self.sim_world.elapsed_ms),
            bonus_anim_phase=float(self.sim_world.bonus_anim_phase),
            lan_player_rings_enabled=bool(self.lan_player_rings_enabled),
            lan_local_aim_indicators_only=bool(self.lan_local_aim_indicators_only),
            lan_local_player_slot_index=int(self.lan_local_player_slot_index),
            rtx_mode=self.rtx_mode,
        )

    def update_camera(self, _dt: float) -> None:
        if not self.sim_world.players:
            return

        screen_size = self.renderer._camera_screen_size()

        alive = [player for player in self.sim_world.players if player.health > 0.0]
        if alive:
            inv_alive = 1.0 / float(len(alive))
            focus = Vec2(
                sum(player.pos.x for player in alive) * inv_alive,
                sum(player.pos.y for player in alive) * inv_alive,
            )
            camera = screen_size * 0.5 - focus
        else:
            camera = self.camera

        camera = camera + self.sim_world.state.camera_shake_offset

        self.camera = self.renderer._clamp_camera(camera, screen_size)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self.renderer.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self.renderer.screen_to_world(pos)
