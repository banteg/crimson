from __future__ import annotations

import random
from pathlib import Path

from crimson.creatures.anim import creature_corpse_frame_for_type
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.sim.world_state import WorldState
from crimson.world import WorldRuntime
from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2


class WorldRuntimeHost:
    def __init__(
        self,
        *,
        assets_dir: Path,
        world_size: float = 1024.0,
        demo_mode_active: bool = False,
        difficulty_level: int = 0,
        hardcore: bool = False,
        preserve_bugs: bool = False,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
        rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    ) -> None:
        self._runtime = WorldRuntime(
            assets_dir=assets_dir,
            world_size=world_size,
            demo_mode_active=demo_mode_active,
            difficulty_level=difficulty_level,
            hardcore=hardcore,
            preserve_bugs=preserve_bugs,
            texture_cache=texture_cache,
            config=config,
            audio=audio,
            audio_rng=audio_rng,
            rtx_mode=rtx_mode,
        )
        player_count = 1
        if config is not None:
            player_count = int(config.player_count)
        self._runtime.reset(player_count=max(1, min(4, int(player_count))))

    # ------------------------------------------------------------------
    # Delegated properties
    # ------------------------------------------------------------------

    @property
    def assets_dir(self) -> Path:
        return self._runtime.assets_dir

    @property
    def world_size(self) -> float:
        return self._runtime.world_size

    @world_size.setter
    def world_size(self, value: float) -> None:
        self._runtime.world_size = float(value)

    @property
    def demo_mode_active(self) -> bool:
        return self._runtime.demo_mode_active

    @demo_mode_active.setter
    def demo_mode_active(self, value: bool) -> None:
        self._runtime.demo_mode_active = bool(value)

    @property
    def difficulty_level(self) -> int:
        return self._runtime.difficulty_level

    @difficulty_level.setter
    def difficulty_level(self, value: int) -> None:
        self._runtime.difficulty_level = int(value)

    @property
    def hardcore(self) -> bool:
        return self._runtime.hardcore

    @hardcore.setter
    def hardcore(self, value: bool) -> None:
        self._runtime.hardcore = bool(value)

    @property
    def preserve_bugs(self) -> bool:
        return self._runtime.preserve_bugs

    @preserve_bugs.setter
    def preserve_bugs(self, value: bool) -> None:
        self._runtime.preserve_bugs = bool(value)

    @property
    def texture_cache(self) -> PaqTextureCache | None:
        return self._runtime.texture_cache

    @texture_cache.setter
    def texture_cache(self, value: PaqTextureCache | None) -> None:
        self._runtime.texture_cache = value

    @property
    def config(self) -> CrimsonConfig | None:
        return self._runtime.config

    @config.setter
    def config(self, value: CrimsonConfig | None) -> None:
        self._runtime.config = value

    @property
    def audio(self) -> AudioState | None:
        return self._runtime.audio

    @audio.setter
    def audio(self, value: AudioState | None) -> None:
        self._runtime.audio = value

    @property
    def audio_rng(self) -> random.Random | None:
        return self._runtime.audio_rng

    @audio_rng.setter
    def audio_rng(self, value: random.Random | None) -> None:
        self._runtime.audio_rng = value

    @property
    def rtx_mode(self) -> RtxRenderMode:
        return self._runtime.rtx_mode

    @rtx_mode.setter
    def rtx_mode(self, value: RtxRenderMode) -> None:
        self._runtime.rtx_mode = value

    @property
    def sim_world(self):
        return self._runtime.sim_world

    @property
    def render_resources(self):
        return self._runtime.render_resources

    @property
    def audio_bridge(self):
        return self._runtime.audio_bridge

    @property
    def terrain_runtime(self):
        return self._runtime.terrain_runtime

    @property
    def camera(self) -> Vec2:
        return self._runtime.camera

    @camera.setter
    def camera(self, value: Vec2) -> None:
        self._runtime.camera = value

    @property
    def lan_player_rings_enabled(self) -> bool:
        return self._runtime.lan_player_rings_enabled

    @lan_player_rings_enabled.setter
    def lan_player_rings_enabled(self, value: bool) -> None:
        self._runtime.lan_player_rings_enabled = bool(value)

    @property
    def lan_local_aim_indicators_only(self) -> bool:
        return self._runtime.lan_local_aim_indicators_only

    @lan_local_aim_indicators_only.setter
    def lan_local_aim_indicators_only(self, value: bool) -> None:
        self._runtime.lan_local_aim_indicators_only = bool(value)

    @property
    def lan_local_player_slot_index(self) -> int:
        return self._runtime.lan_local_player_slot_index

    @lan_local_player_slot_index.setter
    def lan_local_player_slot_index(self, value: int) -> None:
        self._runtime.lan_local_player_slot_index = int(value)

    @property
    def renderer(self):
        return self._runtime.renderer

    # ------------------------------------------------------------------
    # Delegated lifecycle methods
    # ------------------------------------------------------------------

    def sync_audio_bridge_state(self) -> None:
        self._runtime.sync_audio_bridge_state()

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_pos: Vec2 | None = None,
    ) -> None:
        self._runtime.reset(seed=seed, player_count=player_count, spawn_pos=spawn_pos)

    def open(self) -> None:
        self._runtime.open_runtime()

    def close(self) -> None:
        self._runtime.close_runtime()

    def build_render_frame(self) -> RenderFrame:
        return self._runtime.build_render_frame()

    def update_camera(self, dt: float) -> None:
        self._runtime.update_camera(dt)

    # ------------------------------------------------------------------
    # Test-specific methods (not on WorldRuntime)
    # ------------------------------------------------------------------

    def load_world_state(self, world_state: WorldState) -> None:
        self._runtime.sim_world.load_world_state(world_state)

    def sync_ground_settings(self) -> None:
        self._runtime.render_resources.config = self._runtime.config
        self._runtime.render_resources.sync_ground_settings()

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_ids: tuple[int, int, int],
        seed: int,
        layers: int = 3,
    ) -> None:
        self._runtime.terrain_runtime.apply_bootstrap_terrain(
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
        self._runtime.terrain_runtime.set_terrain(
            base_key=base_key,
            overlay_key=overlay_key,
            base_path=base_path,
            overlay_path=overlay_path,
            detail_key=detail_key,
            detail_path=detail_path,
        )
        terrain_seed = int(self._runtime.sim_world.state.rng.state)
        self._runtime.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed, layers=3)

    def _bake_fx_queues(self) -> None:
        self._runtime.render_resources.bake_fx_queues(corpse_frame_for_type=creature_corpse_frame_for_type)

    def draw(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._bake_fx_queues()
        self._runtime.renderer.draw(
            render_frame=self._runtime.build_render_frame(),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._runtime.renderer.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._runtime.renderer.screen_to_world(pos)
