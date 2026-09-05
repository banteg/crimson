from __future__ import annotations

from pathlib import Path

from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl

from ..camera import CameraUpdate, camera_update_for_players
from ..render.frame import RenderFrame
from ..render.rtx.mode import RtxRenderMode
from ..render.world import viewport
from ..render.world.renderer import WorldRenderer
from .audio_bridge import AudioBridge
from .render_resources import RenderResources
from .sim_world_state import SimWorldState
from .terrain_runtime import TerrainRuntime


class WorldRuntime:
    """Composition container owning the 4 world components and shared lifecycle methods."""

    def __init__(
        self,
        *,
        assets_dir: Path,
        world_size: float = 1024.0,
        demo_mode_active: bool = False,
        quest_fail_retry_count: int = 0,
        hardcore: bool = False,
        preserve_bugs: bool = False,
        config: CrimsonConfig | None = None,
        audio_rng: CrandLike,
        audio: AudioState | None = None,
        rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    ) -> None:
        self.assets_dir = Path(assets_dir)
        self.world_size = float(world_size)
        self.demo_mode_active = bool(demo_mode_active)
        self.quest_fail_retry_count = int(quest_fail_retry_count)
        self.hardcore = bool(hardcore)
        self.preserve_bugs = bool(preserve_bugs)
        self.config = config
        self.audio = audio
        self.audio_rng = audio_rng
        self.rtx_mode = rtx_mode

        self.sim_world = SimWorldState(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            quest_fail_retry_count=int(self.quest_fail_retry_count),
            preserve_bugs=bool(self.preserve_bugs),
        )
        render_resources = RenderResources(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            config=self.config,
        )
        self.render_resources = render_resources
        self.audio_bridge = AudioBridge(
            reflex_boost_timer=lambda: float(self.sim_world.state.bonuses.reflex_boost),
            audio=self.audio,
            audio_rng=self.audio_rng,
        )
        self.terrain_runtime = TerrainRuntime(
            world_size=float(self.world_size),
            render_resources=render_resources,
        )

        self.camera = Vec2(-1.0, -1.0)
        self.renderer = WorldRenderer(
            world_size=float(self.world_size),
            config=self.config,
            camera=self.camera,
        )

        self._sync_world_size_ownership()
        self.sync_audio_bridge_state()

    # ------------------------------------------------------------------
    # Shared lifecycle methods (extracted from 4 identical implementations)
    # ------------------------------------------------------------------

    def sync_world_size(self) -> None:
        self._sync_world_size_ownership()

    def _sync_world_size_ownership(self) -> None:
        world_size = float(self.world_size)
        self.sim_world.world_size = world_size
        self.render_resources.world_size = world_size
        self.terrain_runtime.world_size = world_size
        self.renderer.sync_viewport(
            world_size=world_size,
            config=self.config,
            camera=self.camera,
        )
        ground = self.render_resources.ground
        if ground is not None:
            side = max(0, int(world_size))
            ground.width = side
            ground.height = side

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
        self.sim_world.quest_fail_retry_count = int(self.quest_fail_retry_count)
        self.sim_world.preserve_bugs = bool(self.preserve_bugs)
        self.sim_world.reset(
            seed=int(seed),
            player_count=int(player_count),
            spawn_pos=spawn_pos,
        )
        self.render_resources.clear_pending_terrain_fx()
        self.camera = Vec2(-1.0, -1.0)
        self.renderer.sync_viewport(
            world_size=self.world_size,
            config=self.config,
            camera=self.camera,
        )
        if self.render_resources.ground is not None:
            terrain_seed = self.sim_world.state.rng.state
            self.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed)

    def open_runtime(self) -> None:
        self.render_resources.config = self.config
        self.render_resources.open(terrain_seed=self.sim_world.state.rng.state)

    def close_runtime(self) -> None:
        self.render_resources.close()
        self.sim_world.close_session()

    def sync_audio_bridge_state(self) -> None:
        self.audio_bridge.sync(
            audio=self.audio,
            audio_rng=self.audio_rng,
        )

    def update_camera(self, update: CameraUpdate | None = None) -> None:
        if update is None:
            update = camera_update_for_players(self.sim_world.players, self.sim_world.state.camera_shake_offset)
        if update is None:
            return

        screen_size = viewport.camera_screen_size(
            world_size=self.world_size,
            config=self.config,
            runtime_w=float(rl.get_screen_width()),
            runtime_h=float(rl.get_screen_height()),
        )
        camera = self.camera if update.focus is None else screen_size * 0.5 - update.focus
        camera = camera + update.shake
        self.camera = viewport.clamp_camera(
            world_size=self.world_size,
            camera=camera,
            screen_size=screen_size,
        )
        self.renderer.sync_viewport(
            world_size=self.world_size,
            config=self.config,
            camera=self.camera,
        )

    def draw(
        self,
        *,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
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
            elapsed_ms=float(self.sim_world.presentation_elapsed_ms),
            bonus_anim_phase=float(self.sim_world.bonus_anim_phase),
            rtx_mode=self.rtx_mode,
        )
