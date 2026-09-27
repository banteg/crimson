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
from ..render.world.context import WorldRenderCtx
from ..render.world.draw import draw_world
from ..sim.world_reset import build_reset_world
from ..sim.world_state import WorldState
from .audio_bridge import AudioBridge
from .render_resources import RenderResources
from .terrain_runtime import TerrainRuntime


class WorldRuntime:
    """Binds the simulated world to camera, terrain, audio and render resources."""

    world: WorldState
    presentation_elapsed_ms: float
    bonus_anim_phase: float
    game_tune_started: bool

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

        self._reset_world(seed=0xBEEF, player_count=1, spawn_pos=None)

        render_resources = RenderResources(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            config=self.config,
        )
        self.render_resources = render_resources
        self.audio_bridge = AudioBridge(
            reflex_boost_timer=lambda: float(self.world.state.bonuses.reflex_boost),
            audio=self.audio,
            audio_rng=self.audio_rng,
        )
        self.terrain_runtime = TerrainRuntime(
            world_size=float(self.world_size),
            render_resources=render_resources,
        )

        self.camera = Vec2(-1.0, -1.0)

        self._sync_world_size_ownership()
        self.sync_audio_bridge_state()

    # ------------------------------------------------------------------
    # Shared lifecycle methods (extracted from 4 identical implementations)
    # ------------------------------------------------------------------

    def sync_world_size(self) -> None:
        self._sync_world_size_ownership()

    def _sync_world_size_ownership(self) -> None:
        world_size = float(self.world_size)
        self.render_resources.world_size = world_size
        self.terrain_runtime.world_size = world_size

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
        self._reset_world(seed=int(seed), player_count=int(player_count), spawn_pos=spawn_pos)
        self.render_resources.clear_pending_terrain_fx()
        self.camera = Vec2(-1.0, -1.0)

        if self.render_resources.ground is not None:
            terrain_seed = self.world.state.rng.state
            self.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed)

    def _reset_world(self, *, seed: int, player_count: int, spawn_pos: Vec2 | None) -> None:
        self.world = build_reset_world(
            world_size=self.world_size,
            seed=seed,
            player_count=player_count,
            spawn_pos=spawn_pos,
            demo_mode_active=self.demo_mode_active,
            hardcore=self.hardcore,
            quest_fail_retry_count=self.quest_fail_retry_count,
            preserve_bugs=self.preserve_bugs,
        )
        self.presentation_elapsed_ms = 0.0
        self.bonus_anim_phase = 0.0
        self.game_tune_started = False

    def load_world_state(self, world: WorldState) -> None:
        self.world = world

    def advance_presentation_clock(self, *, dt_sim: float, game_tune_started: bool) -> None:
        """Advance the render-only clocks by one simulated tick."""

        if float(dt_sim) > 0.0:
            self.presentation_elapsed_ms += float(dt_sim) * 1000.0
            self.bonus_anim_phase += float(dt_sim) * 1.3
        self.game_tune_started = bool(game_tune_started)

    def open_runtime(self) -> None:
        self.render_resources.config = self.config
        self.render_resources.open(terrain_seed=self.world.state.rng.state)

    def close_runtime(self) -> None:
        self.render_resources.close()
        self.game_tune_started = False

    def sync_audio_bridge_state(self) -> None:
        self.audio_bridge.sync(
            audio=self.audio,
            audio_rng=self.audio_rng,
        )

    def update_camera(self, update: CameraUpdate | None = None) -> None:
        if update is None:
            update = camera_update_for_players(self.world.players, self.world.state.camera_shake_offset)
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

    def draw(
        self,
        *,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
        self.render_resources.process_ground_pending()
        draw_world(
            WorldRenderCtx(frame=self.build_render_frame(), view=self.view_transform()),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def view_transform(self) -> viewport.ViewTransform:
        return viewport.view_transform(
            world_size=self.world_size, config=self.config, camera=self.camera,
            out_size=Vec2(float(rl.get_screen_width()), float(rl.get_screen_height())),
        )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self.view_transform().world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self.view_transform().screen_to_world(pos)

    def build_render_frame(self) -> RenderFrame:
        return self.render_resources.build_render_frame(
            state=self.world.state,
            players=self.world.players,
            creatures=self.world.creatures,
            camera=self.camera,
            demo_mode_active=bool(self.demo_mode_active),
            elapsed_ms=float(self.presentation_elapsed_ms),
            bonus_anim_phase=float(self.bonus_anim_phase),
            rtx_mode=self.rtx_mode,
        )
