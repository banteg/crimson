from __future__ import annotations

from pathlib import Path

from grim import canvas
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.rand import CrandLike

from ..camera import CameraUpdate, camera_update_for_players
from ..render.frame import RenderFrame
from ..render.rtx.mode import RtxRenderMode
from ..render.world import viewport
from ..render.world.context import WorldRenderCtx
from ..render.world.draw import draw_world, ui_render_aim_indicators
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
        quest_fail_retry_count: int = 0,
        hardcore: bool = False,
        preserve_bugs: bool = False,
        config: CrimsonConfig | None = None,
        audio_rng: CrandLike,
        audio: AudioState | None = None,
        rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    ) -> None:
        self.assets_dir = Path(assets_dir)
        self.quest_fail_retry_count = int(quest_fail_retry_count)
        self.hardcore = bool(hardcore)
        self.preserve_bugs = bool(preserve_bugs)
        self.config = config
        self.audio = audio
        self.audio_rng = audio_rng
        self.rtx_mode = rtx_mode

        self._reset_world(seed=0xBEEF, player_count=1)

        render_resources = RenderResources(
            assets_dir=self.assets_dir,
            config=self.config,
        )
        self.render_resources = render_resources
        self.audio_bridge = AudioBridge(
            reflex_boost_timer=lambda: float(self.world.state.bonuses.reflex_boost),
            audio=self.audio,
            audio_rng=self.audio_rng,
        )
        self.terrain_runtime = TerrainRuntime(
            render_resources=render_resources,
        )

        self.camera = Vec2(-1.0, -1.0)

        self.sync_audio_bridge_state()

    # ------------------------------------------------------------------
    # Shared lifecycle methods (extracted from 4 identical implementations)
    # ------------------------------------------------------------------

    @property
    def detail_preset(self) -> int:
        # Worlds without a loaded config use the game's default detail level.
        return 5 if self.config is None else int(self.config.display.detail_preset)

    @property
    def violence_disabled(self) -> int:
        return 0 if self.config is None else int(self.config.display.violence_disabled)

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
    ) -> None:
        self._reset_world(seed=int(seed), player_count=int(player_count))
        self.render_resources.clear_pending_terrain_fx()
        self.camera = Vec2(-1.0, -1.0)

        if self.render_resources.ground is not None:
            terrain_seed = self.world.state.rng.state
            self.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed)

    def _reset_world(self, *, seed: int, player_count: int) -> None:
        self.world = build_reset_world(
            seed=seed,
            player_count=player_count,
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

        screen_size = viewport.camera_screen_size(
            config=self.config,
            runtime_w=float(canvas.width()),
            runtime_h=float(canvas.height()),
        )
        camera = self.camera if update.focus is None else screen_size * 0.5 - update.focus
        camera = camera + update.shake
        self.camera = viewport.clamp_camera(
            camera=camera,
            screen_size=screen_size,
        )

    def draw(self, *, entity_alpha: float = 1.0) -> None:
        self.render_resources.process_ground_pending()
        draw_world(self._render_ctx(), entity_alpha=entity_alpha)

    def draw_aim_indicators(self, *, show_aim: bool, entity_alpha: float = 1.0) -> None:
        ui_render_aim_indicators(self._render_ctx(), show_aim=show_aim, entity_alpha=entity_alpha)

    def _render_ctx(self) -> WorldRenderCtx:
        return WorldRenderCtx(frame=self.build_render_frame(), view=self.view_transform())

    def view_transform(self) -> viewport.ViewTransform:
        return viewport.view_transform(
            config=self.config, camera=self.camera,
            out_size=Vec2(float(canvas.width()), float(canvas.height())),
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
            elapsed_ms=float(self.presentation_elapsed_ms),
            bonus_anim_phase=float(self.bonus_anim_phase),
            rtx_mode=self.rtx_mode,
        )
