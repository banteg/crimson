from __future__ import annotations

from pathlib import Path

from grim import canvas
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.rand import CrandLike

from ..camera import CameraUpdate, camera_update_for_players
from ..render.frame import RenderFrame
from ..render.rtx.debug import RtxDebugView, draw_debug_label
from ..render.rtx.mode import RtxRenderMode
from ..render.rtx.shockwaves import collect_pressure_fronts
from ..render.world import viewport
from ..render.world.context import WorldRenderCtx
from ..render.world.draw import draw_world, ui_render_aim_indicators
from ..sim.clock import PresentationClock
from ..sim.sessions import DeterministicSession
from ..sim.terrain_generate import TerrainSetup
from ..sim.world_reset import build_reset_world
from ..sim.world_state import WorldState
from ..terrain_slots import resolve_terrain_slots
from .audio_bridge import AudioBridge
from .render_resources import RenderResources


class WorldRuntime:
    """Owns the active run: its session and world, bound to camera, terrain, audio and render resources.

    `reset` installs an idle world and drops the session; `start_session` installs a run. Everything else (the
    gameplay modes, the replay viewer) reads the world and session from here.
    """

    world: WorldState
    session: DeterministicSession | None
    presentation: PresentationClock

    def __init__(
        self,
        *,
        assets_dir: Path,
        preserve_bugs: bool = False,
        config: CrimsonConfig | None = None,
        audio_rng: CrandLike,
        audio: AudioState | None = None,
        rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    ) -> None:
        self.assets_dir = Path(assets_dir)
        self.preserve_bugs = bool(preserve_bugs)
        self.config = config
        self.rtx_mode = rtx_mode
        self.rtx_debug = RtxDebugView.SHADED

        self._reset_world(seed=0xBEEF, player_count=1)

        render_resources = RenderResources(
            assets_dir=self.assets_dir,
            config=self.config,
            rtx_mode=rtx_mode,
        )
        self.render_resources = render_resources
        self.audio_bridge = AudioBridge(
            reflex_boost_timer=lambda: float(self.world.state.bonuses.reflex_boost),
            audio=audio,
            audio_rng=audio_rng,
        )
        # The setup the ground was last drawn from; applying it again draws the same stamps.
        self.terrain_setup: TerrainSetup | None = None

        self.camera = Vec2(-1.0, -1.0)
        self.view_cap = viewport.DEFAULT_VIEW_CAP

    @property
    def rtx_mode(self) -> RtxRenderMode:
        return self._rtx_mode

    @rtx_mode.setter
    def rtx_mode(self, mode: RtxRenderMode) -> None:
        self._rtx_mode = mode
        resources = getattr(self, "render_resources", None)
        if resources is not None and resources.rtx_mode is not mode:
            resources.rtx_mode = mode
            resources.smoke.reset()
            resources.debris.reset()

    @property
    def audio(self) -> AudioState | None:
        return self.audio_bridge.audio

    @audio.setter
    def audio(self, value: AudioState | None) -> None:
        self.audio_bridge.audio = value

    @property
    def audio_rng(self) -> CrandLike:
        return self.audio_bridge.audio_rng

    @audio_rng.setter
    def audio_rng(self, value: CrandLike) -> None:
        self.audio_bridge.audio_rng = value

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
        self.render_resources.smoke.reset()
        self.render_resources.debris.reset()
        self.camera = Vec2(-1.0, -1.0)

    def _reset_world(self, *, seed: int, player_count: int) -> None:
        self.session = None
        self.world = build_reset_world(
            seed=seed,
            player_count=player_count,
            preserve_bugs=self.preserve_bugs,
        )
        self.presentation = PresentationClock()

    def start_session(self, session: DeterministicSession) -> None:
        """Install a run: its world is the one stepped, drawn and read until the next reset."""
        self.session = session
        self.world = session.world
        # A keyframe's restored pool numbers its spawns afresh (EffectPool.generation_for_slot).
        self.render_resources.smoke.reset()
        self.render_resources.debris.reset()

    def end_session(self) -> None:
        """Stop stepping the run; its world stays on screen until the next reset."""
        self.session = None

    def open_runtime(self) -> None:
        self.render_resources.config = self.config
        self.render_resources.open()
        self.terrain_setup = None

    def apply_terrain_setup(self, setup: TerrainSetup) -> None:
        """Bind the setup's terrain textures and draw its stamps into the ground."""
        base, overlay, detail = resolve_terrain_slots(setup.terrain_slots, self.render_resources.registry_texture)
        self.render_resources.set_ground_textures(base=base, overlay=overlay, detail=detail)
        self.render_resources.schedule_ground_stamps(setup.layers)
        self.terrain_setup = setup

    def close_runtime(self) -> None:
        self.render_resources.close()

    def update_camera(self, update: CameraUpdate | None = None) -> None:
        if update is None:
            update = camera_update_for_players(self.world.players, self.world.state.camera_shake_offset)

        screen_size = viewport.camera_screen_size(
            config=self.config,
            runtime_w=float(canvas.width()),
            runtime_h=float(canvas.height()),
            view_cap=self.view_cap,
        )
        camera = self.camera if update.focus is None else screen_size * 0.5 - update.focus
        camera = camera + update.shake
        self.camera = viewport.clamp_camera(
            camera=camera,
            screen_size=screen_size,
        )

    @property
    def rtx_debug_active(self) -> bool:
        return self.rtx_mode is RtxRenderMode.RTX and self.rtx_debug is not RtxDebugView.SHADED

    @property
    def rtx_debug_map_active(self) -> bool:
        return self.rtx_debug_active and self.rtx_debug.is_map

    def draw(self, *, entity_alpha: float = 1.0) -> None:
        self.render_resources.process_ground_pending()
        render_ctx = self._render_ctx()
        if self.rtx_mode is RtxRenderMode.RTX and not self.rtx_debug_map_active:
            with self.render_resources.hdr.scope(
                out_size=render_ctx.view.out_size,
                pressure_fronts=collect_pressure_fronts(render_ctx) if entity_alpha > 1e-3 else (),
            ):
                draw_world(render_ctx, entity_alpha=entity_alpha)
        else:
            draw_world(render_ctx, entity_alpha=entity_alpha)
        if self.rtx_debug_active:
            draw_debug_label(self.rtx_debug, self.render_resources.resources.small_font)

    def draw_aim_indicators(self, *, show_aim: bool, aim_enhancement_fade: float, entity_alpha: float = 1.0) -> None:
        if self.rtx_debug_map_active:
            return
        ui_render_aim_indicators(
            self._render_ctx(), show_aim=show_aim, aim_enhancement_fade=aim_enhancement_fade, entity_alpha=entity_alpha,
        )

    def _render_ctx(self) -> WorldRenderCtx:
        return WorldRenderCtx(frame=self.build_render_frame(), view=self.view_transform())

    def view_transform(self) -> viewport.ViewTransform:
        return viewport.view_transform(
            config=self.config, camera=self.camera,
            out_size=Vec2(float(canvas.width()), float(canvas.height())),
            view_cap=self.view_cap,
        )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self.view_transform().world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self.view_transform().screen_to_world(pos)

    def build_render_frame(self) -> RenderFrame:
        smoke_enabled = self.render_resources.sync_smoke_mode()
        return RenderFrame(
            config=self.config,
            camera=self.camera,
            ground=self.render_resources.ground,
            state=self.world.state,
            players=self.world.players,
            creatures=self.world.creatures,
            resources=self.render_resources.resources,
            elapsed_ms=float(self.presentation.elapsed_ms),
            bonus_anim_phase=float(self.presentation.bonus_anim_phase),
            rtx_mode=self.rtx_mode,
            smoke=self.render_resources.smoke if smoke_enabled else None,
            rtx_debug=self.rtx_debug,
            creature_lighting=self.render_resources.creature_lighting,
            player_lighting=self.render_resources.player_lighting,
            bonus_lighting=self.render_resources.bonus_lighting,
            light_selection=self.render_resources.light_selection,
            debris=self.render_resources.debris,
            contact_glows=self.render_resources.contact_glows,
        )
