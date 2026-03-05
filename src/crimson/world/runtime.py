from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2

from ..game_modes import GameMode
from ..render.frame import RenderFrame
from ..render.rtx.mode import RtxRenderMode
from ..render.world.renderer import WorldRenderer, WorldRenderHost
from ..sim.batch_apply import apply_presentation_outputs, apply_sim_metadata_batch
from ..sim.clock import FixedStepClock
from ..sim.input import PlayerInput
from ..sim.input_providers import FrameContext, InputStatus, LocalInputProvider
from ..sim.sessions import DeterministicSession
from ..sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from .audio_bridge import AudioBridge
from .presentation import PresentationLayer
from .render_resources import RenderResources
from .sim_world_state import SimWorldState
from .terrain_runtime import TerrainRuntime

WorldTickInputBuilder = Callable[[FrameContext], Sequence[PlayerInput]]


class WorldRuntime:
    """Composition container owning the 4 world components and shared lifecycle methods.

    Satisfies both ``WorldHost`` (sim/tick harness) and ``WorldRenderHost``
    (renderer) protocols, eliminating unsafe ``cast()`` patterns.
    """

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
        self.assets_dir = Path(assets_dir)
        self.world_size = float(world_size)
        self.demo_mode_active = bool(demo_mode_active)
        self.difficulty_level = int(difficulty_level)
        self.hardcore = bool(hardcore)
        self.preserve_bugs = bool(preserve_bugs)
        self.texture_cache = texture_cache
        self.config = config
        self.audio = audio
        self.audio_rng = audio_rng
        self.rtx_mode = rtx_mode

        self.sim_world = SimWorldState(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
            preserve_bugs=bool(self.preserve_bugs),
        )
        render_resources = RenderResources(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            texture_cache=self.texture_cache,
            config=self.config,
        )
        self.presentation = PresentationLayer(
            render_resources=render_resources,
            audio_bridge=AudioBridge(
                demo_mode_active=bool(self.demo_mode_active),
                reflex_boost_timer_source=lambda: float(self.sim_world.state.bonuses.reflex_boost),
                audio=self.audio,
                audio_rng=self.audio_rng,
            ),
            terrain_runtime=TerrainRuntime(
                world_size=float(self.world_size),
                render_resources=render_resources,
            ),
        )

        self.camera = Vec2(-1.0, -1.0)
        self.lan_player_rings_enabled = False
        self.lan_local_aim_indicators_only = False
        self.lan_local_player_slot_index = 0

        self._sync_world_size_ownership()
        self.sync_audio_bridge_state()
        self.renderer = WorldRenderer(cast(WorldRenderHost, self))

    # ------------------------------------------------------------------
    # Forwarding properties (satisfy WorldHost / WorldRenderHost protocols)
    # ------------------------------------------------------------------

    @property
    def render_resources(self) -> RenderResources:
        return self.presentation.render_resources

    @property
    def audio_bridge(self) -> AudioBridge:
        return self.presentation.audio_bridge

    @property
    def terrain_runtime(self) -> TerrainRuntime:
        return self.presentation.terrain_runtime

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
            terrain_seed = int(self.sim_world.state.rng.state)
            self.terrain_runtime.schedule_from_rng_seed(seed=terrain_seed, layers=3)

    def open_runtime(self) -> None:
        self.render_resources.texture_cache = self.texture_cache
        self.render_resources.config = self.config
        self.render_resources.open(terrain_seed=int(self.sim_world.state.rng.state))
        self.texture_cache = self.render_resources.texture_cache

    def close_runtime(self) -> None:
        self.render_resources.close()
        self.sim_world.close_session()

    def sync_audio_bridge_state(self) -> None:
        self.audio_bridge.sync(
            audio=self.audio,
            audio_rng=self.audio_rng,
            demo_mode_active=bool(self.demo_mode_active),
        )

    def update_camera(self, dt: float) -> None:
        _ = dt
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

    # ------------------------------------------------------------------
    # Tick-stepping (absorbed from WorldTickRunnerHarness)
    # ------------------------------------------------------------------

    def init_tick_runner(
        self,
        *,
        game_mode: GameMode,
        build_inputs: WorldTickInputBuilder,
        tick_rate: int = 60,
    ) -> None:
        self._game_mode = game_mode
        self._build_inputs = build_inputs
        self._tick_rate = max(1, int(tick_rate))
        self._session: DeterministicSession | None = None
        self._runner: TickRunner | None = None
        self._world_state: object | None = None
        self._player_count = 0
        self._clock = FixedStepClock(tick_rate=int(self._tick_rate))
        self._frame_index = 0
        self._next_tick_index = 0

    def reset_tick_runner(self) -> None:
        self._session = None
        self._runner = None
        self._world_state = None
        self._player_count = 0
        self._clock = FixedStepClock(tick_rate=int(self._tick_rate))
        self._frame_index = 0
        self._next_tick_index = 0

    def _ensure_runner(self) -> tuple[TickRunner, DeterministicSession]:
        world_state = self.sim_world.world_state
        player_count = len(self.sim_world.players)
        session = self._session
        runner = self._runner
        if (
            session is not None
            and runner is not None
            and self._world_state is world_state
            and int(self._player_count) == int(player_count)
        ):
            return runner, session

        detail_preset = 5
        gore_disabled = 0
        config = self.config
        if config is not None:
            detail_preset = config.detail_preset
            gore_disabled = config.gore_disabled

        session = DeterministicSession(
            world=world_state,
            world_size=float(self.world_size),
            damage_scale_by_type=self.sim_world.damage_scale_by_type,
            fx_queue=self.render_resources.fx_queue,
            fx_queue_rotated=self.render_resources.fx_queue_rotated,
            game_mode=self._game_mode,
            detail_preset=int(detail_preset),
            gore_disabled=int(gore_disabled),
            game_tune_started=bool(self.sim_world.game_tune_started),
            demo_mode_active=bool(self.demo_mode_active),
            auto_pick_perks=False,
            perk_progression_enabled=False,
            apply_world_dt_steps=True,
            clear_fx_queues_each_tick=False,
        )
        provider = LocalInputProvider(
            player_count=int(player_count),
            build_inputs=self._build_inputs,
        )
        runner = TickRunner(
            session=session,
            input_provider=provider,
            config=TickRunnerConfig(),
        )
        self._session = session
        self._runner = runner
        self._world_state = world_state
        self._player_count = int(player_count)
        self._clock = FixedStepClock(tick_rate=int(self._tick_rate))
        self._frame_index = 0
        self._next_tick_index = 0
        return runner, session

    def _apply_tick_batch(
        self,
        *,
        batch: TickBatchResult,
        session: DeterministicSession,
    ) -> int:
        outputs = apply_sim_metadata_batch(
            sim_world=self.sim_world,
            completed_results=batch.completed_results,
            game_tune_started=bool(session.game_tune_started),
        )
        apply_presentation_outputs(
            outputs=outputs,
            sync_audio_bridge_state=self.sync_audio_bridge_state,
            apply_audio_plan=lambda plan, should_apply_audio: self.audio_bridge.apply_plan(
                plan=plan,
                apply_audio=bool(should_apply_audio),
            ),
            update_camera=self.update_camera,
            apply_audio=True,
        )
        return len(outputs)

    def advance_tick_frame(self, dt: float) -> int:
        if not self.sim_world.players:
            return 0
        self.terrain_runtime.process_pending()
        runner, session = self._ensure_runner()
        session.demo_mode_active = bool(self.demo_mode_active)
        dt = float(dt)
        ticks_requested = int(self._clock.advance(dt))
        self._frame_index = int(self._frame_index) + 1
        runner.begin_frame(
            FrameContext(
                dt_seconds=float(dt),
                tick_dt_seconds=float(self._clock.dt_tick),
                frame_index=int(self._frame_index),
                candidate_ticks=max(0, int(ticks_requested)),
                is_networked=False,
                is_replay=False,
            ),
        )
        batch = runner.advance_ticks(
            start_tick=int(self._next_tick_index),
            ticks_requested=max(0, int(ticks_requested)),
            tick_dt=float(self._clock.dt_tick),
        )
        self._next_tick_index = int(batch.next_tick_index)
        if batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
            unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
            if unconsumed_ticks > 0:
                self._clock.accum += float(unconsumed_ticks) * float(self._clock.dt_tick)
        return self._apply_tick_batch(
            batch=batch,
            session=session,
        )
