from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.sim.hooks import TickResult
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import ResolvedTick
from crimson.sim.presentation_reactions import (
    PostApplyReactionRuntime,
    apply_post_apply_reaction,
    build_post_apply_reaction,
)
from crimson.sim.sessions import (
    DeterministicSession,
    DeterministicSessionTick,
    SurvivalSessionRuntime,
    SurvivalSpawnState,
)
from crimson.sim.world_state import WorldState
from crimson.terrain_slots import TerrainSlotTriplet
from crimson.world import WorldRuntime
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.rand import Crand
from grim.sfx_map import SfxId


class _WorldRuntimeHostPostApplyReactionRuntime(PostApplyReactionRuntime):
    host: WorldRuntimeHost

    def play_sfx(self, sfx: SfxId) -> None:
        self.host.audio_bridge.router.play_sfx(sfx)


class WorldRuntimeHost:
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
        audio: AudioState | None = None,
        audio_rng: Crand | None = None,
        rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    ) -> None:
        resolved_audio_rng = audio_rng if audio_rng is not None else Crand(0xBEEF)
        self._runtime = WorldRuntime(
            assets_dir=assets_dir,
            world_size=world_size,
            demo_mode_active=demo_mode_active,
            quest_fail_retry_count=quest_fail_retry_count,
            hardcore=hardcore,
            preserve_bugs=preserve_bugs,
            config=config,
            audio=audio,
            audio_rng=resolved_audio_rng,
            rtx_mode=rtx_mode,
        )
        player_count = 1
        if config is not None:
            player_count = int(config.gameplay.player_count)
        self._runtime.reset(player_count=max(1, min(4, int(player_count))))
        self._survival_test_spawn_state = SurvivalSpawnState()
        self._survival_test_elapsed_ms = 0.0

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
    def quest_fail_retry_count(self) -> int:
        return self._runtime.quest_fail_retry_count

    @quest_fail_retry_count.setter
    def quest_fail_retry_count(self, value: int) -> None:
        self._runtime.quest_fail_retry_count = int(value)

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
    def audio_rng(self) -> Crand:
        return self._runtime.audio_rng

    @audio_rng.setter
    def audio_rng(self, value: Crand) -> None:
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
        self._survival_test_spawn_state = SurvivalSpawnState()
        self._survival_test_elapsed_ms = 0.0

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
        self._survival_test_spawn_state = SurvivalSpawnState()
        self._survival_test_elapsed_ms = 0.0

    def sync_ground_settings(self) -> None:
        self._runtime.render_resources.config = self._runtime.config
        self._runtime.render_resources.sync_ground_settings()

    def apply_terrain_setup(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
        seed: int,
    ) -> None:
        self._runtime.terrain_runtime.apply_terrain_setup(
            terrain_slots=terrain_slots,
            seed=int(seed),
        )

    def draw(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._runtime.draw(
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._runtime.renderer.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._runtime.renderer.screen_to_world(pos)

    def step_survival_frame(
        self,
        dt: float,
        *,
        inputs: list[PlayerInput] | None = None,
        perk_progression_enabled: bool = False,
        defer_camera_shake_update: bool = False,
        apply_audio: bool = True,
    ) -> DeterministicSessionTick:
        self.sync_audio_bridge_state()
        self.terrain_runtime.process_pending()

        detail_preset = 5
        violence_disabled = 0
        if self.config is not None:
            detail_preset = int(self.config.display.detail_preset)
            violence_disabled = int(self.config.display.violence_disabled)

        session = DeterministicSession(
            world=self.sim_world.world_state,
            world_size=self.world_size,
            damage_scale_by_type=self.sim_world.damage_scale_by_type,
            game_mode=GameMode.SURVIVAL,
            perk_progression_enabled=perk_progression_enabled,
            detail_preset=detail_preset,
            violence_disabled=violence_disabled,
            game_tune_started=self.sim_world.game_tune_started,
            demo_mode_active=self.demo_mode_active,
            defer_camera_shake_update=defer_camera_shake_update,
            mode_runtime=SurvivalSessionRuntime(spawn=self._survival_test_spawn_state),
        )
        session.elapsed_ms = float(self._survival_test_elapsed_ms)

        tick_inputs = None if inputs is None else list(inputs)
        tick = session.step_tick(
            dt=float(dt),
            inputs=tick_inputs,
            trace_rng=False,
        )
        self._survival_test_elapsed_ms = float(session.elapsed_ms)

        self.sim_world.apply_step_metadata(
            events=tick.step.events,
            presentation=tick.step.presentation,
            dt_sim=float(tick.step.dt_sim),
            game_tune_started=session.game_tune_started,
        )
        self.sync_audio_bridge_state()
        self.audio_bridge.apply_plan(
            plan=tick.step.presentation,
            apply_audio=bool(apply_audio),
        )
        self.update_camera(float(tick.step.dt_sim))
        self.render_resources.consume_terrain_fx_batch(tick.step.presentation.terrain_fx)
        apply_post_apply_reaction(
            reaction=build_post_apply_reaction(
                tick_result=TickResult(
                    source_tick=ResolvedTick(
                        tick_index=0,
                        dt_seconds=float(dt),
                        inputs=() if tick_inputs is None else tuple(tick_inputs),
                        commands=(),
                    ),
                    payload=tick,
                ),
            ),
            runtime=_WorldRuntimeHostPostApplyReactionRuntime(host=self),
        )
        return tick
