from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.render.rtx.mode import RtxRenderMode
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import (
    DeterministicSession,
    DeterministicSessionTick,
    SurvivalSpawnState,
)
from crimson.sim.world_state import WorldState
from crimson.terrain_slots import TerrainSlotTriplet
from crimson.world import WorldRuntime
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.rand import Crand


class WorldRuntimeHost(WorldRuntime):
    def __init__(
        self,
        *,
        assets_dir: Path,
        quest_fail_retry_count: int = 0,
        hardcore: bool = False,
        preserve_bugs: bool = False,
        config: CrimsonConfig | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand | None = None,
        rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    ) -> None:
        resolved_audio_rng = audio_rng if audio_rng is not None else Crand(0xBEEF)
        super().__init__(
            assets_dir=assets_dir,
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
        self.reset(player_count=max(1, min(4, int(player_count))))

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
    ) -> None:
        super().reset(seed=seed, player_count=player_count)
        self._survival_test_spawn_state = SurvivalSpawnState()
        self._survival_test_elapsed_ms = 0.0

    def open(self) -> None:
        self.open_runtime()

    def close(self) -> None:
        self.close_runtime()

    # ------------------------------------------------------------------
    # Test-specific methods (not on WorldRuntime)
    # ------------------------------------------------------------------

    def load_world_state(self, world: WorldState) -> None:
        super().load_world_state(world)
        self._survival_test_spawn_state = SurvivalSpawnState()
        self._survival_test_elapsed_ms = 0.0

    def sync_ground_settings(self) -> None:
        self.render_resources.config = self.config
        self.render_resources.sync_ground_settings()

    def apply_terrain_setup(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
        seed: int,
    ) -> None:
        self.terrain_runtime.apply_terrain_setup(
            terrain_slots=terrain_slots,
            seed=int(seed),
        )

    def step_survival_frame(
        self,
        dt: float,
        *,
        inputs: list[PlayerInput] | None = None,
        perk_progression_enabled: bool = False,
    ) -> DeterministicSessionTick:
        detail_preset = 5
        violence_disabled = 0
        if self.config is not None:
            detail_preset = int(self.config.display.detail_preset)
            violence_disabled = int(self.config.display.violence_disabled)

        session = DeterministicSession(
            world=self.world,
            game_mode=GameMode.SURVIVAL,
            perk_progression_enabled=perk_progression_enabled,
            detail_preset=detail_preset,
            violence_disabled=violence_disabled,
            game_tune_started=self.game_tune_started,
            mode_state=self._survival_test_spawn_state,
        )
        session.elapsed_ms = float(self._survival_test_elapsed_ms)

        tick_inputs = None if inputs is None else list(inputs)
        tick = session.step_tick(
            dt=float(dt),
            inputs=tick_inputs,
        )
        self._survival_test_elapsed_ms = float(session.elapsed_ms)

        self.advance_presentation_clock(dt_sim=tick.dt_sim, game_tune_started=session.game_tune_started)
        apply_presentation_plans(plans=[tick.presentation], runtime=self)
        return tick
