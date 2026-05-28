from __future__ import annotations

from typing import Literal

from grim.assets import TextureId
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..net.debug_log import lan_debug_log
from ..net.rollback_resync_v5 import (
    ModeStateSnapshotV2,
    RushRuntimeSnapshotV2,
    RushStateSnapshotV2,
)
from ..persistence.save_status import GameStatusData
from ..replay import Replay, ReplayHeader, ReplayRecorder
from ..replay.checkpoints import DEFAULT_CHECKPOINT_SAMPLE_RATE
from ..sim.bootstrap import advance_unlock_terrain
from ..sim.session_builders import build_rush_session
from ..sim.sessions import DeterministicSession, DeterministicSessionTick, RushSpawnState, enforce_rush_loadout
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from .base_gameplay_mode import (
    BaseGameplayMode,
    LanSession,
    LanStepAction,
)
from .components.highscore_record_builder import build_highscore_record_for_game_over

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


class RushMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        config: CrimsonConfig,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand,
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=GameMode.RUSH,
            demo_mode_active=False,
            quest_fail_retry_count=0,
            hardcore=False,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._replay_recorder: ReplayRecorder | None = None
        self._spawn_state = RushSpawnState()
        self._sim_session: DeterministicSession | None = self._new_sim_session()

    def _new_sim_session(self) -> DeterministicSession:
        session, spawn_state = build_rush_session(
            world=self.sim_world.world_state,
            world_size=float(self.world_size),
            damage_scale_by_type=self.sim_world.damage_scale_by_type,
            detail_preset=5,
            violence_disabled=0,
            game_tune_started=bool(self.sim_world.game_tune_started),
            finalize_post_render_lifecycle=True,
        )
        self._spawn_state = spawn_state
        return session

    def open(self) -> None:
        super().open()
        self._reset_gameplay_frame_clock()
        self._reset_lan_capture_clock()

        status = self.state.status
        base_status = self.save_status
        sim_unlock_index = int(status.quest_unlock_index) if status is not None else 0
        sim_unlock_index_full = int(status.quest_unlock_index_full) if status is not None else 0
        status_unlock_index = int(base_status.quest_unlock_index) if base_status is not None else int(sim_unlock_index)
        status_unlock_index_full = (
            int(base_status.quest_unlock_index_full) if base_status is not None else int(sim_unlock_index_full)
        )
        quest_unlock_index = int(sim_unlock_index)
        terrain = advance_unlock_terrain(
            self.state.rng,
            unlock_index=int(quest_unlock_index),
            width=int(self.world_size),
            height=int(self.world_size),
        )
        lan_debug_log(
            "terrain_prelude",
            mode="RushMode",
            lan_enabled=bool(self._lan_enabled),
            lan_role=str(self._lan_role),
            status_quest_unlock_index=int(status_unlock_index),
            status_quest_unlock_index_full=int(status_unlock_index_full),
            sim_quest_unlock_index=int(sim_unlock_index),
            sim_quest_unlock_index_full=int(sim_unlock_index_full),
            quest_unlock_index=int(quest_unlock_index),
            terrain_slots=terrain.terrain_slots,
            terrain_seed=terrain.terrain_seed,
        )
        self.apply_terrain_setup(
            terrain_slots=terrain.terrain_slots,
            seed=terrain.terrain_seed,
        )
        self.sim_world.state.rng.srand(int(self.state.rng.state))
        self._sim_session = self._new_sim_session()
        enforce_rush_loadout(self.sim_world.world_state)
        replay_status = GameStatusData() if status is None else status.as_data()
        record_replay = (not bool(self._lan_enabled)) or str(self._lan_role) == "host"
        if record_replay:
            self._replay_recorder = ReplayRecorder(
                ReplayHeader(
                    game_mode_id=GameMode.RUSH,
                    seed=int(self._run_reset_seed),
                    tick_rate=int(self._gameplay_tick_rate()),
                    quest_fail_retry_count=int(self.quest_fail_retry_count),
                    hardcore=bool(self.hardcore),
                    preserve_bugs=bool(self.state.preserve_bugs),
                    detail_preset=int(self._deterministic_detail_preset()),
                    violence_disabled=int(self._deterministic_violence_disabled()),
                    world_size=float(self.world_size),
                    player_count=len(self.sim_world.players),
                    status=replay_status,
                ),
            )
            self._replay_checkpoints_sample_rate = int(DEFAULT_CHECKPOINT_SAMPLE_RATE)
        else:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def close(self) -> None:
        self._sim_session = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = "back_to_menu"
                self.close_requested = True
            return

        if (not bool(self._lan_enabled)) and rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

    def _enter_game_over(self) -> None:
        if self._game_over_active:
            return

        game_mode_id = GameMode(self.config.gameplay.mode)
        record = build_highscore_record_for_game_over(
            state=self.state,
            player=self.player,
            survival_elapsed_ms=int(self._session_elapsed_ms()),
            creature_kill_count=int(self.creatures.kill_count),
            game_mode_id=game_mode_id,
            hardcore=bool(self.hardcore),
        )

        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True
        self._save_replay()

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return self._session_elapsed_ms()

    def _replay_claimed_stats_complete(self) -> bool:
        return bool(self._game_over_active)

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        return int(self._session_elapsed_ms())

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        kills = int(self.creatures.kill_count)
        return f"rush_{stamp}_kills{kills}"

    def _lan_mode_name(self) -> Literal["rush"]:
        return "rush"

    def _lan_match_session(self) -> DeterministicSession | None:
        return self._sim_session

    def _lan_prepare_frame(
        self,
        role: str,
        dt_ui_ms: float,
        session: LanSession,
        dt_tick: float,
    ) -> bool:
        _ = role, dt_ui_ms, dt_tick
        session.detail_preset = int(self._deterministic_detail_preset())
        session.violence_disabled = int(self._deterministic_violence_disabled())
        return True

    def _lan_on_tick_applied(
        self,
        tick: DeterministicSessionTick,
        frame_tick_index: int | None,
        dt_tick: float,
    ) -> LanStepAction:
        _ = tick, dt_tick
        elapsed_ms = self._session_elapsed_ms()
        spawn_cooldown_ms = float(self._spawn_state.spawn_cooldown_ms)
        if frame_tick_index is not None:
            self._store_net_runtime_snapshot(
                snapshot=RushStateSnapshotV2(
                    tick_index=int(frame_tick_index),
                    replay_state=self._net_replay_snapshot_state(),
                    runtime_state=RushRuntimeSnapshotV2(
                        elapsed_ms=elapsed_ms,
                        spawn_cooldown_ms=spawn_cooldown_ms,
                        kill_count=int(self.creatures.kill_count),
                    ),
                ),
            )
        if not self._any_player_alive():
            self._enter_game_over()
            return "stop_after_finalize"
        return "continue"

    def _apply_resync_snapshot(self, snapshot: ModeStateSnapshotV2) -> None:
        if not isinstance(snapshot, RushStateSnapshotV2):
            return
        rs = snapshot.runtime_state
        if self._sim_session is not None:
            self._sim_session.elapsed_ms = float(rs.elapsed_ms)
        self._spawn_state.spawn_cooldown_ms = float(rs.spawn_cooldown_ms)
        self.creatures.kill_count = int(rs.kill_count)

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return

        if self._game_over_active:
            self._update_game_over_ui(float(frame.dt))
            return

        if bool(self._lan_enabled) and self._lan_runtime is not None:
            self._update_lan_match(dt=float(frame.dt), dt_ui_ms=0.0)
            return

        any_alive = self._any_player_alive()
        sim_dt = float(frame.dt) if ((not self._paused) and any_alive) else 0.0
        session = self._sim_session

        if self._lan_wait_gate_active():
            self._reset_gameplay_frame_clock()
            return
        if sim_dt <= 0.0:
            self._reset_gameplay_frame_clock()
            if not any_alive:
                self._enter_game_over()
            return
        if session is None:
            return

        self._run_deterministic_session_ticks(
            dt_frame=float(sim_dt),
            session=session,
            recorder=self._replay_recorder,
            stop_on_mode_tick=True,
        )

    def _draw_game_cursor(self) -> None:
        resources = self.render_resources.resources
        mouse_pos = self._ui_mouse
        draw_menu_cursor(
            resources.texture(TextureId.PARTICLES),
            resources.texture(TextureId.UI_CURSOR),
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )

    def draw(self) -> None:
        self._draw_world(
            draw_aim_indicators=(not self._game_over_active),
            entity_alpha=self._world_entity_alpha(),
        )
        self._draw_screen_fade()

        hud_bottom = 0.0
        if not self._game_over_active:
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    resources=self.render_resources.resources,
                    state=self._hud_state,
                    font=self._small,
                    show_health=hud_flags.show_health,
                    show_weapon=hud_flags.show_weapon,
                    show_xp=hud_flags.show_xp,
                    show_time=hud_flags.show_time,
                    show_quest_hud=hud_flags.show_quest_hud,
                    small_indicators=self._hud_small_indicators(),
                ),
                player=self.player,
                players=self.sim_world.players,
                bonus_hud=self.state.bonus_hud,
                elapsed_ms=self._session_elapsed_ms(),
                frame_dt_ms=self._last_dt_ms,
            )

        if debug_enabled() and (not self._game_over_active):
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            self._draw_ui_text(
                f"rush: t={self._session_elapsed_ms() / 1000.0:6.1f}s",
                Vec2(x, y),
                UI_TEXT_COLOR,
            )
            self._draw_ui_text(f"kills={self.creatures.kill_count}", Vec2(x, y + line), UI_HINT_COLOR)
            y_extra = y + line * 2.0
            if self._paused:
                self._draw_ui_text("paused (TAB)", Vec2(x, y_extra), UI_HINT_COLOR)
                y_extra += line
            if self.player.health <= 0.0:
                self._draw_ui_text("game over", Vec2(x, y_extra), UI_ERROR_COLOR)
                y_extra += line
            self._draw_lan_debug_info(x=x, y=y_extra, line_h=line)

        if self._game_over_active:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    resources=self.render_resources.resources,
                    mouse=self._ui_mouse_pos(),
                )
        self._draw_lan_wait_overlay()
