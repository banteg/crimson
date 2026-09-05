from __future__ import annotations

from crimson.screens.actions import Route
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
from ..replay import Replay, ReplayRecorder
from ..sim.sessions import (
    DeterministicSession,
    DeterministicSessionTick,
    RushSessionRuntime,
    RushSpawnState,
)
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from .base_gameplay_mode import (
    BaseGameplayMode,
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
        self._sim_session: DeterministicSession | None = None

    def open(self) -> None:
        super().open()
        self._reset_gameplay_frame_clock()
        prepared = self._initialize_run(GameMode.RUSH)
        self._sim_session = prepared.session
        mode_runtime = prepared.session.mode_runtime
        assert isinstance(mode_runtime, RushSessionRuntime)
        self._spawn_state = mode_runtime.spawn

    def close(self) -> None:
        self._sim_session = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = Route.MENU
                self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = Route.PAUSE
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

    def _on_tick_applied(
        self,
        tick: DeterministicSessionTick,
        dt_tick: float,
    ) -> bool:
        _ = tick, dt_tick
        if not self._any_player_alive():
            self._enter_game_over()
            return False
        return True

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return

        if self._game_over_active:
            self._update_game_over_ui(float(frame.dt))
            return

        any_alive = self._any_player_alive()
        sim_dt = float(frame.dt) if ((not self._paused) and any_alive) else 0.0
        session = self._sim_session

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

        if self._game_over_active:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    resources=self.render_resources.resources,
                    mouse=self._ui_mouse_pos(),
                )
