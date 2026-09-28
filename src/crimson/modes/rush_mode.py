from __future__ import annotations

from crimson.screens.actions import Route
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..input_codes import PadCode, pad_nav_pressed
from ..replay import Replay, ReplayRecorder
from ..ui.hud import HudRenderContext, draw_hud_overlay
from .base_gameplay_mode import (
    BaseGameplayMode,
)

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
            default_game_mode_id=GameMode.RUSH,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._replay_recorder: ReplayRecorder | None = None

    def open(self) -> None:
        super().open()
        self._reset_gameplay_frame_clock()
        prepared = self._initialize_run(GameMode.RUSH)
        self._sim_session = prepared.session

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

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.START):
            self._action = Route.PAUSE
            return

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return self._session_elapsed_ms()

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        kills = int(self.creatures.kill_count)
        return f"rush_{stamp}_kills{kills}"

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
            self._finish_run_if_over()
            return
        if session is None:
            return

        self._run_deterministic_session_ticks(
            dt_frame=float(sim_dt),
            session=session,
            recorder=self._replay_recorder,
        )


    def draw(self) -> None:
        entity_alpha = self._world_entity_alpha()
        self._draw_world(entity_alpha=entity_alpha)
        self._draw_screen_fade()
        self._draw_aim_indicators(show_aim=not self._game_over_active, entity_alpha=entity_alpha)

        hud_bottom = 0.0
        if not self._game_over_active:
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    resources=self.render_resources.resources,
                    state=self._hud_state,
                    font=self._small,
                    game_mode=self._config_game_mode_id(),
                    small_indicators=self._hud_small_indicators(),
                ),
                player=self.player,
                players=self.world.players,
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
