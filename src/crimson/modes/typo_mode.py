from __future__ import annotations

from crimson.screens.actions import Route
from grim.assets import TextureId
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..persistence.highscores import scores_path_for_mode
from ..replay import Replay
from ..sim.commands import TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from ..sim.input import PlayerInput
from ..sim.sessions import DeterministicSession
from ..typo.names import load_typo_dictionary, load_typo_highscore_names
from ..typo.player import build_typo_player_input
from ..ui.hud import HudRenderContext, draw_hud_overlay
from ..ui.overlays.typo_run import draw_typing_box, draw_typo_name_labels
from .base_gameplay_mode import BaseGameplayMode


class TypoShooterMode(BaseGameplayMode):
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
            default_game_mode_id=GameMode.TYPO,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._sim_session: DeterministicSession | None = None
        # Native `game_time_s`, which blinks the typing caret.
        self._game_time_s = 0.0

    def open(self) -> None:
        super().open()
        dictionary_path = self._base_dir / "typo_dictionary.txt"
        dictionary_words: tuple[str, ...] = ()
        if dictionary_path.is_file():
            dictionary_words = tuple(load_typo_dictionary(dictionary_path))
        highscore_names = tuple(load_typo_highscore_names(scores_path_for_mode(self._base_dir, GameMode.TYPO)))

        prepared = self._initialize_run(GameMode.TYPO, dictionary_words=dictionary_words, highscore_names=highscore_names)
        self._sim_session = prepared.session

    def close(self) -> None:
        self._sim_session = None
        super().close()

    def _runtime_player_count(self) -> int:
        return 1

    def _build_local_inputs(self, *, dt: float) -> list[PlayerInput]:
        _ = dt
        return [
            build_typo_player_input(
                aim=self.screen_to_world(self._ui_mouse),
                fire_requested=False,
                reload_requested=False,
            ),
        ]

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

    def _enqueue_typing_commands(self) -> None:
        enter_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER)
        if enter_pressed and self.state.typo.typing.text:
            self.enqueue_input_command(TypoSubmitCommand(player_index=0))

        # Native processes at most one keychar per frame via `console_input_poll`.
        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE) or rl.is_key_pressed_repeat(rl.KeyboardKey.KEY_BACKSPACE):
            self.enqueue_input_command(TypoBackspaceCommand(player_index=0))
        else:
            codepoint = int(rl.get_char_pressed())
            if codepoint not in (13, 8) and 0x20 <= codepoint <= 0xFF:
                try:
                    ch = chr(codepoint)
                except ValueError:
                    ch = ""
                if ch:
                    self.enqueue_input_command(TypoCharCommand(player_index=0, ch=ch[0]))

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return self._session_elapsed_ms()

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        score = int(self.player.experience)
        return f"typo_{stamp}_score{score}"

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt = self._tick_frame(dt)[0]
        self._game_time_s += dt
        self._handle_input()
        if self._action == Route.PAUSE:
            return

        if self._game_over_active:
            self._update_game_over_ui(dt)
            return

        dt_world = 0.0 if self._paused else dt

        # Native: delay game-over transition until the trooper death animation finishes
        # (checks `death_timer < 0.0` in the main gameplay loop).
        if self.player.health <= 0.0:
            if dt_world > 0.0:
                self.player.death_timer -= float(dt_world) * 20.0
            if self.player.death_timer < 0.0:
                self._enter_game_over()
                self._update_game_over_ui(dt)
                return
            return

        if dt_world > 0.0:
            self._enqueue_typing_commands()

        if dt_world <= 0.0:
            return

        session = self._sim_session
        if session is None:
            return

        self._run_deterministic_session_ticks(
            dt_frame=float(dt_world),
            session=session,
            recorder=self._replay_recorder,
        )
        # Death/game-over flow is handled at the start of the next frame so the
        # trooper death animation can play before the UI slides in.


    def _draw_name_labels(self) -> None:
        draw_typo_name_labels(
            creatures=self.creatures.entries,
            names=self.state.typo.names.names,
            world_to_screen=self.world_to_screen,
            draw_text=self._draw_ui_text,
            measure_text_width=self._ui_text_width,
        )

    def _draw_typing_box(self) -> None:
        draw_typing_box(
            self.render_resources.resources.texture(TextureId.UI_IND_PANEL),
            text=self.state.typo.typing.text,
            game_time_s=self._game_time_s,
            draw_text=self._draw_ui_text,
            measure_text_width=self._ui_text_width,
        )

    def draw(self) -> None:
        alive = self.player.health > 0.0
        show_gameplay_ui = alive and (not self._game_over_active)

        self._draw_world(entity_alpha=self._world_entity_alpha())
        self._draw_screen_fade()
        # Native `typo_gameplay_update_and_render` draws the name labels right after
        # the world, living player or not, and never calls `ui_render_aim_indicators`.
        if not self._game_over_active:
            self._draw_name_labels()

        if show_gameplay_ui:
            self._draw_target_health_bar()
            draw_hud_overlay(
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
                elapsed_ms=float(self._session_elapsed_ms()),
                frame_dt_ms=self._last_dt_ms,
            )

        if show_gameplay_ui:
            self._draw_typing_box()

        if self._game_over_active:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    resources=self.render_resources.resources,
                    mouse=self._ui_mouse_pos(),
                )
