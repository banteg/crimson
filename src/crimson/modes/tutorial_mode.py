from __future__ import annotations

from crimson.screens.actions import Route
from grim import canvas
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.math import clamp
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..input_codes import PadCode, input_code_is_down, input_code_is_pressed, pad_nav_pressed
from ..perks.selection import perk_selection_prepared_choices
from ..replay import ReplayRecorder
from ..sim.input import PlayerInput
from ..sim.sessions import DeterministicSession
from ..ui.hud import HudRenderContext, draw_hud_overlay
from ..ui.overlays.tutorial_run import (
    TUTORIAL_PANEL_POS,
    draw_tutorial_overlay_panels,
    tutorial_prompt_panel_rect,
)
from ..ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from .base_gameplay_mode import BaseGameplayMode

UI_HINT_COLOR = rl.Color(140, 140, 140, 255)


class TutorialMode(BaseGameplayMode):
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
            default_game_mode_id=GameMode.TUTORIAL,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )

        self._skip_button = UiButtonState("Skip tutorial", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._repeat_button = UiButtonState("Repeat tutorial", force_wide=True)
        self._sim_session: DeterministicSession | None = None
        self._replay_recorder: ReplayRecorder | None = None
        self._frame_input_state: PlayerInput | None = None

    def _runtime_player_count(self) -> int:
        return 1

    def open(self) -> None:
        super().open()

        self._skip_button = UiButtonState("Skip tutorial", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._repeat_button = UiButtonState("Repeat tutorial", force_wide=True)

        self._frame_input_state = None

        self.state.perk_selection.pending_count = 0
        self.state.perk_selection.choices.clear()
        self.state.perk_selection.choices_dirty = True

        prepared = self._initialize_run(GameMode.TUTORIAL)
        self._sim_session = prepared.session

    def close(self) -> None:
        self._sim_session = None
        self._replay_recorder = None
        self._frame_input_state = None
        super().close()

    def _replay_output_basename(self, *, stamp: str, replay) -> str:
        _ = replay
        return f"tutorial_{stamp}"

    def _handle_input(self) -> None:
        if self._perk_menu.open and (
            rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.FACE_RIGHT)
        ):
            self._perk_menu.close()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.START):
            self._request_pause()
            return

    def _build_input(self) -> PlayerInput:
        controls = self.config.controls.player(0)
        move_forward_key, move_backward_key, turn_left_key, turn_right_key = controls.move_codes
        fire_key = controls.fire_code

        move = Vec2(
            float(input_code_is_down(turn_right_key)) - float(input_code_is_down(turn_left_key)),
            float(input_code_is_down(move_backward_key)) - float(input_code_is_down(move_forward_key)),
        )

        mouse = self._ui_mouse_pos()
        aim = self.screen_to_world(Vec2.from_xy(mouse))

        fire_down = input_code_is_down(fire_key)
        fire_pressed = input_code_is_pressed(fire_key)
        reload_key = self.config.controls.reload_code
        reload_pressed = input_code_is_pressed(reload_key)

        return PlayerInput(
            move=move,
            aim=aim,
            fire_down=bool(fire_down),
            fire_pressed=bool(fire_pressed),
            reload_pressed=bool(reload_pressed),
        )

    def _build_local_inputs(self, *, dt: float) -> list[PlayerInput]:
        _ = dt
        frame_input_state = self._frame_input_state
        if frame_input_state is None:
            frame_input_state = self._build_input()
        return [frame_input_state]

    def _finish_tutorial_run(self, *, restart: bool) -> None:
        self._save_replay()
        if restart:
            self.open()
            return
        self.close_requested = True

    def _update_prompt_buttons(self, *, dt_ms: float, mouse: rl.Vector2, click: bool) -> None:
        tutorial = self.state.tutorial
        overlay = self.state.tutorial_overlay
        font = self._small
        assert font is not None, "tutorial buttons require loaded small font"
        stage = int(tutorial.stage_index)
        prompt_alpha = float(overlay.prompt_alpha)
        if stage == 8:
            self._play_button.alpha = prompt_alpha
            self._repeat_button.alpha = prompt_alpha
            self._play_button.enabled = prompt_alpha > 1e-3
            self._repeat_button.enabled = prompt_alpha > 1e-3
        else:
            skip_alpha = clamp(float(tutorial.stage_timer_ms - 1000) * 0.001, 0.0, 1.0)
            self._skip_button.alpha = skip_alpha
            self._skip_button.enabled = skip_alpha > 1e-3

        if stage == 8:
            resources = self.render_resources.resources
            rect, _lines, _line_h = tutorial_prompt_panel_rect(
                overlay.prompt_text,
                measure_text_width=self._ui_text_width,
                measure_line_height=self._ui_line_height,
                pos=TUTORIAL_PANEL_POS,
            )
            gap = 18.0
            button_base_pos = Vec2(rect.x + 10.0, rect.y + rect.height + 10.0)
            play_w = button_width(resources, self._play_button)
            if button_update(
                resources,
                self._play_button,
                pos=button_base_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._finish_tutorial_run(restart=False)
                return
            if button_update(
                resources,
                self._repeat_button,
                pos=button_base_pos.offset(dx=play_w + gap),
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._finish_tutorial_run(restart=True)
                return
            return

        if self._skip_button.enabled:
            resources = self.render_resources.resources
            y = float(canvas.height()) - 50.0
            if button_update(resources, self._skip_button, pos=Vec2(10.0, y), dt_ms=dt_ms, mouse=mouse, click=click):
                self._finish_tutorial_run(restart=False)

    def update(self, dt: float) -> None:
        self._update_audio(dt)
        dt, dt_ui_ms = self._tick_frame(dt)

        self._handle_input()
        if self._action == Route.PAUSE:
            return
        if self.close_requested:
            return

        self._update_perk_ui(dt_ui_ms=dt_ui_ms)

        perk_menu_active = self._perk_menu.active

        dt_world = 0.0 if self._paused or perk_menu_active else dt

        input_state = self._build_input()
        if dt_world > 0.0:
            session = self._sim_session
            if session is not None:
                self._frame_input_state = input_state
                try:
                    self._run_deterministic_session_ticks(
                        dt_frame=float(dt_world),
                        session=session,
                        recorder=self._replay_recorder,
                    )
                finally:
                    self._frame_input_state = None

        mouse = self._ui_mouse_pos()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_prompt_buttons(dt_ms=dt_ui_ms, mouse=mouse, click=click)

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        entity_alpha = self._world_entity_alpha()
        self._draw_world(entity_alpha=entity_alpha)
        self._draw_screen_fade()
        # Native order: perk prompt, aim indicators, then the HUD over both.
        self._draw_perk_prompt()
        self._draw_aim_indicators(show_aim=not perk_menu_active, entity_alpha=entity_alpha)

        if not perk_menu_active:
            self._draw_target_health_bar()
            draw_hud_overlay(
                HudRenderContext(
                    resources=self.render_resources.resources,
                    state=self._hud_state,
                    font=self._small,
                    alpha=self._hud_alpha(),
                    game_mode=self._config_game_mode_id(),
                    small_indicators=self._hud_small_indicators(),
                ),
                player=self.player,
                players=self.world.players,
                bonus_hud=self.state.bonus_hud,
                elapsed_ms=float(self._session_elapsed_ms() if self._sim_session is not None else 0.0),
                score=int(self.player.experience),
                frame_dt_ms=self._last_dt_ms,
            )

        self._draw_tutorial_prompts()

        self._perk_menu.draw(
            self._perk_menu_ui_context(),
            perk_selection_prepared_choices(self.state),
        )
        self._draw_keybind_help()
        if perk_menu_active:
            self._draw_game_cursor()

    def _draw_tutorial_prompts(self) -> None:
        overlay = self.state.tutorial_overlay
        draw_tutorial_overlay_panels(
            overlay,
            draw_text=self._draw_ui_text,
            measure_text_width=self._ui_text_width,
            measure_line_height=self._ui_line_height,
        )
        resources = self.render_resources.resources
        font = self._small
        assert font is not None, "tutorial prompts require loaded small font"

        stage = int(self.state.tutorial.stage_index)
        if stage == 8:
            rect, _lines, _line_h = tutorial_prompt_panel_rect(
                overlay.prompt_text,
                measure_text_width=self._ui_text_width,
                measure_line_height=self._ui_line_height,
                pos=TUTORIAL_PANEL_POS,
            )
            gap = 18.0
            button_base_pos = Vec2(rect.x + 10.0, rect.y + rect.height + 10.0)
            play_w = button_width(resources, self._play_button)
            button_draw(
                resources,
                self._play_button,
                pos=button_base_pos,
            )
            button_draw(
                resources,
                self._repeat_button,
                pos=button_base_pos.offset(dx=play_w + gap),
            )
            return

        if self._skip_button.alpha > 1e-3:
            y = float(canvas.height()) - 50.0
            button_draw(resources, self._skip_button, pos=Vec2(10.0, y))

