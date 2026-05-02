from __future__ import annotations

from grim.assets import TextureId
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.math import clamp
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..input_codes import input_code_is_down, input_code_is_pressed
from ..perks.selection import perk_selection_prepared_choices
from ..persistence.save_status import GameStatusData
from ..replay import ReplayHeader, ReplayRecorder
from ..replay.checkpoints import DEFAULT_CHECKPOINT_SAMPLE_RATE
from ..sim.bootstrap import advance_unlock_terrain
from ..sim.input import PlayerInput
from ..sim.session_builders import build_tutorial_session
from ..sim.sessions import DeterministicSession
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from ..ui.overlays.tutorial_run import (
    TUTORIAL_PANEL_POS,
    draw_tutorial_overlay_panels,
    tutorial_prompt_panel_rect,
)
from ..ui.perk_menu import (
    UiButtonState,
    button_draw,
    button_update,
    button_width,
)
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from .base_gameplay_mode import BaseGameplayMode
from .components.perk_menu_controller import PerkMenuController

UI_HINT_COLOR = rl.Color(140, 140, 140, 255)


class TutorialMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        demo_mode_active: bool = False,
        config: CrimsonConfig,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand,
    ) -> None:
        super().__init__(
            ctx,
            world_size=1024.0,
            default_game_mode_id=GameMode.TUTORIAL,
            demo_mode_active=bool(demo_mode_active),
            quest_fail_retry_count=0,
            hardcore=False,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._perk_menu = PerkMenuController()

        self._skip_button = UiButtonState("Skip tutorial", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._repeat_button = UiButtonState("Repeat tutorial", force_wide=True)
        self._sim_session: DeterministicSession | None = None
        self._replay_recorder: ReplayRecorder | None = None
        self._frame_input_state: PlayerInput | None = None
        self._perk_pick_pending = False

    def _new_sim_session(self) -> DeterministicSession:
        return build_tutorial_session(
            world=self.sim_world.world_state,
            world_size=float(self.world_size),
            damage_scale_by_type=self.sim_world.damage_scale_by_type,
            detail_preset=int(self._deterministic_detail_preset()),
            violence_disabled=int(self._deterministic_violence_disabled()),
            game_tune_started=bool(self.sim_world.game_tune_started),
            demo_mode_active=bool(self.demo_mode_active),
        )

    def _runtime_player_count(self) -> int:
        return 1

    def open(self) -> None:
        super().open()
        self._perk_menu.reset()

        self._skip_button = UiButtonState("Skip tutorial", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._repeat_button = UiButtonState("Repeat tutorial", force_wide=True)

        self._frame_input_state = None
        self._perk_pick_pending = False

        self.state.perk_selection.pending_count = 0
        self.state.perk_selection.choices.clear()
        self.state.perk_selection.choices_dirty = True

        status = self.state.status
        terrain = advance_unlock_terrain(
            self.state.rng,
            unlock_index=(0 if status is None else int(status.quest_unlock_index)),
            width=int(self.world_size),
            height=int(self.world_size),
        )
        self.apply_terrain_setup(
            terrain_slots=terrain.terrain_slots,
            seed=int(terrain.terrain_seed),
        )
        self.sim_world.state.rng.srand(int(self.state.rng.state))

        self.player.pos = Vec2(float(self.world_size) * 0.5, float(self.world_size) * 0.5)
        weapon_assign_player(self.player, WeaponId.PISTOL, state=self.state)
        self._sim_session = self._new_sim_session()
        self._replay_recorder = ReplayRecorder(
            ReplayHeader(
                game_mode_id=GameMode.TUTORIAL,
                seed=int(self._run_reset_seed),
                tick_rate=int(self._gameplay_tick_rate()),
                quest_fail_retry_count=int(self.quest_fail_retry_count),
                hardcore=bool(self.hardcore),
                preserve_bugs=bool(self.state.preserve_bugs),
                detail_preset=int(self._deterministic_detail_preset()),
                violence_disabled=int(self._deterministic_violence_disabled()),
                world_size=float(self.world_size),
                player_count=1,
                status=GameStatusData() if status is None else status.as_data(),
            ),
        )
        self._replay_checkpoints_sample_rate = int(DEFAULT_CHECKPOINT_SAMPLE_RATE)
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def close(self) -> None:
        self._sim_session = None
        self._replay_recorder = None
        self._frame_input_state = None
        super().close()

    def _replay_claimed_stats_complete(self) -> bool:
        return int(self.state.tutorial.stage_index) >= 8

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        session = self._sim_session
        if session is None:
            return 0
        return int(session.elapsed_ms)

    def _replay_output_basename(self, *, stamp: str, replay) -> str:
        _ = replay
        return f"tutorial_{stamp}"

    def _open_perk_menu(self) -> None:
        self._open_perk_menu_ui(
            menu=self._perk_menu,
            players=[self.player],
            game_mode=GameMode.TUTORIAL,
            player_count=1,
        )

    def _handle_input(self) -> None:
        if self._perk_menu.open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._perk_menu.close()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
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
                measure_text_width=lambda text, scale: float(self._ui_text_width(text, scale)),
                measure_line_height=self._ui_line_height,
                pos=TUTORIAL_PANEL_POS,
                scale=1.0,
            )
            gap = 18.0
            button_base_pos = Vec2(rect.x + 10.0, rect.y + rect.height + 10.0)
            play_w = button_width(resources, self._play_button.label, scale=1.0, force_wide=True)
            repeat_w = button_width(resources, self._repeat_button.label, scale=1.0, force_wide=True)
            if button_update(
                self._play_button,
                pos=button_base_pos,
                width=play_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._finish_tutorial_run(restart=False)
                return
            if button_update(
                self._repeat_button,
                pos=button_base_pos.offset(dx=play_w + gap),
                width=repeat_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._finish_tutorial_run(restart=True)
                return
            return

        if self._skip_button.enabled:
            resources = self.render_resources.resources
            y = float(rl.get_screen_height()) - 50.0
            w = button_width(resources, self._skip_button.label, scale=1.0, force_wide=True)
            if button_update(self._skip_button, pos=Vec2(10.0, y), width=w, dt_ms=dt_ms, mouse=mouse, click=click):
                self._finish_tutorial_run(restart=False)

    def update(self, dt: float) -> None:
        self._update_audio(dt)
        dt, dt_ui_ms = self._tick_frame(dt, clamp_cursor_pulse=True)

        self._handle_input()
        if self._action == "open_pause_menu":
            return
        if self.close_requested:
            return

        perk_pending = int(self.state.perk_selection.pending_count) > 0 and self.player.health > 0.0
        choices = perk_selection_prepared_choices(self.sim_world.players, self.state.perk_selection)
        if int(self.state.tutorial.stage_index) == 6 and perk_pending and (not self._perk_menu.active) and (
            not self._perk_pick_pending
        ):
            self._open_perk_menu()
        if self._perk_menu.open:
            choice_index = self._perk_menu.handle_input(
                self._perk_menu_ui_context(),
                choices,
                dt_ui_ms=dt_ui_ms,
            )
            if choice_index is not None:
                self._perk_pick_pending = True
                self.record_perk_pick_command(int(choice_index), player_index=0)
        self._perk_menu.tick_timeline(dt_ui_ms)

        perk_menu_active = self._perk_menu.active

        dt_world = 0.0 if self._paused or perk_menu_active else dt

        input_state = self._build_input()
        if dt_world > 0.0:
            session = self._sim_session
            if session is not None:
                elapsed_before_ms = float(session.elapsed_ms)
                session.detail_preset = int(self._deterministic_detail_preset())
                session.violence_disabled = int(self._deterministic_violence_disabled())
                self._frame_input_state = input_state
                try:
                    self._run_deterministic_session_ticks(
                        dt_frame=float(dt_world),
                        session=session,
                        recorder=self._replay_recorder,
                    )
                finally:
                    self._frame_input_state = None
                if float(session.elapsed_ms) != elapsed_before_ms:
                    self._perk_pick_pending = False

        mouse = self._ui_mouse_pos()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_prompt_buttons(dt_ms=dt_ui_ms, mouse=mouse, click=click)

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        self._draw_world(
            draw_aim_indicators=not perk_menu_active,
            entity_alpha=self._world_entity_alpha(),
        )
        self._draw_screen_fade()

        hud_bottom = 0.0
        if not perk_menu_active:
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    resources=self.render_resources.resources,
                    state=self._hud_state,
                    font=self._small,
                    alpha=1.0,
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
                elapsed_ms=float(self._session_elapsed_ms() if self._sim_session is not None else 0.0),
                score=int(self.player.experience),
                frame_dt_ms=self._last_dt_ms,
            )

        self._draw_tutorial_prompts(hud_bottom=hud_bottom)

        if perk_menu_active:
            self._perk_menu.draw(
                self._perk_menu_ui_context(),
                perk_selection_prepared_choices(self.sim_world.players, self.state.perk_selection),
            )
            self._draw_menu_cursor()

    def _draw_tutorial_prompts(self, *, hud_bottom: float) -> None:
        overlay = self.state.tutorial_overlay
        draw_tutorial_overlay_panels(
            overlay,
            draw_text=lambda text, pos, color, scale: self._draw_ui_text(text, pos, color, scale=scale),
            measure_text_width=lambda text, scale: float(self._ui_text_width(text, scale)),
            measure_line_height=self._ui_line_height,
        )
        resources = self.render_resources.resources
        font = self._small
        assert font is not None, "tutorial prompts require loaded small font"

        stage = int(self.state.tutorial.stage_index)
        if stage == 8:
            rect, _lines, _line_h = tutorial_prompt_panel_rect(
                overlay.prompt_text,
                measure_text_width=lambda text, scale: float(self._ui_text_width(text, scale)),
                measure_line_height=self._ui_line_height,
                pos=TUTORIAL_PANEL_POS,
                scale=1.0,
            )
            gap = 18.0
            button_base_pos = Vec2(rect.x + 10.0, rect.y + rect.height + 10.0)
            play_w = button_width(resources, self._play_button.label, scale=1.0, force_wide=True)
            repeat_w = button_width(resources, self._repeat_button.label, scale=1.0, force_wide=True)
            button_draw(
                resources,
                self._play_button,
                pos=button_base_pos,
                width=play_w,
                scale=1.0,
            )
            button_draw(
                resources,
                self._repeat_button,
                pos=button_base_pos.offset(dx=play_w + gap),
                width=repeat_w,
                scale=1.0,
            )
            return

        if self._skip_button.alpha > 1e-3:
            y = float(rl.get_screen_height()) - 50.0
            w = button_width(resources, self._skip_button.label, scale=1.0, force_wide=True)
            button_draw(resources, self._skip_button, pos=Vec2(10.0, y), width=w, scale=1.0)

        if self._paused:
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            self._draw_ui_text("paused (TAB)", Vec2(x, y), UI_HINT_COLOR)

    def _draw_menu_cursor(self) -> None:
        resources = self.render_resources.resources
        mouse_pos = self._ui_mouse
        draw_menu_cursor(
            resources.texture(TextureId.PARTICLES),
            resources.texture(TextureId.UI_CURSOR),
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )
