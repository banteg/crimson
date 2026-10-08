from __future__ import annotations

from crimson.screens.actions import Route
from grim.audio import AudioState
from grim.config import (
    CrimsonConfig,
)
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl, rl_color
from grim.sfx_map import SfxId
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..gameplay import survival_check_level_up
from ..input_codes import PadCode, pad_nav_pressed
from ..perks.selection import perk_selection_prepared_choices
from ..replay import ReplayRecorder
from ..sim.mode_updates import SurvivalSpawnState
from ..sim.sessions import DeterministicSessionTick
from ..weapon_runtime import weapon_assign_player
from ..weapons import WEAPON_BY_ID, WeaponId
from .base_gameplay_mode import (
    BaseGameplayMode,
)

UI_TEXT_COLOR = rl_color(220, 220, 220, 255)
UI_HINT_COLOR = rl_color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl_color(255, 255, 255, int(255 * 0.5))
UI_ERROR_COLOR = rl_color(240, 80, 80, 255)

_DEBUG_WEAPON_IDS = tuple(sorted(WEAPON_BY_ID))


class SurvivalMode(BaseGameplayMode):
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
            default_game_mode_id=GameMode.SURVIVAL,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._cursor_time = 0.0
        self._replay_recorder: ReplayRecorder | None = None
        self._spawn_state = SurvivalSpawnState()

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return self._session_elapsed_ms()


    def open(self) -> None:
        super().open()

        self._cursor_time = 0.0
        self._reset_gameplay_frame_clock()
        prepared = self._initialize_run(GameMode.SURVIVAL)
        spawn_state = prepared.session.mode_state
        assert isinstance(spawn_state, SurvivalSpawnState)
        self._spawn_state = spawn_state

    def close(self) -> None:
        self._world_runtime.end_session()
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = Route.MENU
                self.close_requested = True
            return
        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self._debug_cheat_used()
                self.state.debug_god_mode = not bool(self.state.debug_god_mode)
                self.audio_bridge.play_sfx(SfxId.UI_BUTTONCLICK)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self._debug_cheat_used()
                self.state.perk_selection.pending_count += 1
                self.state.perk_selection.choices_dirty = True
                self.audio_bridge.play_sfx(SfxId.UI_LEVELUP)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
                self._debug_cheat_used()
                self._debug_cycle_weapon(-1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
                self._debug_cheat_used()
                self._debug_cycle_weapon(1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_X):
                self._debug_cheat_used()
                self.player.experience += 5000
                survival_check_level_up(self.state, self.player)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.START):
            self._request_pause()
            return

    def _debug_cycle_weapon(self, delta: int) -> None:
        weapon_ids = _DEBUG_WEAPON_IDS
        if not weapon_ids:
            return
        current = self.player.weapon.weapon_id
        try:
            idx = weapon_ids.index(current)
        except ValueError:
            idx = 0
        weapon_id = WeaponId(weapon_ids[(idx + int(delta)) % len(weapon_ids)])
        weapon_assign_player(self.player, weapon_id, state=self.state)

    def _enter_game_over(self) -> None:
        self._perk_menu.close()
        super()._enter_game_over()

    def _on_tick_applied(self, tick: DeterministicSessionTick) -> bool:
        if self._perk_menu.active:
            return False
        return super()._on_tick_applied(tick)

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return

        self._cursor_time += float(frame.dt)
        if self._game_over_active:
            self._update_game_over_ui(float(frame.dt))
            return

        self._update_perk_ui(dt_ui_ms=float(frame.dt_ui_ms))

        perk_menu_active = self._perk_menu.active
        sim_dt = float(frame.dt) if ((not self._paused) and (not perk_menu_active)) else 0.0
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
        perk_menu_active = self._perk_menu.active
        entity_alpha = self._world_entity_alpha()
        self._draw_world(entity_alpha=entity_alpha)
        self._draw_screen_fade()
        # Native order: perk prompt, aim indicators, then the HUD over both.
        if not self._game_over_active:
            self._draw_perk_prompt()
        self._draw_aim_indicators(
            show_aim=(not self._game_over_active) and (not perk_menu_active),
            entity_alpha=entity_alpha,
        )

        hud_bottom = 0.0
        if (not self._game_over_active) and (not perk_menu_active):
            self._draw_target_health_bar(alpha=self._hud_alpha())
            hud_bottom = self._draw_hud(elapsed_ms=self._session_elapsed_ms())

        if debug_enabled() and (not self._game_over_active) and (not perk_menu_active):
            # Minimal debug text.
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            elapsed_ms = self._session_elapsed_ms()
            self._draw_ui_text(
                f"survival: t={elapsed_ms / 1000.0:6.1f}s  stage={int(self._spawn_state.stage)}",
                Vec2(x, y),
                UI_TEXT_COLOR,
            )
            self._draw_ui_text(
                f"xp={self.player.experience}  level={self.player.level}  kills={self.creatures.kill_count}",
                Vec2(x, y + line),
                UI_HINT_COLOR,
            )
            god = "on" if self.state.debug_god_mode else "off"
            self._draw_ui_text(
                f"debug: [/] weapon  F3 perk+1  F2 god={god}  X xp+5000",
                Vec2(x, y + line * 2.0),
                UI_HINT_COLOR,
            )
            y_extra = y + line * 3.0
            if self.player.health <= 0.0:
                self._draw_ui_text("game over", Vec2(x, y_extra), UI_ERROR_COLOR)
                y_extra += line
        if not self._game_over_active:
            self._perk_menu.draw(
                self._perk_menu_ui_context(),
                perk_selection_prepared_choices(self.state),
            )
        if not self._game_over_active:
            self._draw_keybind_help()
        if (not self._game_over_active) and perk_menu_active:
            self._draw_game_cursor()

        if self._game_over_active and self._game_over_record is not None:
            self._game_over_ui.draw(
                record=self._game_over_record,
                banner_kind=self._game_over_banner,
                resources=self.render_resources.resources,
                mouse=self._ui_mouse_pos(),
            )
