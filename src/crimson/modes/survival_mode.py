from __future__ import annotations

from crimson.screens.actions import Route
from grim.assets import TextureId
from grim.audio import AudioState
from grim.config import (
    CrimsonConfig,
)
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.math import clamp
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..gameplay import survival_check_level_up
from ..perks.selection import perk_selection_prepared_choices
from ..persistence.save_status import GameStatusData
from ..replay import Replay, ReplayHeader, ReplayRecorder
from ..replay.checkpoints import DEFAULT_CHECKPOINT_SAMPLE_RATE
from ..sim.bootstrap import advance_unlock_terrain
from ..sim.session_builders import build_survival_session
from ..sim.sessions import DeterministicSession, DeterministicSessionTick, SurvivalSpawnState
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import PERK_MENU_TRANSITION_MS
from ..weapon_runtime import weapon_assign_player
from ..weapons import WEAPON_BY_ID, WeaponId
from .base_gameplay_mode import (
    BaseGameplayMode,
)
from .components.highscore_record_builder import build_highscore_record_for_game_over
from .components.perk_menu_controller import PerkMenuController
from .components.perk_prompt_controller import PerkPromptState

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

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
            world_size=WORLD_SIZE,
            default_game_mode_id=GameMode.SURVIVAL,
            demo_mode_active=False,
            quest_fail_retry_count=0,
            hardcore=False,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._perk_prompt = PerkPromptState()
        self._perk_menu = PerkMenuController(runtime=self._perk_menu_runtime())
        self._hud_fade_ms = PERK_MENU_TRANSITION_MS
        self._cursor_time = 0.0
        self._replay_recorder: ReplayRecorder | None = None
        self._spawn_state = SurvivalSpawnState()
        self._sim_session: DeterministicSession | None = self._new_sim_session()

    def _new_sim_session(self) -> DeterministicSession:
        session, spawn_state = build_survival_session(
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

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return self._session_elapsed_ms()

    def _replay_claimed_stats_complete(self) -> bool:
        return bool(self._game_over_active)

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        return int(self._session_elapsed_ms())

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        score = int(self.player.experience)
        return f"survival_{stamp}_score{score}"

    def _try_open_perk_menu(self) -> None:
        self._open_perk_menu_ui(
            menu=self._perk_menu,
            players=self.sim_world.players,
            game_mode=GameMode.SURVIVAL,
            player_count=max(1, len(self.sim_world.players)),
        )

    def _perk_menu_closed(self) -> None:
        self._perk_prompt.reset_if_pending(pending_count=int(self.state.perk_selection.pending_count))

    def _update_perk_ui(
        self,
        *,
        dt_ui_ms: float,
        allow_input: bool = True,
        allow_pulse: bool = True,
    ) -> None:
        perk_ctx = self._perk_menu_ui_context()
        pending_count = int(self.state.perk_selection.pending_count)
        any_alive = self._any_player_alive()
        choices = perk_selection_prepared_choices(self.sim_world.players, self.state.perk_selection)
        self._perk_prompt.begin_frame()
        if self._perk_menu.open and allow_input:
            choice_index = self._perk_menu.handle_input(
                perk_ctx,
                choices,
                dt_ui_ms=float(dt_ui_ms),
            )
            if choice_index is not None:
                self.record_perk_pick_command(int(choice_index), player_index=0)
        if allow_input and self._perk_prompt.poll_open_request(
            ctx=perk_ctx,
            config=self.config,
            pending_count=pending_count,
            player_count=max(1, len(self.sim_world.players)),
            any_alive=any_alive,
            paused=self._paused,
            menu_active=self._perk_menu.active,
            prompt_scale=UI_TEXT_SCALE,
        ):
            self._try_open_perk_menu()
        self._perk_prompt.tick_timer(
            pending_count=pending_count,
            any_alive=any_alive,
            paused=self._paused,
            menu_active=self._perk_menu.active,
            dt_ui_ms=float(dt_ui_ms),
        )
        if allow_pulse:
            self._perk_prompt.tick_pulse(float(dt_ui_ms))
        self._perk_menu.tick_timeline(float(dt_ui_ms))

    def _wrap_ui_text(self, text: str, *, max_width: float, scale: float = UI_TEXT_SCALE) -> list[str]:
        lines: list[str] = []
        for raw in text.splitlines() or [""]:
            para = raw.strip()
            if not para:
                lines.append("")
                continue
            current = ""
            for word in para.split():
                candidate = word if not current else f"{current} {word}"
                if current and self._ui_text_width(candidate, scale) > max_width:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
        return lines

    def open(self) -> None:
        super().open()

        self._perk_prompt.reset()
        self._perk_menu.reset()
        self._cursor_time = 0.0
        self._cursor_pulse_time = 0.0
        self._reset_gameplay_frame_clock()

        status = self.state.status
        quest_unlock_index = int(status.quest_unlock_index) if status is not None else 0
        terrain = advance_unlock_terrain(
            self.state.rng,
            unlock_index=int(quest_unlock_index),
            width=int(self.world_size),
            height=int(self.world_size),
        )
        self.apply_terrain_setup(terrain_slots=terrain.terrain_slots, seed=terrain.terrain_seed)
        self.sim_world.state.rng.srand(int(self.state.rng.state))

        self._sim_session = self._new_sim_session()

        self._hud_fade_ms = PERK_MENU_TRANSITION_MS
        replay_status = GameStatusData() if status is None else status.as_data()
        self._replay_recorder = ReplayRecorder(
            ReplayHeader(
                game_mode_id=GameMode.SURVIVAL,
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
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def close(self) -> None:
        self._sim_session = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = Route.MENU
                self.close_requested = True
            return
        if self._perk_menu.open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.audio_bridge.router.play_sfx(SfxId.UI_BUTTONCLICK)
            self._perk_menu.close()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self.state.debug_god_mode = not bool(self.state.debug_god_mode)
                self.audio_bridge.router.play_sfx(SfxId.UI_BUTTONCLICK)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self.state.perk_selection.pending_count += 1
                self.state.perk_selection.choices_dirty = True
                self.audio_bridge.router.play_sfx(SfxId.UI_LEVELUP)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
                self._debug_cycle_weapon(-1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
                self._debug_cycle_weapon(1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_X):
                self.player.experience += 5000
                survival_check_level_up(self.player, self.state.perk_selection)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = Route.PAUSE
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

    def _death_transition_ready(self) -> bool:
        dead_players = 0
        for player in self.sim_world.players:
            if float(player.health) > 0.0:
                return False
            dead_players += 1
            if float(player.death_timer) >= 0.0:
                return False
        return dead_players > 0

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
        self._perk_menu.close()
        self._save_replay()

    def _on_tick_applied(
        self,
        tick: DeterministicSessionTick,
        dt_tick: float,
    ) -> bool:
        _ = tick, dt_tick

        if self._perk_menu.active:
            return False

        if self._death_transition_ready():
            self._enter_game_over()
            return False
        return True

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return

        self._cursor_time += float(frame.dt)
        if self._game_over_active:
            self._update_game_over_ui(float(frame.dt))
            return

        self._update_perk_ui(
            dt_ui_ms=float(frame.dt_ui_ms),
            allow_pulse=(not self._paused) and (not self._game_over_active),
        )
        if self._perk_menu.active:
            self._hud_fade_ms = 0.0
        else:
            self._hud_fade_ms = clamp(self._hud_fade_ms + float(frame.dt_ui_ms), 0.0, PERK_MENU_TRANSITION_MS)

        perk_menu_active = self._perk_menu.active
        sim_dt = float(frame.dt) if ((not self._paused) and (not perk_menu_active)) else 0.0
        session = self._sim_session
        if sim_dt <= 0.0:
            self._reset_gameplay_frame_clock()
            if self._death_transition_ready():
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
        perk_menu_active = self._perk_menu.active
        self._draw_world(
            draw_aim_indicators=(not self._game_over_active) and (not perk_menu_active),
            entity_alpha=self._world_entity_alpha(),
        )
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not self._game_over_active) and (not perk_menu_active):
            hud_alpha = clamp(self._hud_fade_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar(alpha=hud_alpha)
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    resources=self.render_resources.resources,
                    state=self._hud_state,
                    font=self._small,
                    alpha=hud_alpha,
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
                score=self.player.experience,
                frame_dt_ms=self._last_dt_ms,
            )

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
                scale=0.9,
            )
            y_extra = y + line * 3.0
            if self._paused:
                self._draw_ui_text("paused (TAB)", Vec2(x, y_extra), UI_HINT_COLOR)
                y_extra += line
            if self.player.health <= 0.0:
                self._draw_ui_text("game over", Vec2(x, y_extra), UI_ERROR_COLOR)
                y_extra += line
        if not self._game_over_active:
            self._perk_prompt.draw(
                ctx=self._perk_menu_ui_context(),
                pending_count=int(self.state.perk_selection.pending_count),
                any_alive=self._any_player_alive(),
                menu_active=self._perk_menu.active,
                config=self.config,
                ui_text_width=self._ui_text_width,
                text_color=UI_TEXT_COLOR,
                prompt_scale=UI_TEXT_SCALE,
            )
            self._perk_menu.draw(
                self._perk_menu_ui_context(),
                perk_selection_prepared_choices(self.sim_world.players, self.state.perk_selection),
            )
        if (not self._game_over_active) and perk_menu_active:
            self._draw_game_cursor()

        if self._game_over_active and self._game_over_record is not None:
            self._game_over_ui.draw(
                record=self._game_over_record,
                banner_kind=self._game_over_banner,
                resources=self.render_resources.resources,
                mouse=self._ui_mouse_pos(),
            )
