from __future__ import annotations

import webbrowser
from typing import cast

from crimson.quest_level import QuestLevel
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from grim.view import View

from ..debug import debug_enabled
from ..demo import DemoView
from ..demo_trial import demo_trial_overlay_info, tick_demo_trial_timers
from ..frontend.boot import BootView
from ..frontend.menu import MenuView, ensure_menu_ground
from ..frontend.panels.alien_zookeeper import AlienZooKeeperView
from ..frontend.panels.base import PanelMenuView
from ..frontend.panels.controls import ControlsMenuView
from ..frontend.panels.credits import CreditsView
from ..frontend.panels.databases import UnlockedPerksDatabaseView, UnlockedWeaponsDatabaseView
from ..frontend.panels.mods import ModsMenuView
from ..frontend.panels.network_lobby import NetworkLobbyPanelView
from ..frontend.panels.network_session import NetworkSessionPanelView
from ..frontend.panels.options import OptionsMenuView
from ..frontend.panels.play_game import PlayGameMenuView
from ..frontend.panels.stats import StatisticsMenuView
from ..frontend.pause_menu import PauseMenuView
from ..frontend.transitions import _update_screen_fade
from ..game_modes import GameMode
from ..input_codes import input_begin_frame
from ..net.debug_log import init_lan_debug_log, lan_debug_log, lan_debug_log_path
from ..render.rtx.mode import RtxRenderMode, cycle_rtx_render_mode
from ..ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayInfo, DemoTrialOverlayUi
from .high_scores_view import HighScoresView
from .mode_views import QuestGameView, RushGameView, SurvivalGameView, TutorialGameView, TypoShooterGameView
from .quest_views import EndNoteView, QuestFailedView, QuestResultsView, QuestsMenuView
from .types import FrontView, GameState, PauseBackground

_GAMMA_RAMP_SHADER: rl.Shader | None = None
_GAMMA_RAMP_SHADER_GAIN_LOC: int = -1
_GAMMA_RAMP_SHADER_TRIED = False

_GAMMA_RAMP_VS_330 = r"""
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;

out vec2 fragTexCoord;
out vec4 fragColor;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

_GAMMA_RAMP_FS_330 = r"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform float u_gamma_gain;

out vec4 finalColor;

void main() {
    vec4 texel = texture(texture0, fragTexCoord) * fragColor * colDiffuse;
    texel.rgb = clamp(texel.rgb * max(u_gamma_gain, 0.0), 0.0, 1.0);
    finalColor = texel;
}
"""


_GameplayView = QuestGameView | RushGameView | SurvivalGameView | TutorialGameView | TypoShooterGameView


def _get_gamma_ramp_shader() -> tuple[rl.Shader | None, int]:
    global _GAMMA_RAMP_SHADER, _GAMMA_RAMP_SHADER_GAIN_LOC, _GAMMA_RAMP_SHADER_TRIED
    if _GAMMA_RAMP_SHADER_TRIED:
        shader = _GAMMA_RAMP_SHADER
        if shader is None:
            return None, -1
        if int(shader.id) <= 0:
            return None, -1
        if _GAMMA_RAMP_SHADER_GAIN_LOC < 0:
            return None, -1
        return shader, _GAMMA_RAMP_SHADER_GAIN_LOC

    _GAMMA_RAMP_SHADER_TRIED = True
    try:
        shader = rl.load_shader_from_memory(_GAMMA_RAMP_VS_330, _GAMMA_RAMP_FS_330)
    except (RuntimeError, OSError, ValueError):
        _GAMMA_RAMP_SHADER = None
        _GAMMA_RAMP_SHADER_GAIN_LOC = -1
        return None, -1

    if int(shader.id) <= 0:
        _GAMMA_RAMP_SHADER = None
        _GAMMA_RAMP_SHADER_GAIN_LOC = -1
        return None, -1

    gain_loc = int(rl.get_shader_location(shader, "u_gamma_gain"))
    if gain_loc < 0:
        _GAMMA_RAMP_SHADER = None
        _GAMMA_RAMP_SHADER_GAIN_LOC = -1
        return None, -1

    _GAMMA_RAMP_SHADER = shader
    _GAMMA_RAMP_SHADER_GAIN_LOC = gain_loc
    return _GAMMA_RAMP_SHADER, _GAMMA_RAMP_SHADER_GAIN_LOC


def _set_gamma_ramp_gain(shader: rl.Shader, gain_loc: int, gain: float) -> None:
    rl.set_shader_value(
        shader,
        int(gain_loc),
        rl.ffi.new("float *", max(0.0, float(gain))),
        rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
    )


class GameLoopView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._boot = BootView(state)
        self._demo = DemoView(state)
        self._menu = MenuView(state)
        self._front_views: dict[str, FrontView] = {
            "open_play_game": PlayGameMenuView(state),
            "open_lan_session": NetworkSessionPanelView(state),
            "open_lan_lobby": NetworkLobbyPanelView(state),
            "open_quests": QuestsMenuView(state),
            "open_pause_menu": PauseMenuView(state),
            "start_quest": QuestGameView(state),
            "quest_results": QuestResultsView(state),
            "quest_failed": QuestFailedView(state),
            "end_note": EndNoteView(state),
            "open_high_scores": HighScoresView(state),
            "start_survival": SurvivalGameView(state),
            "start_rush": RushGameView(state),
            "start_typo": TypoShooterGameView(state),
            "start_tutorial": TutorialGameView(state),
            "open_options": OptionsMenuView(state),
            "open_controls": ControlsMenuView(state),
            "open_statistics": StatisticsMenuView(state),
            "open_weapon_database": UnlockedWeaponsDatabaseView(state),
            "open_perk_database": UnlockedPerksDatabaseView(state),
            "open_credits": CreditsView(state),
            "open_alien_zookeeper": AlienZooKeeperView(state),
            "open_mods": ModsMenuView(state),
            "open_other_games": PanelMenuView(
                state,
                title="Other games",
                body="This menu is out of scope for the rewrite.",
            ),
        }
        self._front_active: FrontView | None = None
        self._front_stack: list[FrontView] = []
        self._active: View = self._boot
        self._demo_trial_overlay = DemoTrialOverlayUi(state.assets_dir)
        self._demo_trial_info: DemoTrialOverlayInfo | None = None
        self._demo_active = False
        self._menu_active = False
        self._quit_after_demo = False
        self._screenshot_requested = False
        self._gameplay_views: frozenset[FrontView] = frozenset(
            {
                self._front_views["start_survival"],
                self._front_views["start_rush"],
                self._front_views["start_typo"],
                self._front_views["start_tutorial"],
                self._front_views["start_quest"],
            },
        )

    def _pending_session(self):
        return self.state.pending_network_session

    def _ensure_lan_debug_log_started(self) -> None:
        if lan_debug_log_path() is not None:
            return
        pending = self._pending_session()
        if pending is None:
            return
        cfg = pending.config
        if str(cfg.netcode_mode) == "lockstep":
            endpoint = cfg.lockstep_endpoint()
            host = str(endpoint.host)
            port = int(endpoint.port)
        else:
            endpoint = cfg.rollback_endpoint()
            host = str(endpoint.relay_host)
            port = int(endpoint.relay_port)
        from ..net.lockstep_protocol import current_build_id

        log_path = init_lan_debug_log(
            base_dir=self.state.base_dir,
            role=str(pending.role),
            mode=str(cfg.mode),
            build_id=str(current_build_id()),
            host=host,
            port=int(port),
            player_count=cfg.player_count,
            auto_start=bool(pending.auto_start),
            debug_enabled=debug_enabled(),
        )
        self.state.console.log.log(f"lan debug log: {log_path}")
        self.state.console.log.flush()
        print(f"[lan-debug] role={pending.role} log={log_path}")

    def open(self) -> None:
        rl.hide_cursor()
        self._boot.open()

    def should_close(self) -> bool:
        return self.state.quit_requested

    def _lan_ui_enabled(self) -> bool:
        cvar = self.state.console.cvars.get("cv_lanLockstepEnabled")
        if cvar is None:
            return True
        return bool(cvar.value_f)

    def _auto_lan_start_action(self) -> str | None:
        pending = self._pending_session()
        if pending is None:
            return None
        if (not pending.auto_start) or pending.started:
            return None
        self._ensure_lan_debug_log_started()
        mode = str(pending.config.mode)
        pending.started = True
        lan_debug_log(
            "auto_lan_start",
            role=str(pending.role),
            mode=mode,
            auto_start=bool(pending.auto_start),
            player_count=pending.config.player_count,
        )
        if mode == "rush":
            return "start_rush_lan"
        if mode == "quests":
            return "start_quest_lan"
        if mode == "survival":
            return "start_survival_lan"
        pending.error = f"Unsupported LAN mode: {mode}"
        self.state.network_last_error = pending.error
        lan_debug_log("auto_lan_start_error", error=str(pending.error))
        return "open_lan_session"

    def _resolve_lan_action(self, action: str) -> str | None:
        if action == "open_lan_session":
            if self._lan_ui_enabled():
                return action
            self.state.network_last_error = "LAN UI is disabled (set cv_lanLockstepEnabled 1 to enable)."
            lan_debug_log("lan_action_denied", action=action, reason=str(self.state.network_last_error))
            return "open_play_game"

        mode_by_action = {
            "start_survival_lan": ("survival", "open_lan_lobby", 1),
            "start_rush_lan": ("rush", "open_lan_lobby", 2),
            "start_quest_lan": ("quests", "open_lan_lobby", 3),
        }
        resolved = mode_by_action.get(action)
        if resolved is None:
            if action in {"start_survival", "start_rush", "start_typo", "start_tutorial", "start_quest"}:
                # Starting gameplay from the LAN lobby uses the normal mode start actions
                # (`start_survival`, `start_rush`, etc) but must keep the LAN runtime alive.
                pending = self._pending_session()
                runtime = self.state.network_runtime
                if bool(self.state.network_in_lobby) and pending is not None and runtime is not None:
                    return action

                self.state.network_in_lobby = False
                self.state.network_waiting_for_players = False
                self.state.network_expected_players = 1
                self.state.network_connected_players = 1
                if runtime is not None:
                    runtime.close()
                self.state.network_runtime = None
            return action

        self._ensure_lan_debug_log_started()

        expected_mode, forward_action, mode_id = resolved
        pending = self._pending_session()
        if pending is None:
            self.state.network_last_error = "LAN session is not configured."
            lan_debug_log("lan_action_error", action=action, reason=str(self.state.network_last_error))
            return None
        cfg = pending.config
        if str(cfg.mode) != expected_mode:
            self.state.network_last_error = (
                f"LAN mode mismatch: pending={cfg.mode!r} action={expected_mode!r}"
            )
            lan_debug_log("lan_action_error", action=action, reason=str(self.state.network_last_error))
            return None

        player_count = max(1, min(4, int(cfg.player_count)))
        self.state.config.player_count = int(player_count)
        self.state.network_in_lobby = True
        self.state.network_expected_players = int(player_count)
        self.state.network_connected_players = 1 if str(pending.role) == "host" else 0
        self.state.network_waiting_for_players = True
        self.state.network_desync_count = 0
        self.state.network_resync_failure_count = 0
        self.state.config.game_mode = int(mode_id)

        runtime = self.state.network_runtime
        if runtime is not None:
            runtime.close()

        netcode_mode = str(cfg.netcode_mode).strip().lower()
        if netcode_mode == "lockstep":
            from ..net.lockstep_runtime import LockstepRuntime, LockstepRuntimeConfig
        else:
            from ..net.rollback_runtime import RollbackRuntime, RollbackRuntimeConfig

        sim_status_snapshot = None
        if str(pending.role) == "host":
            from ..net.deterministic_status import status_snapshot_from_status

            sim_status_snapshot = status_snapshot_from_status(self.state.status)

        if netcode_mode == "lockstep":
            endpoint = cfg.lockstep_endpoint()
            runtime = LockstepRuntime(
                LockstepRuntimeConfig(
                    role=str(pending.role),
                    mode_id=int(mode_id),
                    player_count=int(player_count),
                    bind_host=str(endpoint.bind_host),
                    host_ip=str(endpoint.host),
                    port=int(endpoint.port),
                    quest_level=str(cfg.quest_level or ""),
                    preserve_bugs=False,
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    sim_status_snapshot=sim_status_snapshot,
                ),
            )
        else:
            endpoint = cfg.rollback_endpoint()
            runtime = RollbackRuntime(
                RollbackRuntimeConfig(
                    role=str(pending.role),
                    mode_id=int(mode_id),
                    player_count=int(player_count),
                    relay_host=str(endpoint.relay_host),
                    relay_port=int(endpoint.relay_port),
                    room_code=str(endpoint.room_code).strip().upper(),
                    quest_level=str(cfg.quest_level or ""),
                    preserve_bugs=False,
                    netcode_mode="rollback",
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    rollback_max_ticks=max(1, int(cfg.rollback_max_ticks)),
                    reconnect_timeout_ms=max(1000, int(cfg.reconnect_timeout_ms)),
                    sim_status_snapshot=sim_status_snapshot,
                ),
            )
        self.state.network_runtime = runtime
        lan_debug_log(
            "lan_action_resolved",
            action=action,
            forward_action=forward_action,
            role=str(pending.role),
            mode=str(expected_mode),
            netcode_mode=str(netcode_mode),
            auto_start=bool(pending.auto_start),
            player_count=int(player_count),
            connected_players=int(self.state.network_connected_players),
            waiting_for_players=bool(self.state.network_waiting_for_players),
        )

        if expected_mode == "quests":
            raw_level = str(cfg.quest_level or "").strip()
            if not raw_level:
                self.state.network_last_error = "Quest LAN mode requires --quest-level."
                pending.error = self.state.network_last_error
                lan_debug_log("lan_action_error", action=action, reason=str(self.state.network_last_error))
                return None
            level = QuestLevel.try_parse(raw_level)
            if level is None:
                self.state.network_last_error = f"Invalid quest level for LAN: {raw_level!r}"
                pending.error = self.state.network_last_error
                lan_debug_log("lan_action_error", action=action, reason=str(self.state.network_last_error))
                return None
            self.state.pending_quest_level = level.to_string()

        return forward_action

    def _tick_network_runtime(self) -> None:
        pending = self._pending_session()
        runtime = self.state.network_runtime
        if pending is None or runtime is None:
            return
        try:
            runtime.open()
        except OSError as exc:
            msg = f"LAN socket error: {exc}"
            runtime.error = msg
            pending.error = msg
            self.state.network_last_error = msg
            lan_debug_log("net_open_error", role=str(pending.role), error=str(exc))
            return
        runtime.update()
        self.state.network_desync_count = int(runtime.desync_count)
        lobby_state = runtime.lobby_state()
        if lobby_state is not None:
            expected = max(1, min(4, int(lobby_state.player_count)))
            connected = sum(1 for slot in lobby_state.slots if bool(slot.connected))
            self.state.network_expected_players = int(expected)
            self.state.network_connected_players = max(0, min(int(expected), int(connected)))
            self.state.network_waiting_for_players = not bool(lobby_state.started)
        error = str(runtime.error)
        if error and not self.state.network_last_error:
            self.state.network_last_error = error

    def update(self, dt: float) -> None:
        input_begin_frame()
        console = self.state.console
        console.handle_hotkey()
        console.update(dt)
        self._sync_console_elapsed_ms()
        self._handle_console_requests()
        self._sync_rtx_mode()
        _update_screen_fade(self.state, dt)
        self._tick_network_runtime()
        if debug_enabled() and (not console.open_flag) and rl.is_key_pressed(rl.KeyboardKey.KEY_F4):
            self._set_rtx_mode(cycle_rtx_render_mode(self.state.rtx_mode), source="debug hotkey F4")
        if debug_enabled() and (not console.open_flag) and rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True
        if console.open_flag:
            if console.quit_requested:
                self.state.quit_requested = True
                console.quit_requested = False
            return

        self._demo_trial_info = None
        self._tick_statistics_playtime(dt)
        if self._front_active is not None and self._front_active in self._gameplay_views:
            if self._update_demo_trial_overlay(dt):
                return

        self._active.update(dt)
        if self._front_active is not None:
            action = self._front_active.take_action()
            if action is not None:
                action = self._resolve_lan_action(action)
                if action is None:
                    return
            if action == "back_to_menu":
                self._capture_gameplay_ground_for_menu()
                self.state.pause_background = None
                self._front_active.close()
                self._front_active = None
                while self._front_stack:
                    self._front_stack.pop().close()
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action == "back_to_previous":
                if self._front_stack:
                    self._front_active.close()
                    self._front_active = self._front_stack.pop()
                    if self._front_active in self._gameplay_views:
                        self.state.pause_background = None
                    else:
                        if isinstance(self._front_active, StatisticsMenuView):
                            self._front_active.reopen_from_child()
                    self._active = self._front_active
                    return
                self._front_active.close()
                self._front_active = None
                self.state.pause_background = None
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action == "open_pause_menu":
                pause_view = self._front_views.get("open_pause_menu")
                if pause_view is None:
                    return
                if self._front_active in self._gameplay_views:
                    self.state.pause_background = cast(PauseBackground, self._front_active)
                    self._front_stack.append(self._front_active)
                    pause_view.open()
                    self._front_active = pause_view
                    self._active = pause_view
                    return
                if self.state.pause_background is None:
                    # Options panel uses open_pause_menu as back_action; when no game is
                    # running, treat it like back_to_menu.
                    self._front_active.close()
                    self._front_active = None
                    while self._front_stack:
                        self._front_stack.pop().close()
                    self._menu.open()
                    self._active = self._menu
                    self._menu_active = True
                    return
                self._front_active.close()
                pause_view.open()
                self._front_active = pause_view
                self._active = pause_view
                return
            if action in {"start_survival", "start_rush", "start_typo"}:
                # Temporary: bump the counter on mode start so the Play Game overlay (F1)
                # and Statistics screen reflect activity.
                mode_name = {
                    "start_survival": "survival",
                    "start_rush": "rush",
                    "start_typo": "typo",
                }.get(action)
                if mode_name is not None:
                    self.state.status.increment_mode_play_count(mode_name)
            if action is not None:
                view = self._front_views.get(action)
                if view is not None:
                    if action in {"open_high_scores", "open_weapon_database", "open_perk_database", "open_credits"}:
                        if (self._front_active in self._gameplay_views) and (self.state.pause_background is None):
                            self.state.pause_background = cast(PauseBackground, self._front_active)
                        self._front_stack.append(self._front_active)
                    elif action in {"quest_results", "quest_failed"} and (self._front_active in self._gameplay_views):
                        self.state.pause_background = cast(PauseBackground, self._front_active)
                        self._front_stack.append(self._front_active)
                    else:
                        if action in {
                            "start_survival",
                            "start_rush",
                            "start_typo",
                            "start_tutorial",
                            "start_quest",
                            "open_play_game",
                            "open_lan_session",
                            "open_quests",
                        }:
                            self.state.pause_background = None
                            while self._front_stack:
                                self._front_stack.pop().close()
                        self._front_active.close()
                    view.open()
                    self._maybe_adopt_menu_ground(action, view)
                    self._front_active = view
                    self._active = view
                    return
        if self._menu_active:
            action = self._menu.take_action()
            if action is None:
                action = self._auto_lan_start_action()
            if action == "quit_app":
                self.state.quit_requested = True
                return
            if action == "start_demo":
                self._menu.close()
                self._menu_active = False
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
                return
            if action == "quit_after_demo":
                self._menu.close()
                self._menu_active = False
                self._quit_after_demo = True
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
                return
            if action is not None:
                action = self._resolve_lan_action(action)
                if action is None:
                    return
                view = self._front_views.get(action)
                if view is not None:
                    self._menu.close()
                    self._menu_active = False
                    view.open()
                    self._maybe_adopt_menu_ground(action, view)
                    self._front_active = view
                    self._active = view
                    return
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._front_active is None
            and self.state.demo_enabled
            and self._boot.is_theme_started()
        ):
            self._demo.open()
            self._active = self._demo
            self._demo_active = True
            return
        if self._demo_active and not self._menu_active and self._demo.is_finished():
            self._demo.close()
            self._demo_active = False
            if self._quit_after_demo:
                self._quit_after_demo = False
                self.state.quit_requested = True
                return
            ensure_menu_ground(self.state, regenerate=True)
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._front_active is None
            and self._boot.is_theme_started()
        ):
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
        if console.quit_requested:
            self.state.quit_requested = True
            console.quit_requested = False

    def _tick_statistics_playtime(self, dt: float) -> None:
        # Native `_game_sequence_id` advances on gameplay frames only (state 9)
        # and is used by the Statistics "played for ... hours ... minutes" row.
        if self.state.demo_enabled:
            return
        if self._front_active is None or self._front_active not in self._gameplay_views:
            return
        delta_ms = int(float(dt) * 1000.0)
        if delta_ms <= 0:
            return
        self.state.status.game_sequence_id = int(self.state.status.game_sequence_id + delta_ms)

    def _sync_console_elapsed_ms(self) -> None:
        views: list[FrontView] = []
        if self._front_active is not None:
            views.append(self._front_active)
        if self._front_stack:
            views.extend(reversed(self._front_stack))
        for view in views:
            gameplay = self._as_gameplay_view(view)
            if gameplay is not None:
                self.state.survival_elapsed_ms = max(0.0, float(gameplay.console_elapsed_ms()))
                return

    def _handle_console_requests(self) -> None:
        if self.state.terrain_regenerate_requested:
            self.state.terrain_regenerate_requested = False
            self._regenerate_terrain_for_console()

    def _regenerate_terrain_for_console(self) -> None:
        ensure_menu_ground(self.state, regenerate=True)
        views: list[FrontView] = []
        if self._front_active is not None:
            views.append(self._front_active)
        if self._front_stack:
            views.extend(reversed(self._front_stack))
        for view in views:
            gameplay = self._as_gameplay_view(view)
            if gameplay is not None:
                gameplay.regenerate_terrain_for_console()
                return

    def _update_demo_trial_overlay(self, dt: float) -> bool:
        if not self.state.demo_enabled:
            return False

        mode_raw = self.state.config.game_mode
        try:
            mode_id = GameMode(mode_raw)
        except ValueError:
            mode_id = GameMode.DEMO
        quest_major, quest_minor = 0, 0
        match mode_id:
            case GameMode.QUESTS:
                level_text = str(self.state.pending_quest_level or "")
                if level_text:
                    level = QuestLevel.parse(level_text)
                    quest_major, quest_minor = level.to_stage_pair()
            case _:
                pass

        current = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self.state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self.state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )

        frame_dt = min(float(dt), 0.1)
        dt_ms = int(frame_dt * 1000.0)
        used_ms, grace_ms = tick_demo_trial_timers(
            demo_build=True,
            game_mode_id=mode_id,
            overlay_visible=bool(current.visible),
            global_playtime_ms=int(self.state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self.state.demo_trial_elapsed_ms),
            dt_ms=int(dt_ms),
        )
        if used_ms != int(self.state.status.game_sequence_id):
            self.state.status.game_sequence_id = int(used_ms)
        self.state.demo_trial_elapsed_ms = int(grace_ms)

        info = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self.state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self.state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )
        self._demo_trial_info = info
        if not info.visible:
            return False

        self._demo_trial_overlay.bind_cache(self.state.texture_cache)
        action = self._demo_trial_overlay.update(dt_ms)
        if action == "purchase":
            try:
                webbrowser.open(DEMO_PURCHASE_URL)
            except (OSError, webbrowser.Error):
                self.state.console.log.log("demo trial: failed to open purchase URL")
            return True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or action == "maybe_later":
            self._capture_gameplay_ground_for_menu()
            if self._front_active is not None:
                self._front_active.close()
                self._front_active = None
            while self._front_stack:
                self._front_stack.pop().close()
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return True

        return True

    def _maybe_adopt_menu_ground(self, action: str, _view: FrontView) -> None:
        if action not in {"start_survival", "start_rush"}:
            return
        # Native `game_state_set(9)` always calls `gameplay_reset_state()`, which
        # runs `terrain_generate_random()`. Menu terrain should carry back to menu,
        # but entering a fresh gameplay run must regenerate terrain instead of
        # reusing the captured menu render target.

    def _as_gameplay_view(self, view: FrontView | None) -> _GameplayView | None:
        if view is None or view not in self._gameplay_views:
            return None
        return cast(_GameplayView, view)

    def _set_rtx_mode(self, mode: RtxRenderMode, *, source: str) -> None:
        if mode is self.state.rtx_mode:
            return
        self.state.rtx_mode = mode
        self._sync_rtx_mode()
        self.state.console.log.log(f"render mode: {mode.value} ({source})")

    def _sync_rtx_mode(self) -> None:
        views: list[FrontView] = []
        if self._front_active is not None:
            views.append(self._front_active)
        if self._front_stack:
            views.extend(self._front_stack)
        for view in views:
            gameplay = self._as_gameplay_view(view)
            if gameplay is not None:
                gameplay.set_rtx_mode(self.state.rtx_mode)

    def _steal_ground_from_view(self, view: FrontView | None) -> GroundRenderer | None:
        gameplay = self._as_gameplay_view(view)
        if gameplay is None:
            return None
        ground = gameplay.steal_ground_for_menu()
        if isinstance(ground, GroundRenderer):
            return ground
        return None

    def _menu_ground_camera_from_view(self, view: FrontView | None) -> Vec2 | None:
        gameplay = self._as_gameplay_view(view)
        if gameplay is None:
            return None
        camera = gameplay.menu_ground_camera()
        if isinstance(camera, Vec2):
            return camera
        return None

    def _replace_menu_ground(self, ground: GroundRenderer, *, camera: Vec2 | None) -> None:
        previous = self.state.menu_ground
        if previous is ground:
            self.state.menu_ground_camera = camera
            return
        if previous is not None and previous.render_target is not None:
            rl.unload_render_texture(previous.render_target)
            previous.render_target = None
        self.state.menu_ground = ground
        self.state.menu_ground_camera = camera

    def _capture_gameplay_ground_for_menu(self) -> None:
        ground: GroundRenderer | None = None
        camera: Vec2 | None = None
        if self._front_active in self._gameplay_views:
            camera = self._menu_ground_camera_from_view(self._front_active)
            ground = self._steal_ground_from_view(self._front_active)
        if ground is None:
            for view in reversed(self._front_stack):
                if view in self._gameplay_views:
                    camera = self._menu_ground_camera_from_view(view)
                    ground = self._steal_ground_from_view(view)
                    if ground is not None:
                        break
        if ground is None:
            return
        self._replace_menu_ground(ground, camera=camera)

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def _draw_scene_layers(self) -> None:
        self._active.draw()
        info = self._demo_trial_info
        if info is not None and bool(info.visible):
            self._demo_trial_overlay.bind_cache(self.state.texture_cache)
            self._demo_trial_overlay.draw(info)
        self.state.console.draw()
        self.state.console.draw_fps_counter()

    def draw(self) -> None:
        gamma_gain = max(0.0, float(self.state.gamma_ramp))
        if abs(gamma_gain - 1.0) <= 1e-6:
            self._draw_scene_layers()
            return

        shader, gain_loc = _get_gamma_ramp_shader()
        if shader is None or gain_loc < 0:
            self._draw_scene_layers()
            return

        _set_gamma_ramp_gain(shader, gain_loc, gamma_gain)
        rl.begin_shader_mode(shader)
        try:
            self._draw_scene_layers()
        finally:
            rl.end_shader_mode()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        if self._front_active is not None:
            self._front_active.close()
        while self._front_stack:
            self._front_stack.pop().close()
        if self._demo_active:
            self._demo.close()
        self._demo_trial_overlay.close()
        if self.state.menu_ground is not None and self.state.menu_ground.render_target is not None:
            rl.unload_render_texture(self.state.menu_ground.render_target)
            self.state.menu_ground.render_target = None
        self._boot.close()
        self.state.console.close()
        rl.show_cursor()
