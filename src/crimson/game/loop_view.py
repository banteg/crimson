from __future__ import annotations

import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto

from grim.audio import stop_music
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from grim.view import View, ViewContext

from ..debug import debug_enabled
from ..demo import DemoView
from ..demo_trial import demo_trial_overlay_info, tick_demo_trial_timers
from ..game_modes import GameMode
from ..input_codes import input_begin_frame
from ..modes.quest_mode import QuestMode
from ..modes.rush_mode import RushMode
from ..modes.survival_mode import SurvivalMode
from ..modes.tutorial_mode import TutorialMode
from ..modes.typo_mode import TypoShooterMode
from ..net.debug_log import init_lan_debug_log, lan_debug_log, lan_debug_log_path
from ..render.rtx.mode import RtxRenderMode, cycle_rtx_render_mode
from ..screens.boot import BootView
from ..screens.chrome.runtime import ensure_menu_ground
from ..screens.chrome.view import ChromeScreenView
from ..screens.high_scores_view import HighScoresView
from ..screens.menu import MenuView
from ..screens.panels.alien_zookeeper import AlienZooKeeperView
from ..screens.panels.controls import ControlsMenuView
from ..screens.panels.credits import CreditsView
from ..screens.panels.databases import UnlockedPerksDatabaseView, UnlockedWeaponsDatabaseView
from ..screens.panels.mods import ModsMenuView
from ..screens.panels.network_lobby import NetworkLobbyPanelView
from ..screens.panels.network_session import NetworkSessionPanelView
from ..screens.panels.options import OptionsMenuView
from ..screens.panels.other_games import OtherGamesView
from ..screens.panels.play_game import PlayGameMenuView
from ..screens.panels.stats import StatisticsMenuView
from ..screens.pause_menu import PauseMenuView
from ..screens.quest_views import EndNoteView, QuestFailedView, QuestResultsView, QuestsMenuView
from ..screens.transitions import _update_screen_fade
from ..ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayInfo, DemoTrialOverlayUi
from .types import (
    BackToMenu,
    BackToPrevious,
    FrontRouteId,
    GameplayScreen,
    GameState,
    HighScoresRequest,
    OpenFrontRoute,
    OpenFrontRouteWithParent,
    OpenLanLobby,
    QuitAfterDemo,
    QuitApp,
    Screen,
    ScreenAction,
    StartDemo,
    StartLanMatch,
    front_route_for_network_mode,
    game_mode_for_front_route,
)

_GAMMA_RAMP_SHADER: rl.Shader | None = None
_GAMMA_RAMP_SHADER_GAIN_LOC: int = -1
_GAMMA_RAMP_SHADER_TRIED = False


class _FrontRouteMode(Enum):
    REPLACE_CURRENT = auto()
    PUSH_CURRENT = auto()


@dataclass(frozen=True)
class _FrontRoute:
    view: Screen
    mode: _FrontRouteMode = _FrontRouteMode.REPLACE_CURRENT
    clear_stack: bool = False
    require_gameplay: bool = False
    before_open: Callable[[], None] | None = None

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


def _mode_view_context(state: GameState) -> ViewContext:
    preserve_bugs = bool(state.preserve_bugs)
    if bool(state.network_in_lobby):
        # Network multiplayer must keep simulation rules deterministic across peers.
        preserve_bugs = False
    return ViewContext(assets_dir=state.assets_dir, preserve_bugs=preserve_bugs)


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
        play_game = PlayGameMenuView(state)
        network_session = NetworkSessionPanelView(state)
        network_lobby = NetworkLobbyPanelView(state)
        quests_menu = QuestsMenuView(state)
        pause_menu = PauseMenuView(state)
        quest_mode = QuestMode(
            _mode_view_context(state),
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        quest_results = QuestResultsView(state)
        quest_failed = QuestFailedView(state)
        end_note = EndNoteView(state)
        high_scores = HighScoresView(state)
        survival_mode = SurvivalMode(
            _mode_view_context(state),
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        rush_mode = RushMode(
            _mode_view_context(state),
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        typo_mode = TypoShooterMode(
            _mode_view_context(state),
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        tutorial_mode = TutorialMode(
            _mode_view_context(state),
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        options_menu = OptionsMenuView(state)
        controls_menu = ControlsMenuView(state)
        statistics_menu = StatisticsMenuView(state)
        weapons_database = UnlockedWeaponsDatabaseView(state)
        perks_database = UnlockedPerksDatabaseView(state)
        credits_view = CreditsView(state)
        alien_zookeeper = AlienZooKeeperView(state)
        mods_menu = ModsMenuView(state)
        other_games = OtherGamesView(state)

        self._front_routes: dict[FrontRouteId, _FrontRoute] = {
            FrontRouteId.OPEN_PLAY_GAME: _FrontRoute(play_game, clear_stack=True),
            FrontRouteId.OPEN_LAN_SESSION: _FrontRoute(network_session, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_LAN_LOBBY: _FrontRoute(network_lobby, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_QUESTS: _FrontRoute(quests_menu, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_PAUSE_MENU: _FrontRoute(
                pause_menu,
                mode=_FrontRouteMode.PUSH_CURRENT,
                require_gameplay=True,
            ),
            FrontRouteId.START_QUEST: _FrontRoute(quest_mode, clear_stack=True),
            FrontRouteId.QUEST_RESULTS: _FrontRoute(
                quest_results,
                mode=_FrontRouteMode.PUSH_CURRENT,
                require_gameplay=True,
            ),
            FrontRouteId.QUEST_FAILED: _FrontRoute(
                quest_failed,
                mode=_FrontRouteMode.PUSH_CURRENT,
                require_gameplay=True,
            ),
            FrontRouteId.END_NOTE: _FrontRoute(end_note),
            FrontRouteId.OPEN_HIGH_SCORES: _FrontRoute(high_scores, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.START_SURVIVAL: _FrontRoute(
                survival_mode,
                clear_stack=True,
                before_open=lambda: self.state.status.increment_mode_play_count("survival"),
            ),
            FrontRouteId.START_RUSH: _FrontRoute(
                rush_mode,
                clear_stack=True,
                before_open=lambda: self.state.status.increment_mode_play_count("rush"),
            ),
            FrontRouteId.START_TYPO: _FrontRoute(
                typo_mode,
                clear_stack=True,
                before_open=lambda: self.state.status.increment_mode_play_count("typo"),
            ),
            FrontRouteId.START_TUTORIAL: _FrontRoute(tutorial_mode, clear_stack=True),
            FrontRouteId.OPEN_OPTIONS: _FrontRoute(options_menu, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_CONTROLS: _FrontRoute(controls_menu, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_STATISTICS: _FrontRoute(statistics_menu),
            FrontRouteId.OPEN_WEAPON_DATABASE: _FrontRoute(weapons_database, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_PERK_DATABASE: _FrontRoute(perks_database, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_CREDITS: _FrontRoute(credits_view, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_ALIEN_ZOOKEEPER: _FrontRoute(alien_zookeeper, mode=_FrontRouteMode.PUSH_CURRENT),
            FrontRouteId.OPEN_MODS: _FrontRoute(mods_menu),
            FrontRouteId.OPEN_OTHER_GAMES: _FrontRoute(other_games, mode=_FrontRouteMode.PUSH_CURRENT),
        }
        self._front_active: Screen | None = None
        self._front_stack: list[Screen] = []
        self._active: View = self._boot
        self._demo_trial_overlay: DemoTrialOverlayUi | None = None
        self._demo_trial_info: DemoTrialOverlayInfo | None = None
        self._demo_active = False
        self._menu_active = False
        self._quit_after_demo = False
        self._screenshot_requested = False
        self._runtime_updates_per_frame = 0

    def _pending_session(self):
        return self.state.pending_network_session

    def _demo_trial_overlay_view(self) -> DemoTrialOverlayUi:
        overlay = self._demo_trial_overlay
        if overlay is None:
            overlay = DemoTrialOverlayUi(self.state.assets_dir)
            self._demo_trial_overlay = overlay
        return overlay

    def _ensure_lan_debug_log_started(self) -> None:
        if lan_debug_log_path() is not None:
            return
        pending = self._pending_session()
        if pending is None:
            return
        cfg = pending.config
        if cfg.netcode_mode == "lockstep":
            endpoint = cfg.endpoint
            host = str(endpoint.host)
            port = int(endpoint.port)
        else:
            endpoint = cfg.endpoint
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

    def _auto_lan_start_action(self) -> ScreenAction | None:
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
        try:
            route = front_route_for_network_mode(pending.config.mode)
        except ValueError:
            pending.error = f"Unsupported LAN mode: {mode}"
            self.state.network_last_error = pending.error
            lan_debug_log("auto_lan_start_error", error=str(pending.error))
            return OpenFrontRoute(FrontRouteId.OPEN_LAN_SESSION)
        return OpenLanLobby(route)

    def _reset_local_network_state(self) -> None:
        self.state.network_in_lobby = False
        self.state.network_waiting_for_players = False
        self.state.network_expected_players = 1
        self.state.network_connected_players = 1
        runtime = self.state.network_runtime
        if runtime is not None:
            runtime.close()
        self.state.network_runtime = None

    def _prepare_lan_lobby(self, route: FrontRouteId) -> None:
        self._ensure_lan_debug_log_started()
        pending = self._pending_session()
        if pending is None:
            self.state.network_last_error = "LAN session is not configured."
            lan_debug_log("lan_action_error", route=route.name, reason=str(self.state.network_last_error))
            raise RuntimeError(self.state.network_last_error)
        cfg = pending.config
        expected_route = front_route_for_network_mode(cfg.mode)
        if expected_route is not route:
            self.state.network_last_error = (
                f"LAN mode mismatch: pending={cfg.mode!r} route={route.name!r}"
            )
            lan_debug_log("lan_action_error", route=route.name, reason=str(self.state.network_last_error))
            raise RuntimeError(self.state.network_last_error)
        mode_id = game_mode_for_front_route(route)
        if mode_id is None:
            raise RuntimeError(f"LAN lobby route must target gameplay: {route!r}")

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

        netcode_mode = cfg.netcode_mode
        if netcode_mode == "lockstep":
            from ..net.lockstep_runtime import (
                HostLockstepRuntimeConfig,
                JoinLockstepRuntimeConfig,
                LockstepRuntime,
            )
        else:
            from ..net.rollback_runtime import (
                HostRollbackRuntimeConfig,
                JoinRollbackRuntimeConfig,
                RollbackRuntime,
            )

        sim_status_snapshot = None
        if str(pending.role) == "host":
            from ..net.deterministic_status import status_snapshot_from_status

            sim_status_snapshot = status_snapshot_from_status(self.state.status)

        if netcode_mode == "lockstep":
            endpoint = cfg.endpoint
            if pending.role == "host":
                runtime_cfg = HostLockstepRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    bind_host=str(endpoint.bind_host),
                    host_ip=str(endpoint.host),
                    port=int(endpoint.port),
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    sim_status_snapshot=sim_status_snapshot,
                )
            else:
                runtime_cfg = JoinLockstepRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    bind_host=str(endpoint.bind_host),
                    host_ip=str(endpoint.host),
                    port=int(endpoint.port),
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    sim_status_snapshot=sim_status_snapshot,
                )
            runtime = LockstepRuntime(runtime_cfg)
        else:
            endpoint = cfg.endpoint
            if pending.role == "host":
                runtime_cfg = HostRollbackRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    relay_host=str(endpoint.relay_host),
                    relay_port=int(endpoint.relay_port),
                    room_code=endpoint.room_code,
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    netcode_mode="rollback",
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    rollback_max_ticks=max(1, int(cfg.rollback_max_ticks)),
                    reconnect_timeout_ms=max(1000, int(cfg.reconnect_timeout_ms)),
                    sim_status_snapshot=sim_status_snapshot,
                )
            else:
                runtime_cfg = JoinRollbackRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    relay_host=str(endpoint.relay_host),
                    relay_port=int(endpoint.relay_port),
                    room_code=endpoint.room_code,
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    netcode_mode="rollback",
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    rollback_max_ticks=max(1, int(cfg.rollback_max_ticks)),
                    reconnect_timeout_ms=max(1000, int(cfg.reconnect_timeout_ms)),
                    sim_status_snapshot=sim_status_snapshot,
                )
            runtime = RollbackRuntime(runtime_cfg)
        self.state.network_runtime = runtime
        lan_debug_log(
            "lan_action_resolved",
            route=route.name,
            forward_route=FrontRouteId.OPEN_LAN_LOBBY.name,
            role=str(pending.role),
            mode=str(cfg.mode),
            netcode_mode=netcode_mode,
            auto_start=bool(pending.auto_start),
            player_count=int(player_count),
            connected_players=int(self.state.network_connected_players),
            waiting_for_players=bool(self.state.network_waiting_for_players),
        )

        if route is FrontRouteId.START_QUEST:
            level = cfg.quest_level
            if level is None:
                self.state.network_last_error = "Quest LAN mode requires --quest-level."
                pending.error = self.state.network_last_error
                lan_debug_log("lan_action_error", route=route.name, reason=str(self.state.network_last_error))
                raise RuntimeError(self.state.network_last_error)
            self.state.pending_quest_level = level

    def _prepare_lan_match(self, action: StartLanMatch) -> None:
        mode_id = game_mode_for_front_route(action.route)
        if mode_id is None:
            raise RuntimeError(f"LAN gameplay route must target gameplay: {action.route!r}")
        player_count = max(1, min(4, int(action.player_count)))
        self.state.network_in_lobby = True
        self.state.network_waiting_for_players = False
        self.state.network_expected_players = int(player_count)
        self.state.network_connected_players = int(player_count)
        self.state.config.player_count = int(player_count)
        self.state.config.game_mode = int(mode_id)
        if action.route is FrontRouteId.START_QUEST:
            if action.quest_level is None:
                raise RuntimeError("LAN quest match start requires a quest level")
            self.state.pending_quest_level = action.quest_level

    def _tick_network_runtime(self) -> None:
        self._runtime_updates_per_frame = 0
        self.state.runtime_updates_per_frame = 0
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
        self._runtime_updates_per_frame += 1
        self.state.runtime_updates_per_frame = int(self._runtime_updates_per_frame)
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
        if bool(self.state.network_in_lobby) and int(self._runtime_updates_per_frame) != 1:
            lan_debug_log(
                "runtime_pump_violation",
                context="interactive_gameplay",
                expected=1,
                actual=int(self._runtime_updates_per_frame),
            )

    def _clear_state_frame_telemetry(self) -> None:
        self.state.input_stall_count = 0
        self.state.ticks_advanced_per_frame = 0
        self.state.sim_ms = 0.0
        self.state.presentation_plan_ms = 0.0
        self.state.presentation_apply_ms = 0.0

    def _sync_gameplay_frame_telemetry_to_state(self) -> None:
        gameplay = self._gameplay_screen(self._front_active)
        if gameplay is None:
            return
        (
            runtime_updates_per_frame,
            input_stall_count,
            ticks_advanced_per_frame,
            sim_ms,
            presentation_plan_ms,
            presentation_apply_ms,
        ) = gameplay.frame_telemetry()
        self.state.runtime_updates_per_frame = int(runtime_updates_per_frame)
        self.state.input_stall_count = int(input_stall_count)
        self.state.ticks_advanced_per_frame = int(ticks_advanced_per_frame)
        self.state.sim_ms = float(sim_ms)
        self.state.presentation_plan_ms = float(presentation_plan_ms)
        self.state.presentation_apply_ms = float(presentation_apply_ms)

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
        self._clear_state_frame_telemetry()
        front_active = self._front_active
        gameplay = self._gameplay_screen(front_active)
        if gameplay is not None:
            gameplay.set_runtime_updates_per_frame(int(self._runtime_updates_per_frame))
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
        if gameplay is not None:
            if self._update_demo_trial_overlay(dt):
                return

        self._active.update(dt)
        self._sync_gameplay_frame_telemetry_to_state()
        if self._front_active is not None:
            front_active = self._front_active
            gameplay = self._gameplay_screen(front_active)
            action = front_active.take_action()
            if gameplay is not None:
                action = self._resolve_gameplay_action(gameplay, action)
            if action is not None:
                self._apply_screen_action(action, current=front_active, gameplay=gameplay)
                return
        if self._menu_active:
            action = self._menu.take_action()
            if action is None:
                action = self._auto_lan_start_action()
            if action is not None:
                self._apply_screen_action(action, current=None, gameplay=None)
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
        if self._gameplay_screen(self._front_active) is None:
            return
        delta_ms = int(float(dt) * 1000.0)
        if delta_ms <= 0:
            return
        self.state.status.game_sequence_id = int(self.state.status.game_sequence_id + delta_ms)

    def _sync_console_elapsed_ms(self) -> None:
        views: list[Screen] = []
        if self._front_active is not None:
            views.append(self._front_active)
        if self._front_stack:
            views.extend(reversed(self._front_stack))
        for view in views:
            gameplay = self._gameplay_screen(view)
            if gameplay is not None:
                self.state.survival_elapsed_ms = max(0.0, float(gameplay.console_elapsed_ms()))
                return

    def _handle_console_requests(self) -> None:
        if self.state.terrain_regenerate_requested:
            self.state.terrain_regenerate_requested = False
            self._regenerate_terrain_for_console()

    def _regenerate_terrain_for_console(self) -> None:
        ensure_menu_ground(self.state, regenerate=True)
        views: list[Screen] = []
        if self._front_active is not None:
            views.append(self._front_active)
        if self._front_stack:
            views.extend(reversed(self._front_stack))
        for view in views:
            gameplay = self._gameplay_screen(view)
            if gameplay is not None:
                gameplay.regenerate_terrain_for_console()
                return

    def _update_demo_trial_overlay(self, dt: float) -> bool:
        if not self.state.demo_enabled:
            return False
        gameplay = self._gameplay_screen(self._front_active)

        mode_raw = self.state.config.game_mode
        try:
            mode_id = GameMode(mode_raw)
        except ValueError:
            mode_id = GameMode.DEMO
        quest_level = None
        match mode_id:
            case GameMode.QUESTS:
                quest_level = self.state.pending_quest_level
            case _:
                pass

        current = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self.state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self.state.demo_trial_elapsed_ms),
            quest_level=quest_level,
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
            quest_level=quest_level,
        )
        self._demo_trial_info = info
        if not info.visible:
            return False
        if gameplay is not None:
            gameplay.prepare_demo_trial_overlay_frame()

        action = self._demo_trial_overlay_view().update(dt_ms)
        if action == "purchase":
            self.state.quit_requested = True
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

    def _maybe_adopt_menu_ground(self, action: ScreenAction, _view: Screen | None = None) -> None:
        match action:
            case OpenFrontRoute(route=FrontRouteId.START_SURVIVAL | FrontRouteId.START_RUSH):
                pass
            case StartLanMatch(route=FrontRouteId.START_SURVIVAL | FrontRouteId.START_RUSH):
                pass
            case _:
                return
        # Native `game_state_set(9)` always calls `gameplay_reset_state()`, which
        # runs `terrain_generate_random()`. Menu terrain should carry back to menu,
        # but entering a fresh gameplay run must regenerate terrain instead of
        # reusing the captured menu render target.

    def _gameplay_screen(self, view: Screen | None) -> GameplayScreen | None:
        if view is None or not isinstance(view, GameplayScreen):
            return None
        return view

    def _front_route(self, route_id: FrontRouteId) -> _FrontRoute:
        route = self._front_routes.get(route_id)
        assert route is not None, f"missing front route: {route_id!r}"
        return route

    def _close_front_stack(self) -> None:
        while self._front_stack:
            self._front_stack.pop().close()

    def _open_route_parent(self, route_id: FrontRouteId) -> Screen:
        parent_view = self._front_route(route_id).view
        parent_view.open()
        return parent_view

    def _close_menu_for_transition(self) -> None:
        if not self._menu_active:
            return
        self._menu.close()
        self._menu_active = False

    def _apply_screen_action(
        self,
        action: ScreenAction,
        *,
        current: Screen | None,
        gameplay: GameplayScreen | None,
    ) -> None:
        match action:
            case QuitApp():
                self.state.quit_requested = True
            case StartDemo():
                self._close_menu_for_transition()
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
            case QuitAfterDemo():
                self._close_menu_for_transition()
                self._quit_after_demo = True
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
            case BackToMenu():
                if gameplay is not None:
                    self._capture_gameplay_ground_for_menu()
                self.state.pause_background = None
                if self._front_active is not None:
                    self._front_active.close()
                self._front_active = None
                self._close_front_stack()
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
            case BackToPrevious():
                if current is None:
                    raise RuntimeError("BackToPrevious requires an active front screen")
                if self._front_stack:
                    current.close()
                    self._front_active = self._front_stack.pop()
                    if self._gameplay_screen(self._front_active) is not None:
                        self.state.pause_background = None
                    elif isinstance(self._front_active, ChromeScreenView):
                        self._front_active.resume_from_child()
                    self._active = self._front_active
                    return
                current.close()
                self._front_active = None
                self.state.pause_background = None
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
            case OpenFrontRoute(route=route_id):
                if route_id is FrontRouteId.OPEN_LAN_SESSION and not self._lan_ui_enabled():
                    self.state.network_last_error = "LAN UI is disabled (set cv_lanLockstepEnabled 1 to enable)."
                    lan_debug_log("lan_action_denied", route=route_id.name, reason=str(self.state.network_last_error))
                    self._apply_screen_action(
                        OpenFrontRoute(FrontRouteId.OPEN_PLAY_GAME),
                        current=current,
                        gameplay=gameplay,
                    )
                    return
                if current is None:
                    self._close_menu_for_transition()
                if game_mode_for_front_route(route_id) is not None:
                    self._reset_local_network_state()
                self._transition_to_front_route(route_id, current=current, gameplay=gameplay)
            case OpenFrontRouteWithParent(route=route_id, parent=parent_id, clear_stack=clear_stack):
                if current is None:
                    self._close_menu_for_transition()
                self._transition_to_front_route_with_parent(
                    route_id,
                    parent=parent_id,
                    clear_stack=clear_stack,
                    current=current,
                    gameplay=gameplay,
                )
            case OpenLanLobby(route=route_id):
                if current is None:
                    self._close_menu_for_transition()
                self._prepare_lan_lobby(route_id)
                self._transition_to_front_route(FrontRouteId.OPEN_LAN_LOBBY, current=current, gameplay=gameplay)
            case StartLanMatch():
                self._prepare_lan_match(action)
                self._transition_to_front_route(action.route, current=current, gameplay=gameplay)
            case _:
                raise AssertionError(f"Unsupported ScreenAction: {action!r}")

    def _transition_to_front_route(
        self,
        route_id: FrontRouteId,
        *,
        current: Screen | None,
        gameplay: GameplayScreen | None,
    ) -> None:
        route = self._front_route(route_id)
        if route.require_gameplay and gameplay is None:
            raise RuntimeError(f"{route_id.name} requires gameplay context")

        if route.clear_stack:
            self.state.pause_background = None
            self._close_front_stack()

        if route.mode is _FrontRouteMode.PUSH_CURRENT:
            if current is not None:
                if gameplay is not None and self.state.pause_background is None:
                    self.state.pause_background = gameplay
                self._front_stack.append(current)
        else:
            if current is not None:
                current.close()

        if route.before_open is not None:
            route.before_open()

        self._open_front_view(OpenFrontRoute(route_id), route.view)
        self._front_active = route.view
        self._active = route.view

    def _transition_to_front_route_with_parent(
        self,
        route_id: FrontRouteId,
        *,
        parent: FrontRouteId,
        clear_stack: bool,
        current: Screen | None,
        gameplay: GameplayScreen | None,
    ) -> None:
        route = self._front_route(route_id)
        if route.require_gameplay and gameplay is None:
            raise RuntimeError(f"{route_id.name} requires gameplay context")
        if clear_stack:
            self.state.pause_background = None
            self._close_front_stack()
        if current is not None:
            current.close()
        self.state.pause_background = None
        self._front_stack.append(self._open_route_parent(parent))
        if route.before_open is not None:
            route.before_open()
        self._open_front_view(OpenFrontRouteWithParent(route=route_id, parent=parent, clear_stack=clear_stack), route.view)
        self._front_active = route.view
        self._active = route.view

    def _open_front_view(self, action: ScreenAction, view: Screen) -> None:
        gameplay = self._gameplay_screen(view)
        if gameplay is not None:
            self._open_gameplay_screen(gameplay)
        else:
            view.open()
        self._maybe_adopt_menu_ground(action)

    def _open_gameplay_screen(self, gameplay: GameplayScreen) -> None:
        if self.state.screen_fade_ramp:
            self.state.screen_fade_alpha = 1.0
        self.state.screen_fade_ramp = False
        if isinstance(gameplay, QuestMode):
            self.state.quest_outcome = None
        if self.state.audio is not None:
            # Original game: entering gameplay cuts the menu theme; in-game tunes
            # start later on the first creature hit.
            stop_music(self.state.audio)
        self._configure_lan_runtime(gameplay)
        gameplay.bind_status(self.state.status)
        gameplay.bind_audio(self.state.audio, self.state.rng)
        gameplay.set_rtx_mode(self.state.rtx_mode)
        gameplay.bind_screen_fade(self.state)
        gameplay.open()
        if isinstance(gameplay, QuestMode):
            self._prepare_quest_run(gameplay)

    def _configure_lan_runtime(self, gameplay: GameplayScreen) -> None:
        pending = self.state.pending_network_session
        in_lobby = bool(self.state.network_in_lobby)
        if (not in_lobby) or pending is None:
            gameplay.set_lan_runtime(
                enabled=False,
                role="",
                expected_players=1,
                connected_players=1,
                waiting_for_players=False,
            )
            gameplay.bind_lan_runtime(runtime=None)
            return

        expected_players = max(
            1,
            min(
                4,
                int(self.state.network_expected_players),
            ),
        )
        connected_players = max(
            0,
            min(
                expected_players,
                int(self.state.network_connected_players),
            ),
        )
        waiting_for_players = bool(self.state.network_waiting_for_players)
        gameplay.set_lan_runtime(
            enabled=True,
            role=str(pending.role),
            expected_players=int(expected_players),
            connected_players=int(connected_players),
            waiting_for_players=bool(waiting_for_players),
        )
        runtime = self.state.network_runtime
        gameplay.bind_lan_runtime(runtime=runtime)
        if runtime is not None:
            match_start = runtime.match_start
            if match_start is not None:
                event = match_start()
                if event is not None:
                    gameplay.set_lan_match_start(
                        seed=int(event.seed),
                        start_tick=int(event.start_tick),
                        status_snapshot=event.status_snapshot,
                    )

    def _prepare_quest_run(self, gameplay: QuestMode) -> None:
        level = self.state.pending_quest_level
        if level is None:
            return
        gameplay.start_run(level, status=self.state.status)

    def _resolve_gameplay_action(self, gameplay: GameplayScreen, action: ScreenAction | None) -> ScreenAction | None:
        if action == OpenFrontRoute(FrontRouteId.OPEN_HIGH_SCORES):
            self.state.pending_high_scores = HighScoresRequest(game_mode_id=gameplay.default_game_mode_id)
            return action
        if action == BackToMenu():
            gameplay.close_requested = False
            return action
        if action is not None:
            return action
        if not gameplay.close_requested:
            return None
        gameplay.close_requested = False
        if isinstance(gameplay, QuestMode):
            outcome = gameplay.consume_outcome()
            if outcome is not None:
                self.state.quest_outcome = outcome
                if outcome.kind == "completed":
                    return OpenFrontRoute(FrontRouteId.QUEST_RESULTS)
                if outcome.kind == "failed":
                    return OpenFrontRoute(FrontRouteId.QUEST_FAILED)
            return BackToMenu()
        return BackToMenu()

    def _set_rtx_mode(self, mode: RtxRenderMode, *, source: str) -> None:
        if mode is self.state.rtx_mode:
            return
        self.state.rtx_mode = mode
        self._sync_rtx_mode()
        self.state.console.log.log(f"render mode: {mode.value} ({source})")

    def _sync_rtx_mode(self) -> None:
        views: list[Screen] = []
        if self._front_active is not None:
            views.append(self._front_active)
        if self._front_stack:
            views.extend(self._front_stack)
        for view in views:
            gameplay = self._gameplay_screen(view)
            if gameplay is not None:
                gameplay.set_rtx_mode(self.state.rtx_mode)

    def _steal_ground_from_view(self, view: Screen | None) -> GroundRenderer | None:
        gameplay = self._gameplay_screen(view)
        if gameplay is None:
            return None
        ground = gameplay.steal_ground_for_menu()
        if isinstance(ground, GroundRenderer):
            return ground
        return None

    def _menu_ground_camera_from_view(self, view: Screen | None) -> Vec2 | None:
        gameplay = self._gameplay_screen(view)
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
        if self._gameplay_screen(self._front_active) is not None:
            camera = self._menu_ground_camera_from_view(self._front_active)
            ground = self._steal_ground_from_view(self._front_active)
        if ground is None:
            for view in reversed(self._front_stack):
                if self._gameplay_screen(view) is not None:
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
            self._demo_trial_overlay_view().draw(info)
        self.state.console.draw()
        self.state.console.draw_fps_counter()

    def _draw_with_gamma(self) -> None:
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

    def draw(self) -> None:
        self._draw_with_gamma()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        if self._front_active is not None:
            self._front_active.close()
        while self._front_stack:
            self._front_stack.pop().close()
        if self._demo_active:
            self._demo.close()
        overlay = self._demo_trial_overlay
        if overlay is not None:
            overlay.close()
        if self.state.menu_ground is not None and self.state.menu_ground.render_target is not None:
            rl.unload_render_texture(self.state.menu_ground.render_target)
            self.state.menu_ground.render_target = None
        self._boot.close()
        self.state.console.close()
        rl.show_cursor()
