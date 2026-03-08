from __future__ import annotations

import webbrowser

from grim.audio import stop_music
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from grim.view import View

from ..debug import debug_enabled
from ..demo_trial import demo_trial_overlay_info, tick_demo_trial_timers
from ..game_modes import GameMode
from ..input_codes import input_begin_frame
from ..modes.quest_mode import QuestMode
from ..net import build_network_runtime
from ..net.debug_log import init_lan_debug_log, lan_debug_log, lan_debug_log_path
from ..render.rtx.mode import RtxRenderMode, cycle_rtx_render_mode
from ..screens.boot import BootView
from ..screens.menu import MenuView, ensure_menu_ground
from ..screens.panels.stats import StatisticsMenuView
from ..screens.transitions import _update_screen_fade
from ..ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayInfo, DemoTrialOverlayUi
from .loop_actions import (
    BACK_TO_MENU,
    BACK_TO_PREVIOUS,
    OPEN_HIGH_SCORES,
    OPEN_LAN_LOBBY,
    OPEN_LAN_SESSION,
    OPEN_PAUSE_MENU,
    OPEN_PLAY_GAME,
    OPEN_QUEST_FAILED,
    OPEN_QUEST_RESULTS,
    QUIT_AFTER_DEMO,
    QUIT_APP,
    START_DEMO,
    START_QUEST_LAN,
    START_RUSH,
    START_RUSH_LAN,
    START_SURVIVAL,
    START_SURVIVAL_LAN,
    START_TYPO,
    OpenScreenAction,
    ScreenId,
    StartLanModeAction,
    StartModeAction,
    ViewAction,
    action_label,
)
from .loop_screens import LoopScreens
from .types import GameplayScreen, GameState, HighScoresRequest, Screen

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
        self._screens = LoopScreens(state)
        self._demo = self._screens.demo
        self._menu = MenuView(state)
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

    def _reset_lan_lobby_state(self, *, close_runtime: bool) -> None:
        self.state.network_in_lobby = False
        self.state.network_waiting_for_players = False
        self.state.network_expected_players = 1
        self.state.network_connected_players = 1
        if not close_runtime:
            return
        runtime = self.state.network_runtime
        if runtime is not None:
            runtime.close()
        self.state.network_runtime = None

    def _auto_lan_start_action(self) -> ViewAction | None:
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
            return START_RUSH_LAN
        if mode == "quests":
            return START_QUEST_LAN
        if mode == "survival":
            return START_SURVIVAL_LAN
        pending.error = f"Unsupported LAN mode: {mode}"
        self.state.network_last_error = pending.error
        lan_debug_log("auto_lan_start_error", error=str(pending.error))
        return OPEN_LAN_SESSION

    def _resolve_lan_action(self, action: ViewAction) -> ViewAction | None:
        if action == OPEN_LAN_SESSION:
            if self._lan_ui_enabled():
                return action
            self.state.network_last_error = "LAN UI is disabled (set cv_lanLockstepEnabled 1 to enable)."
            lan_debug_log("lan_action_denied", action=action_label(action), reason=str(self.state.network_last_error))
            return OPEN_PLAY_GAME

        if isinstance(action, StartModeAction):
            if (
                bool(self.state.network_in_lobby)
                and self.state.pending_network_session is not None
                and self.state.network_runtime is not None
            ):
                return action
            self._reset_lan_lobby_state(close_runtime=True)
            return action

        if not isinstance(action, StartLanModeAction):
            return action

        self._ensure_lan_debug_log_started()
        pending = self._pending_session()
        if pending is None:
            self.state.network_last_error = "LAN session is not configured."
            lan_debug_log("lan_action_error", action=action_label(action), reason=str(self.state.network_last_error))
            return None

        cfg = pending.config
        expected_mode = action.mode
        if str(cfg.mode) != expected_mode:
            self.state.network_last_error = f"LAN mode mismatch: pending={cfg.mode!r} action={expected_mode!r}"
            lan_debug_log("lan_action_error", action=action_label(action), reason=str(self.state.network_last_error))
            return None

        sim_status_snapshot = None
        if str(pending.role) == "host":
            from ..net.deterministic_status import status_snapshot_from_status

            sim_status_snapshot = status_snapshot_from_status(self.state.status)

        built = build_network_runtime(
            pending,
            sim_status_snapshot=sim_status_snapshot,
        )

        runtime = self.state.network_runtime
        if runtime is not None:
            runtime.close()
        self.state.network_runtime = built.runtime
        self.state.config.game_mode = int(built.mode_id)
        self.state.config.player_count = int(built.player_count)
        self.state.network_in_lobby = True
        self.state.network_expected_players = int(built.player_count)
        self.state.network_connected_players = 1 if str(pending.role) == "host" else 0
        self.state.network_waiting_for_players = True
        self.state.network_desync_count = 0
        self.state.network_resync_failure_count = 0

        if built.mode_id == GameMode.QUESTS:
            self.state.pending_quest_level = built.quest_level

        lan_debug_log(
            "lan_action_resolved",
            action=action_label(action),
            forward_action=action_label(OPEN_LAN_LOBBY),
            role=str(pending.role),
            mode=str(expected_mode),
            netcode_mode=str(built.netcode_mode),
            auto_start=bool(pending.auto_start),
            player_count=int(built.player_count),
            connected_players=int(self.state.network_connected_players),
            waiting_for_players=bool(self.state.network_waiting_for_players),
        )
        return OPEN_LAN_LOBBY

    def _resolve_gameplay_action(
        self,
        gameplay: GameplayScreen,
        action: ViewAction | None,
    ) -> ViewAction | None:
        if action == OPEN_HIGH_SCORES:
            self.state.pending_high_scores = HighScoresRequest(game_mode_id=gameplay.default_game_mode_id)
            return action
        if action == BACK_TO_MENU:
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
                    return OPEN_QUEST_RESULTS
                if outcome.kind == "failed":
                    return OPEN_QUEST_FAILED
            return BACK_TO_MENU
        return BACK_TO_MENU

    def _open_menu_action(self, action: OpenScreenAction | StartModeAction) -> None:
        self._menu.close()
        self._menu_active = False
        view = self._screens.resolve(action)
        self._open_front_view(action, view)
        self._front_active = view
        self._active = view

    def _apply_action(
        self,
        action: ViewAction | None,
        *,
        front_active: Screen | None = None,
        gameplay: GameplayScreen | None = None,
        from_menu: bool = False,
    ) -> bool:
        if action is None:
            return False
        if from_menu:
            if action == QUIT_APP:
                self.state.quit_requested = True
                return True
            if action == START_DEMO:
                self._start_demo_sequence(quit_after=False)
                return True
            if action == QUIT_AFTER_DEMO:
                self._start_demo_sequence(quit_after=True)
                return True

        action = self._resolve_lan_action(action)
        if action is None:
            return True

        if action == BACK_TO_MENU:
            assert front_active is not None
            self._return_to_menu()
            return True
        if action == BACK_TO_PREVIOUS:
            assert front_active is not None
            self._return_to_previous(front_active)
            return True
        if action == OPEN_PAUSE_MENU:
            assert front_active is not None
            self._open_pause_menu(front_active, gameplay)
            return True

        if action in {START_SURVIVAL, START_RUSH, START_TYPO}:
            mode_name = {
                START_SURVIVAL: "survival",
                START_RUSH: "rush",
                START_TYPO: "typo",
            }.get(action)
            if mode_name is not None:
                self.state.status.increment_mode_play_count(mode_name)

        if isinstance(action, (OpenScreenAction, StartModeAction)):
            if front_active is not None:
                self._transition_front_view(front_active=front_active, gameplay=gameplay, action=action)
                return True
            if from_menu:
                self._open_menu_action(action)
                return True
        return False

    def _apply_front_action(self, front_active: Screen) -> bool:
        gameplay = self._gameplay_screen(front_active)
        action = front_active.take_action()
        if gameplay is not None:
            action = self._resolve_gameplay_action(gameplay, action)
        return self._apply_action(action, front_active=front_active, gameplay=gameplay)

    def _apply_menu_action(self) -> bool:
        action = self._menu.take_action()
        if action is None:
            action = self._auto_lan_start_action()
        return self._apply_action(action, from_menu=True)

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
        if self._front_active is not None and self._apply_front_action(self._front_active):
            return
        if self._menu_active and self._apply_menu_action():
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

    def _close_front_stack(self) -> None:
        while self._front_stack:
            self._front_stack.pop().close()

    def _return_to_menu(self) -> None:
        self._capture_gameplay_ground_for_menu()
        self.state.pause_background = None
        if self._front_active is not None:
            self._front_active.close()
            self._front_active = None
        self._close_front_stack()
        self._menu.open()
        self._active = self._menu
        self._menu_active = True

    def _return_to_previous(self, front_active: Screen) -> None:
        if self._front_stack:
            front_active.close()
            previous = self._front_stack.pop()
            self._front_active = previous
            if self._gameplay_screen(previous) is not None:
                self.state.pause_background = None
            elif isinstance(previous, StatisticsMenuView):
                previous.reopen_from_child()
            self._active = previous
            return
        front_active.close()
        self._front_active = None
        self.state.pause_background = None
        self._menu.open()
        self._active = self._menu
        self._menu_active = True

    def _open_pause_menu(self, front_active: Screen, gameplay: GameplayScreen | None) -> None:
        pause_view = self._screens.screen(ScreenId.PAUSE_MENU)
        if gameplay is not None:
            self.state.pause_background = gameplay
            self._front_stack.append(front_active)
            pause_view.open()
            self._front_active = pause_view
            self._active = pause_view
            return
        if self.state.pause_background is None:
            front_active.close()
            self._front_active = None
            self._close_front_stack()
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return
        front_active.close()
        pause_view.open()
        self._front_active = pause_view
        self._active = pause_view

    def _start_demo_sequence(self, *, quit_after: bool) -> None:
        self._menu.close()
        self._menu_active = False
        self._quit_after_demo = bool(quit_after)
        self._demo.open()
        self._active = self._demo
        self._demo_active = True

    def _transition_front_view(
        self,
        *,
        front_active: Screen,
        gameplay: GameplayScreen | None,
        action: OpenScreenAction | StartModeAction,
    ) -> None:
        view = self._screens.resolve(action)
        if isinstance(action, OpenScreenAction) and action.screen in {
            ScreenId.HIGH_SCORES,
            ScreenId.WEAPON_DATABASE,
            ScreenId.PERK_DATABASE,
            ScreenId.CREDITS,
        }:
            if gameplay is not None and self.state.pause_background is None:
                self.state.pause_background = gameplay
            self._front_stack.append(front_active)
        elif isinstance(action, OpenScreenAction) and action.screen in {
            ScreenId.QUEST_RESULTS,
            ScreenId.QUEST_FAILED,
        } and gameplay is not None:
            self.state.pause_background = gameplay
            self._front_stack.append(front_active)
        else:
            if isinstance(action, StartModeAction) or (
                isinstance(action, OpenScreenAction)
                and action.screen in {
                    ScreenId.PLAY_GAME,
                    ScreenId.LAN_SESSION,
                    ScreenId.QUESTS,
                }
            ):
                self.state.pause_background = None
                self._close_front_stack()
            front_active.close()
        self._open_front_view(action, view)
        self._front_active = view
        self._active = view

    def _gameplay_screen(self, view: Screen | None) -> GameplayScreen | None:
        if view is None or not isinstance(view, GameplayScreen):
            return None
        return view

    def _open_front_view(self, action: ViewAction, view: Screen) -> None:
        gameplay = self._gameplay_screen(view)
        if gameplay is not None:
            self._open_gameplay_screen(gameplay)
        else:
            view.open()

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
