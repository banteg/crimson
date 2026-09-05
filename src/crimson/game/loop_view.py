from __future__ import annotations

import webbrowser

from crimson.screens.chrome import ensure_menu_ground
from grim.raylib_api import rl

from ..debug import debug_enabled
from ..demo_trial import demo_trial_overlay_info, tick_demo_trial_timers
from ..game_modes import GameMode
from ..input_codes import input_begin_frame
from ..modes.quest_mode import QuestMode
from ..render.rtx.mode import RtxRenderMode, cycle_rtx_render_mode
from ..screens.actions import Route, ScreenAction, ShowQuestOutcome
from ..screens.transitions import _update_screen_fade
from ..sim.timing import ftol_ms_i32
from ..ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayInfo, DemoTrialOverlayUi
from .navigation import ScreenNavigator
from .resources import GameResources
from .types import GameplayScreen, GameState

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
        self.navigation = ScreenNavigator(state)
        self.resources = GameResources(state)
        self._demo_trial_overlay: DemoTrialOverlayUi | None = None
        self._demo_trial_info: DemoTrialOverlayInfo | None = None
        self._screenshot_requested = False
        self._runtime_updates_per_frame = 0
        self._gamma_shader: rl.Shader | None = None
        self._gamma_gain_loc = -1
        self._gamma_target: rl.RenderTexture | None = None

    def open(self) -> None:
        rl.hide_cursor()
        self.resources.open()
        self.navigation.open()

    def _demo_trial_overlay_view(self) -> DemoTrialOverlayUi:
        overlay = self._demo_trial_overlay
        if overlay is None:
            overlay = DemoTrialOverlayUi(self.state.assets_dir)
            self._demo_trial_overlay = overlay
        return overlay

    def should_close(self) -> bool:
        return self.state.quit_requested

    def _clear_state_frame_telemetry(self) -> None:
        self.state.input_stall_count = 0
        self.state.ticks_advanced_per_frame = 0
        self.state.sim_ms = 0.0
        self.state.presentation_plan_ms = 0.0
        self.state.presentation_apply_ms = 0.0

    def _sync_gameplay_frame_telemetry_to_state(self) -> None:
        gameplay = self.state.screens.active_gameplay
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
        self._clear_state_frame_telemetry()
        gameplay = self.state.screens.active_gameplay
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
        if gameplay is not None and self._update_demo_trial_overlay(dt):
            return

        active = self.state.screens.active
        active.update(dt)
        self._sync_gameplay_frame_telemetry_to_state()
        action = active.take_action()
        if gameplay is not None:
            action = self._resolve_gameplay_action(gameplay, action)
        if action is not None:
            self.navigation.navigate(action)
        if console.quit_requested:
            self.state.quit_requested = True
            console.quit_requested = False

    def _tick_statistics_playtime(self, dt: float) -> None:
        # Native `_play_time_ms` advances on gameplay frames only (state 9)
        # and is used by the Statistics "played for ... hours ... minutes" row.
        if self.state.demo_enabled:
            return
        if self.state.screens.active_gameplay is None:
            return
        delta_ms = ftol_ms_i32(dt)
        if delta_ms <= 0:
            return
        self.state.status.play_time_ms = (self.state.status.play_time_ms + delta_ms) & 0xFFFFFFFF

    def _sync_console_elapsed_ms(self) -> None:
        gameplay = self.state.screens.gameplay
        if gameplay is not None:
            self.state.survival_elapsed_ms = max(0.0, float(gameplay.console_elapsed_ms()))

    def _handle_console_requests(self) -> None:
        if self.state.terrain_regenerate_requested:
            self.state.terrain_regenerate_requested = False
            self._regenerate_terrain_for_console()

    def _regenerate_terrain_for_console(self) -> None:
        ensure_menu_ground(self.state, regenerate=True)
        gameplay = self.state.screens.gameplay
        if gameplay is not None:
            gameplay.regenerate_terrain_for_console()

    def _update_demo_trial_overlay(self, dt: float) -> bool:
        if not self.state.demo_enabled:
            return False
        gameplay = self.state.screens.active_gameplay

        mode_raw = self.state.config.gameplay.mode
        try:
            mode_id = GameMode(mode_raw)
        except ValueError:
            mode_id = GameMode.DEMO
        quest_level = None
        match mode_id:
            case GameMode.QUESTS:
                quest_level = self.state.config.gameplay.quest_level
            case _:
                pass

        current = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self.state.status.play_time_ms),
            quest_grace_elapsed_ms=int(self.state.demo_trial_elapsed_ms),
            quest_level=quest_level,
        )

        frame_dt = min(float(dt), 0.1)
        dt_ms = int(frame_dt * 1000.0)
        used_ms, grace_ms = tick_demo_trial_timers(
            demo_build=True,
            game_mode_id=mode_id,
            overlay_visible=bool(current.visible),
            global_playtime_ms=int(self.state.status.play_time_ms),
            quest_grace_elapsed_ms=int(self.state.demo_trial_elapsed_ms),
            dt_ms=int(dt_ms),
        )
        if used_ms != int(self.state.status.play_time_ms):
            self.state.status.play_time_ms = int(used_ms)
        self.state.demo_trial_elapsed_ms = int(grace_ms)

        info = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self.state.status.play_time_ms),
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
            self.navigation.navigate(Route.MENU)
            self._demo_trial_info = None
            return True

        return True

    def _resolve_gameplay_action(self, gameplay: GameplayScreen, action: ScreenAction | None) -> ScreenAction | None:
        if isinstance(gameplay, QuestMode):
            self.state.quest_fail_retry_count = int(gameplay.sim_world.spawn_env.quest_fail_retry_count)
        if action is not None:
            if action is Route.MENU:
                gameplay.close_requested = False
            return action
        if not gameplay.close_requested:
            return None
        gameplay.close_requested = False
        if isinstance(gameplay, QuestMode):
            outcome = gameplay.consume_outcome()
            if outcome is not None:
                return ShowQuestOutcome(outcome)
        return Route.MENU

    def _set_rtx_mode(self, mode: RtxRenderMode, *, source: str) -> None:
        if mode is self.state.rtx_mode:
            return
        self.state.rtx_mode = mode
        self._sync_rtx_mode()
        self.state.console.log.log(f"render mode: {mode.value} ({source})")

    def _sync_rtx_mode(self) -> None:
        gameplay = self.state.screens.gameplay
        if gameplay is not None:
            gameplay.set_rtx_mode(self.state.rtx_mode)

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def _draw_scene_layers(self) -> None:
        self.state.screens.active.draw()
        info = self._demo_trial_info
        if info is not None and bool(info.visible):
            self._demo_trial_overlay_view().draw(info)
        self.state.console.draw()
        self.state.console.draw_fps_counter()

    def _ensure_gamma_resources(self, width: int, height: int) -> None:
        if self._gamma_shader is None:
            shader = rl.load_shader_from_memory(_GAMMA_RAMP_VS_330, _GAMMA_RAMP_FS_330)
            if shader.id <= 0:
                raise RuntimeError("gamma shader compilation returned an invalid shader id")
            try:
                gain_loc = rl.get_shader_location(shader, "u_gamma_gain")
                if gain_loc < 0:
                    raise RuntimeError("gamma shader is missing its gain uniform")
            except Exception:
                rl.unload_shader(shader)
                raise
            self._gamma_shader = shader
            self._gamma_gain_loc = gain_loc
        target = self._gamma_target
        if target is not None and target.texture.width == width and target.texture.height == height:
            return
        candidate = rl.load_render_texture(width, height)
        if candidate.id <= 0 or not rl.rl_framebuffer_complete(candidate.id):
            rl.unload_render_texture(candidate)
            raise RuntimeError("gamma render target is incomplete")
        if target is not None:
            rl.unload_render_texture(target)
        self._gamma_target = candidate

    def _close_gamma_resources(self) -> None:
        if self._gamma_target is not None:
            rl.unload_render_texture(self._gamma_target)
            self._gamma_target = None
        if self._gamma_shader is not None:
            rl.unload_shader(self._gamma_shader)
            self._gamma_shader = None
        self._gamma_gain_loc = -1

    def _draw_with_gamma(self) -> None:
        gamma_gain = max(0.0, float(self.state.gamma_ramp))
        if abs(gamma_gain - 1.0) <= 1e-6:
            self._draw_scene_layers()
            return

        screen_w, screen_h = rl.get_screen_width(), rl.get_screen_height()
        render_w, render_h = rl.get_render_width(), rl.get_render_height()
        if min(screen_w, screen_h, render_w, render_h) <= 0:
            return
        self._ensure_gamma_resources(render_w, render_h)
        target, shader = self._gamma_target, self._gamma_shader
        assert target is not None and shader is not None
        # Inner world/UI shaders may change the shader binding. Capture their
        # completed frame first, then apply the native linear gamma multiplier.
        # Scale logical drawing coordinates into the full DPI-sized framebuffer.
        rl.begin_texture_mode(target)
        try:
            rl.clear_background(rl.BLACK)
            rl.rl_push_matrix()
            try:
                rl.rl_scalef(render_w / screen_w, render_h / screen_h, 1.0)
                self._draw_scene_layers()
            finally:
                rl.rl_pop_matrix()
        finally:
            rl.end_texture_mode()
        _set_gamma_ramp_gain(shader, self._gamma_gain_loc, gamma_gain)
        rl.begin_shader_mode(shader)
        try:
            rl.draw_texture_pro(
                target.texture,
                rl.Rectangle(0.0, 0.0, float(render_w), -float(render_h)),
                rl.Rectangle(0.0, 0.0, float(screen_w), float(screen_h)),
                rl.Vector2(0.0, 0.0), 0.0, rl.WHITE,
            )
        finally:
            rl.end_shader_mode()

    def draw(self) -> None:
        self._draw_with_gamma()

    def close(self) -> None:
        try:
            self.state.screens.close()
            if self._demo_trial_overlay is not None:
                self._demo_trial_overlay.close()
            ground = self.state.menu_ground
            if ground is not None:
                ground.close()
        finally:
            self._close_gamma_resources()
            self.resources.close()
            self.state.console.close()
            rl.show_cursor()
