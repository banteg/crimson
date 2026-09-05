from __future__ import annotations

from pathlib import Path

from grim import music as grim_music
from grim.assets import (
    TextureId,
)
from grim.audio import AudioState, init_audio_state, shutdown_audio, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..quests.level import QuestLevel
from ..render.rtx.mode import mode_from_rtx_flag
from ..replay import (
    Replay,
    load_replay_file,
    warn_on_game_version_mismatch,
)
from ..replay.driver.playback_driver import (
    PlaybackDriver,
    build_runtime_playback_driver,
)
from ..replay.driver.playback_pump import advance_playback_frame
from ..replay.driver.setup import ReplayRunnerError
from ..sim.batch_apply import (
    apply_presentation_outputs,
)
from ..sim.clock import FixedStepClock
from ..ui.hud import (
    HUD_AMMO_BASE_POS,
    HUD_AMMO_TEXT_OFFSET,
    HudRenderContext,
    HudState,
    draw_hud_overlay,
    hud_flags_for_game_mode,
    hud_ui_scale,
)
from ..ui.overlays.quest_run import (
    draw_quest_complete_banner_overlay,
    draw_quest_title_timer_overlay,
)
from ..ui.overlays.tutorial_run import draw_tutorial_overlay_panels
from ..ui.overlays.typo_run import draw_typing_box, draw_typo_name_labels
from ..world.runtime import WorldRuntime

_PLAYBACK_SPEED_STEPS: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
_DEFAULT_SPEED_INDEX = 2
_SKIP_SHORT_SECONDS = 5.0
_SKIP_LONG_SECONDS = 30.0
_REPLAY_WIDGET_PANEL_SIZE = Vec2(182.0, 53.0)
_REPLAY_WIDGET_ICON_SIZE = Vec2(32.0, 32.0)
_REPLAY_WIDGET_BAR_HEIGHT = 4.0
_REPLAY_WIDGET_X_SHIFT = 10.0
_REPLAY_WIDGET_TEXT_LINE1_Y = HUD_AMMO_BASE_POS[1] + HUD_AMMO_TEXT_OFFSET[1]
_REPLAY_WIDGET_PANEL_TO_LINE1_Y = -7.0
_REPLAY_WIDGET_PANEL_OFFSET_X = 0.0
_REPLAY_WIDGET_PANEL_OFFSET_Y = 0.0
_REPLAY_WIDGET_CLOCK_OFFSET_X = 0.0
_REPLAY_WIDGET_CLOCK_OFFSET_Y = 0.0
_REPLAY_WIDGET_TEXT_OFFSET_X = 0.0
_REPLAY_WIDGET_TEXT_OFFSET_Y = 0.0
_REPLAY_WIDGET_BAR_OFFSET_X = 0.0
_REPLAY_WIDGET_BAR_OFFSET_Y = 0.0


class ReplayPlaybackMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        replay_path: Path,
        config: CrimsonConfig,
        console: ConsoleState,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        rtx: bool = False,
        show_replay_widget: bool = True,
    ) -> None:
        self._ctx = ctx
        self._replay_path = Path(replay_path)
        self._config = config
        self._console = console
        self._max_ticks = max(0, int(max_ticks)) if max_ticks is not None else None
        self._trace_rng = bool(trace_rng)
        self._rtx = bool(rtx)
        self._show_replay_widget = bool(show_replay_widget)

        self.close_requested = False

        self._replay: Replay | None = None
        self._runtime: WorldRuntime | None = None
        self._small: SmallFontData | None = None
        self._hud_state = HudState()
        self._grim_mono: GrimMonoFont | None = None
        self._quest_title = ""
        self._quest_level: QuestLevel | None = None

        self._tick_rate = 60
        self._dt = 1.0 / 60.0
        self._dt_accum = 0.0
        self._clock = FixedStepClock(tick_rate=60)
        self._frame_index = 0
        self._tick_index = 0
        self._finished = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX

        self._driver: PlaybackDriver | None = None
        self._quest_total_spawn_count = 0

        self._audio: AudioState | None = None
        self._audio_rng: Crand | None = None

    @property
    def tick_index(self) -> int:
        return int(self._tick_index)

    @property
    def finished(self) -> bool:
        return bool(self._finished)

    @staticmethod
    def _format_time_text(seconds: float) -> str:
        total_seconds = max(0, int(seconds))
        minutes = total_seconds // 60
        rem_seconds = total_seconds % 60
        return f"{minutes}:{rem_seconds:02d}"

    def _replay_progress_ratio(self) -> float:
        replay = self._replay
        if replay is None:
            return 0.0
        total_ticks = len(replay.ticks)
        if total_ticks <= 0:
            return 1.0
        ratio = float(self._tick_index) / float(total_ticks)
        if ratio < 0.0:
            return 0.0
        if ratio > 1.0:
            return 1.0
        return ratio

    def _register_replay_audio_commands(self) -> None:
        console = self._console

        def cmd_snd_add_game_tune(args: list[str]) -> None:
            if len(args) != 1:
                console.log.log("snd_addGameTune <tuneName.ogg>")
                return
            audio = self._audio
            if audio is None:
                return
            rel_path = f"music/{args[0]}"
            result = grim_music.load_music_track(audio.music, self._ctx.assets_dir, rel_path, console=console)
            if result is None:
                return
            track_key, _track_id = result
            grim_music.queue_track(audio.music, track_key)

        console.register_command("snd_addGameTune", cmd_snd_add_game_tune)

    def _load_game_tune_queue(self) -> None:
        if self._audio is None:
            return
        self._console.exec_line("exec music/game_tunes.txt")

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        runtime = self._runtime
        if runtime is None:
            return
        runtime.draw(
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def _replay_widget_metrics(self) -> tuple[float, float, float, float, float, float]:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = hud_ui_scale(screen_w, screen_h)

        panel_w = _REPLAY_WIDGET_PANEL_SIZE.x * scale
        panel_h = _REPLAY_WIDGET_PANEL_SIZE.y * scale
        panel_x = screen_w - panel_w - float(_REPLAY_WIDGET_X_SHIFT) * scale
        line1_y = float(_REPLAY_WIDGET_TEXT_LINE1_Y) * scale
        panel_y = max(2.0 * scale, line1_y + _REPLAY_WIDGET_PANEL_TO_LINE1_Y * scale)
        return scale, panel_x, panel_y, panel_w, panel_h, line1_y

    def _draw_replay_widget(self) -> None:
        replay = self._replay
        if replay is None:
            return

        scale, panel_x, panel_y, panel_w, _panel_h, line1_y = self._replay_widget_metrics()
        panel_x += float(_REPLAY_WIDGET_PANEL_OFFSET_X) * scale
        panel_y += float(_REPLAY_WIDGET_PANEL_OFFSET_Y) * scale

        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before replay draw"
        resources = runtime.render_resources.resources

        icon_w = _REPLAY_WIDGET_ICON_SIZE.x * scale
        icon_h = _REPLAY_WIDGET_ICON_SIZE.y * scale
        icon_x = panel_x + 2.0 * scale + float(_REPLAY_WIDGET_CLOCK_OFFSET_X) * scale
        icon_y = panel_y + 8.0 * scale + float(_REPLAY_WIDGET_CLOCK_OFFSET_Y) * scale

        clock_table = resources.texture(TextureId.UI_CLOCK_TABLE)
        src = rl.Rectangle(0.0, 0.0, float(clock_table.width), float(clock_table.height))
        dst = rl.Rectangle(icon_x, icon_y, icon_w, icon_h)
        rl.draw_texture_pro(clock_table, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.Color(255, 255, 255, 230))

        elapsed_seconds = float(self._tick_index) / float(self._tick_rate)

        clock_pointer = resources.texture(TextureId.UI_CLOCK_POINTER)
        src = rl.Rectangle(0.0, 0.0, float(clock_pointer.width), float(clock_pointer.height))
        center_x = icon_x + icon_w * 0.5
        center_y = icon_y + icon_h * 0.5
        dst = rl.Rectangle(center_x, center_y, icon_w, icon_h)
        origin = rl.Vector2(icon_w * 0.5, icon_h * 0.5)
        rotation = max(0.0, float(elapsed_seconds)) * 6.0
        rl.draw_texture_pro(
            clock_pointer,
            src,
            dst,
            origin,
            rotation,
            rl.Color(255, 255, 255, 220),
        )

        total_ticks = len(replay.ticks)
        total_seconds = float(total_ticks) / float(self._tick_rate)
        progress_ratio = self._replay_progress_ratio()

        text_x = icon_x + icon_w + 6.0 * scale + float(_REPLAY_WIDGET_TEXT_OFFSET_X) * scale
        line1_y = line1_y + float(_REPLAY_WIDGET_TEXT_OFFSET_Y) * scale
        text_scale = 1.0
        status = "PAUSE" if self._paused else "REPLAY"
        status_color = rl.Color(245, 210, 120, 230) if self._paused else rl.Color(230, 230, 230, 220)
        self._draw_ui_text(
            f"{status} {self._playback_speed():.2f}x",
            Vec2(text_x, line1_y),
            status_color,
            scale=text_scale,
        )

        elapsed_text = self._format_time_text(elapsed_seconds)
        total_text = self._format_time_text(total_seconds)
        elapsed_w = self._measure_ui_text_width(elapsed_text, scale=text_scale)
        total_w = self._measure_ui_text_width(total_text, scale=text_scale)
        line2_y = line1_y + 18.0 * scale

        right_limit = panel_x + panel_w - 4.0 * scale + float(_REPLAY_WIDGET_TEXT_OFFSET_X) * scale
        total_x = right_limit - total_w
        bar_x_base = text_x + elapsed_w + 6.0 * scale
        bar_w = max(8.0 * scale, total_x - 6.0 * scale - bar_x_base)
        bar_x = bar_x_base + float(_REPLAY_WIDGET_BAR_OFFSET_X) * scale
        bar_y = line2_y + 5.0 * scale + float(_REPLAY_WIDGET_BAR_OFFSET_Y) * scale
        bar_h = _REPLAY_WIDGET_BAR_HEIGHT * scale
        rl.draw_rectangle(int(bar_x), int(bar_y), int(bar_w), int(bar_h), rl.Color(46, 67, 96, 150))
        fill_w = bar_w * progress_ratio
        if fill_w > 0.0:
            rl.draw_rectangle(int(bar_x), int(bar_y), int(fill_w), int(bar_h), rl.Color(70, 130, 220, 225))

        self._draw_ui_text(
            elapsed_text,
            Vec2(text_x, line2_y),
            rl.Color(220, 220, 220, 210),
            scale=text_scale,
        )
        self._draw_ui_text(
            total_text,
            Vec2(total_x, line2_y),
            rl.Color(220, 220, 220, 210),
            scale=text_scale,
        )

    def open(self) -> None:
        self._small = load_small_font(self._ctx.assets_dir)
        self._hud_state = HudState()
        self._grim_mono = None
        self._quest_title = ""

        replay = load_replay_file(self._replay_path)
        self._replay = replay
        warn_on_game_version_mismatch(replay, action="playback")

        tick_rate = int(replay.header.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"invalid tick_rate: {tick_rate}")
        self._tick_rate = tick_rate
        self._dt = 1.0 / float(tick_rate)
        self._dt_accum = 0.0
        self._clock = FixedStepClock(tick_rate=int(tick_rate))
        self._frame_index = 0
        self._tick_index = 0
        self._finished = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX
        self._driver = None

        world_size = float(replay.header.world_size)
        audio = init_audio_state(self._config, self._ctx.assets_dir, self._console)
        audio_rng = Crand(int(replay.header.seed) & 0xFFFFFFFF)
        self._audio = audio
        self._audio_rng = audio_rng
        self._register_replay_audio_commands()
        self._load_game_tune_queue()

        quest_fail_retry_count = int(replay.header.quest_fail_retry_count)
        hardcore = bool(replay.header.hardcore)
        preserve_bugs = bool(replay.header.preserve_bugs)
        rtx_mode = mode_from_rtx_flag(self._rtx)

        runtime = WorldRuntime(
            assets_dir=self._ctx.assets_dir,
            world_size=float(world_size),
            demo_mode_active=False,
            quest_fail_retry_count=int(quest_fail_retry_count),
            hardcore=bool(hardcore),
            preserve_bugs=bool(preserve_bugs),
            config=self._config,
            audio=self._audio,
            audio_rng=self._audio_rng,
            rtx_mode=rtx_mode,
        )
        self._runtime = runtime
        runtime.reset(
            seed=int(replay.header.seed),
            player_count=int(replay.header.player_count),
        )
        runtime.open_runtime()

        sim_world = runtime.sim_world
        try:
            self._driver = build_runtime_playback_driver(
                replay,
                max_ticks=self._max_ticks,
                trace_rng=bool(self._trace_rng),
                world_size=float(world_size),
            )
            driver = self._driver
            sim_world.load_world_state(driver.world)
        except ReplayRunnerError as exc:  # pragma: no cover
            raise ValueError(f"unsupported replay game_mode_id: {int(replay.header.game_mode_id)}") from exc

        self._hud_state.preserve_bugs = bool(sim_world.state.preserve_bugs)

        driver = self._driver
        assert driver is not None, "Replay driver must be initialized before replay view setup"
        terrain_setup = driver.terrain_setup
        if terrain_setup is not None:
            runtime.terrain_runtime.apply_terrain_setup(
                terrain_slots=terrain_setup.terrain_slots,
                seed=int(terrain_setup.terrain_seed),
            )

        quest = driver.quest_definition
        if quest is not None:
            self._quest_title = str(quest.title)
            self._quest_level = quest.level
            self._grim_mono = load_grim_mono_font(self._ctx.assets_dir)
            self._quest_total_spawn_count = int(driver.quest_total_spawn_count)
        else:
            self._quest_total_spawn_count = 0

    def close(self) -> None:
        self._small = None
        self._grim_mono = None
        self._driver = None
        if self._runtime is not None:
            self._runtime.close_runtime()
            self._runtime = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None
            self._audio_rng = None

    def should_close(self) -> bool:
        return bool(self.close_requested)

    def consume_screenshot_request(self) -> bool:
        return False

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color, *, scale: float = 1.0) -> None:
        _ = scale
        font = self._small
        assert font is not None, "small font must be loaded before replay ui draw"
        draw_small_text(font, text, pos, color)

    def _measure_ui_text_width(self, text: str, *, scale: float = 1.0) -> float:
        _ = scale
        font = self._small
        assert font is not None, "small font must be loaded before replay ui measurement"
        return float(measure_small_text_width(font, text))

    def _tick_limit(self) -> int:
        replay = self._replay
        if replay is None:
            return 0
        total_ticks = len(replay.ticks)
        if self._max_ticks is None:
            return int(total_ticks)
        return min(int(total_ticks), max(0, int(self._max_ticks)))

    def _mark_finished_if_complete(self) -> None:
        tick_limit = int(self._tick_limit())
        if int(self._tick_index) < int(tick_limit):
            return
        self._finished = True

    def _advance_runner(
        self,
        *,
        dt_seconds: float,
        max_ticks: int | None = None,
    ) -> None:
        replay = self._replay
        runtime = self._runtime
        driver = self._driver
        if replay is None or runtime is None or driver is None:
            self._finished = True
            return
        tick_limit = int(self._tick_limit())
        if int(self._tick_index) >= tick_limit:
            self._mark_finished_if_complete()
            return

        frame_dt = float(dt_seconds)
        advance = advance_playback_frame(
            driver=driver,
            sim_world=runtime.sim_world,
            clock=self._clock,
            start_tick=int(self._tick_index),
            frame_index=int(self._frame_index),
            dt_seconds=float(frame_dt),
            max_ticks=max_ticks,
            tick_limit=int(tick_limit),
            game_tune_started=bool(driver.session.game_tune_started),
        )
        self._frame_index = int(advance.frame_index)
        self._tick_index = int(advance.next_tick_index)

        apply_presentation_outputs(outputs=advance.outputs, runtime=runtime, apply_audio=True)

        self._mark_finished_if_complete()
        self._dt_accum = float(self._clock.accum)

    def _playback_speed(self) -> float:
        return float(_PLAYBACK_SPEED_STEPS[int(self._speed_index)])

    def _change_speed(self, delta: int) -> None:
        idx = int(self._speed_index) + int(delta)
        idx = max(0, min(idx, len(_PLAYBACK_SPEED_STEPS) - 1))
        self._speed_index = idx

    def _skip_forward_seconds(self, seconds: float) -> None:
        replay = self._replay
        if replay is None or self._finished:
            return
        ticks = int(round(float(seconds) * float(self._tick_rate)))
        if ticks <= 0:
            return
        target = min(int(self._tick_limit()), int(self._tick_index) + int(ticks))
        audio_bridge = self._runtime.audio_bridge if self._runtime is not None else None
        prev_sfx_enabled: bool | None = None
        if audio_bridge is not None:
            prev_sfx_enabled = bool(audio_bridge.sfx_enabled)
            audio_bridge.sfx_enabled = False
        try:
            ticks_to_advance = max(0, int(target) - int(self._tick_index))
            if ticks_to_advance > 0:
                self._advance_runner(
                    dt_seconds=float(ticks_to_advance) * float(self._dt),
                    max_ticks=int(ticks_to_advance),
                )
        finally:
            if prev_sfx_enabled is not None and audio_bridge is not None:
                audio_bridge.sfx_enabled = bool(prev_sfx_enabled)
        self._clock.reset()
        self._dt_accum = 0.0

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not bool(self._paused)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD) and bool(self._paused):
            self._step_once_pending = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._change_speed(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._change_speed(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._speed_index = _DEFAULT_SPEED_INDEX
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._skip_forward_seconds(_SKIP_SHORT_SECONDS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._skip_forward_seconds(_SKIP_LONG_SECONDS)

        if not self._finished and bool(self._paused) and bool(self._step_once_pending):
            self._clock.reset()
            self._advance_runner(
                dt_seconds=float(self._dt),
                max_ticks=1,
            )
            self._clock.reset()
            self._step_once_pending = False
            self._dt_accum = 0.0

        if not self._finished and (not self._paused):
            dt = float(dt)
            if dt < 0.0:
                dt = 0.0
            if dt > 0.1:
                dt = 0.1
            self._advance_runner(
                dt_seconds=dt * self._playback_speed(),
            )

        if self._audio is not None:
            update_audio(self._audio, float(dt))

        # Runtime open schedules terrain generation, but replay advances
        # deterministic world ticks directly, so we must process pending ground
        # work explicitly.
        if self._runtime is not None:
            ground = self._runtime.render_resources.ground
            if ground is not None:
                ground.process_pending()

    def _draw_quest_title(self) -> None:
        replay = self._replay
        if replay is None or replay.header.game_mode_id != GameMode.QUESTS:
            return
        font = self._grim_mono
        if font is None:
            return
        title = str(self._quest_title or "")
        level = self._quest_level
        if not title or level is None:
            return
        driver = self._driver
        if driver is None or driver.quest_spawn_state is None:
            return

        draw_quest_title_timer_overlay(
            font,
            title,
            level.text,
            timer_ms=float(driver.quest_spawn_state.spawn_timeline_ms),
        )

    def _draw_quest_complete_banner(self) -> None:
        replay = self._replay
        if replay is None or replay.header.game_mode_id != GameMode.QUESTS:
            return
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before replay quest banner draw"
        driver = self._driver
        if driver is None or driver.quest_spawn_state is None:
            return
        draw_quest_complete_banner_overlay(
            runtime.render_resources.resources.texture(TextureId.UI_TEXT_LEVEL_COMPLETE),
            timer_ms=float(driver.quest_spawn_state.completion_transition_ms),
        )

    def _draw_typo_name_labels(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before Typ-o replay draw"
        draw_typo_name_labels(
            creatures=runtime.sim_world.creatures.entries,
            names=runtime.sim_world.state.typo.names.names,
            world_to_screen=runtime.renderer.world_to_screen,
            draw_text=lambda text, pos, color, scale: self._draw_ui_text(text, pos, color, scale=scale),
            measure_text_width=lambda text, scale: float(self._measure_ui_text_width(text, scale=scale)),
        )

    def _draw_typing_box(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before Typ-o replay draw"
        driver = self._driver
        cursor_pulse_time = 0.0 if driver is None else float(driver.elapsed_ms) * 0.001
        draw_typing_box(
            runtime.render_resources.resources.texture(TextureId.UI_IND_PANEL),
            text=runtime.sim_world.state.typo.typing.text,
            cursor_pulse_time=float(cursor_pulse_time),
            draw_text=lambda text, pos, color, scale: self._draw_ui_text(text, pos, color, scale=scale),
            measure_text_width=lambda text, scale: float(self._measure_ui_text_width(text, scale=scale)),
        )

    def _draw_tutorial_overlays(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before tutorial replay draw"
        draw_tutorial_overlay_panels(
            runtime.sim_world.state.tutorial_overlay,
            draw_text=lambda text, pos, color, scale: self._draw_ui_text(text, pos, color, scale=scale),
            measure_text_width=lambda text, scale: float(self._measure_ui_text_width(text, scale=scale)),
            measure_line_height=lambda scale: int(
                self._small.cell_size * scale if self._small is not None else 20 * scale,
            ),
        )

    def draw(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before replay draw"
        replay = self._replay
        assert replay is not None, "Replay must be loaded before replay draw"
        sim_world = runtime.sim_world
        players = sim_world.players
        assert players, "Replay runtime must have at least one player before draw"
        self._draw_world(draw_aim_indicators=True)
        mode_id = replay.header.game_mode_id
        show_typo_ui = mode_id == GameMode.TYPO and players[0].health > 0.0
        hud_flags = hud_flags_for_game_mode(mode_id)
        quest_progress_ratio: float | None = None
        elapsed_ms = float(sim_world.presentation_elapsed_ms)
        match mode_id:
            case GameMode.QUESTS:
                total = int(self._quest_total_spawn_count)
                kills = int(sim_world.creatures.kill_count)
                quest_progress_ratio = float(kills) / float(total) if total > 0 else None
                driver = self._driver
                if driver is not None:
                    elapsed_ms = float(driver.elapsed_ms)
            case _:
                driver = self._driver
                if driver is not None:
                    elapsed_ms = float(driver.elapsed_ms)
        if show_typo_ui:
            self._draw_typo_name_labels()
        draw_hud_overlay(
            HudRenderContext(
                resources=runtime.render_resources.resources,
                state=self._hud_state,
                font=self._small,
                show_health=bool(hud_flags.show_health),
                show_weapon=bool(hud_flags.show_weapon),
                show_xp=bool(hud_flags.show_xp),
                show_time=bool(hud_flags.show_time),
                show_quest_hud=bool(hud_flags.show_quest_hud),
                small_indicators=False,
            ),
            player=players[0],
            players=players,
            bonus_hud=sim_world.state.bonus_hud,
            elapsed_ms=elapsed_ms,
            frame_dt_ms=float(max(0.0, rl.get_frame_time()) * 1000.0),
            quest_progress_ratio=quest_progress_ratio,
        )

        self._draw_quest_title()
        self._draw_quest_complete_banner()
        if mode_id == GameMode.TUTORIAL:
            self._draw_tutorial_overlays()
        if show_typo_ui:
            self._draw_typing_box()

        if bool(self._show_replay_widget):
            self._draw_replay_widget()
