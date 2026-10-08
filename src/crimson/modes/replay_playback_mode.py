from __future__ import annotations

import msgspec

from grim import canvas
from grim.assets import (
    TextureId,
)
from grim.audio import AudioState, game_tune_command, init_audio_state, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp
from grim.music import play_music, stop_music
from grim.rand import Crand
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2
from grim.view import ViewContext

from ..game_modes import GameMode
from ..perks.ids import perk_display_name
from ..perks.selection import PerkPick
from ..quests.level import QuestLevel
from ..render.rtx.mode import mode_from_rtx_flag
from ..replay import (
    REPLAY_TICK_DT,
    REPLAY_TICK_RATE,
    Replay,
)
from ..replay.driver.playback_driver import (
    PlaybackDriver,
    build_runtime_playback_driver,
)
from ..replay.driver.playback_pump import advance_playback_frame
from ..replay.driver.setup import ReplayRunnerError
from ..screens.actions import Route, ScreenAction
from ..sim.batch_apply import (
    apply_presentation_plans,
)
from ..sim.clock import FixedStepClock
from ..sim.run_result import RunOutcome, run_result_mismatches
from ..ui.hud import (
    HUD_AMMO_BASE_POS,
    HUD_AMMO_TEXT_OFFSET,
    HudRenderContext,
    HudState,
    draw_hud_overlay,
    ui_transparency,
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
# A skip runs every tick, this many per frame, so a long one does not freeze the frame.
_SKIP_TICKS_PER_FRAME = 600
# How long a perk pick's popup stays, in seconds of the viewer's time.
_PICK_POPUP_SECONDS = 3.0
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


def open_replay_audio(config: CrimsonConfig, ctx: ViewContext, console: ConsoleState) -> AudioState:
    """Audio for a replay played outside the game (`crimson replay play`, rendering, benchmarks), the game's tunes
    queued as the game queues them; the game itself hands its own audio to the replay."""

    audio = init_audio_state(config, ctx.assets_dir, console, Crand(0))
    console.register_command("snd_addGameTune", game_tune_command(console, ctx.assets_dir, lambda: audio))
    console.exec_line("exec music/game_tunes.txt")
    return audio


class ReplayPlaybackMode:
    """Plays a replay in the game's view: in the game, a screen above the high scores that Esc leaves; standalone,
    the whole window. It never writes anything."""

    def __init__(
        self,
        ctx: ViewContext,
        *,
        replay: Replay,
        config: CrimsonConfig,
        console: ConsoleState,
        max_ticks: int | None = None,
        rtx: bool = False,
        show_replay_widget: bool = True,
        audio: AudioState | None = None,
    ) -> None:
        self._ctx = ctx
        self._config = config
        self._console = console
        self._max_ticks = max(0, int(max_ticks)) if max_ticks is not None else None
        self._rtx = bool(rtx)
        self._show_replay_widget = bool(show_replay_widget)

        self.close_requested = False

        self._replay = replay
        self._runtime: WorldRuntime | None = None
        self._small: SmallFontData | None = None
        self._hud_state = HudState()
        self._frame_dt_ms = 0.0
        self._grim_mono: GrimMonoFont | None = None
        self._quest_title = ""
        self._quest_level: QuestLevel | None = None

        self._tick_rate = 60
        self._dt = 1.0 / 60.0
        self._dt_accum = 0.0
        self._clock = FixedStepClock(tick_rate=60)
        self._tick_index = 0
        self._finished = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX

        self._driver: PlaybackDriver | None = None

        self._audio = audio
        self._audio_rng: Crand | None = None
        # The music playing when the replay opened, played again when it closes.
        self._resume_track: str | None = None
        self._skip_target: int | None = None
        # Why playback stopped before the replay's end: a tick the simulation refused.
        self._stopped_reason: str | None = None
        # At the end: whether the run reached the result it recorded.
        self._played_as_recorded: bool | None = None
        self._pick: PerkPick | None = None
        self._pick_level = 0
        self._pick_seconds = 0.0

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
        total_ticks = len(replay.ticks)
        if total_ticks <= 0:
            return 1.0
        ratio = float(self._tick_index) / float(total_ticks)
        if ratio < 0.0:
            return 0.0
        if ratio > 1.0:
            return 1.0
        return ratio

    def _draw_world(self, *, entity_alpha: float = 1.0) -> None:
        runtime = self._runtime
        if runtime is None:
            return
        runtime.draw(entity_alpha=entity_alpha)

    def _replay_widget_metrics(self) -> tuple[float, float, float, float, float]:
        screen_w = float(canvas.width())

        panel_w = _REPLAY_WIDGET_PANEL_SIZE.x
        panel_h = _REPLAY_WIDGET_PANEL_SIZE.y
        panel_x = screen_w - panel_w - float(_REPLAY_WIDGET_X_SHIFT)
        line1_y = float(_REPLAY_WIDGET_TEXT_LINE1_Y)
        panel_y = max(2.0, line1_y + _REPLAY_WIDGET_PANEL_TO_LINE1_Y)
        return panel_x, panel_y, panel_w, panel_h, line1_y

    def _draw_replay_widget(self) -> None:
        replay = self._replay

        panel_x, panel_y, panel_w, _panel_h, line1_y = self._replay_widget_metrics()
        panel_x += float(_REPLAY_WIDGET_PANEL_OFFSET_X)
        panel_y += float(_REPLAY_WIDGET_PANEL_OFFSET_Y)

        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before replay draw"
        resources = runtime.render_resources.resources

        icon_w = _REPLAY_WIDGET_ICON_SIZE.x
        icon_h = _REPLAY_WIDGET_ICON_SIZE.y
        icon_x = panel_x + 2.0 + float(_REPLAY_WIDGET_CLOCK_OFFSET_X)
        icon_y = panel_y + 8.0 + float(_REPLAY_WIDGET_CLOCK_OFFSET_Y)

        clock_table = resources.texture(TextureId.UI_CLOCK_TABLE)
        src = rl_rectangle(0.0, 0.0, float(clock_table.width), float(clock_table.height))
        dst = rl_rectangle(icon_x, icon_y, icon_w, icon_h)
        rl.draw_texture_pro(clock_table, src, dst, rl_vector2(0.0, 0.0), 0.0, rl_color(255, 255, 255, 230))

        elapsed_seconds = float(self._tick_index) / float(self._tick_rate)

        clock_pointer = resources.texture(TextureId.UI_CLOCK_POINTER)
        src = rl_rectangle(0.0, 0.0, float(clock_pointer.width), float(clock_pointer.height))
        center_x = icon_x + icon_w * 0.5
        center_y = icon_y + icon_h * 0.5
        dst = rl_rectangle(center_x, center_y, icon_w, icon_h)
        origin = rl_vector2(icon_w * 0.5, icon_h * 0.5)
        rotation = max(0.0, float(elapsed_seconds)) * 6.0
        rl.draw_texture_pro(
            clock_pointer,
            src,
            dst,
            origin,
            rotation,
            rl_color(255, 255, 255, 220),
        )

        total_ticks = len(replay.ticks)
        total_seconds = float(total_ticks) / float(self._tick_rate)
        progress_ratio = self._replay_progress_ratio()

        text_x = icon_x + icon_w + 6.0 + float(_REPLAY_WIDGET_TEXT_OFFSET_X)
        line1_y = line1_y + float(_REPLAY_WIDGET_TEXT_OFFSET_Y)
        status = "PAUSE" if self._paused else "REPLAY"
        status_color = rl_color(245, 210, 120, 230) if self._paused else rl_color(230, 230, 230, 220)
        self._draw_ui_text(
            f"{status} {self._playback_speed():.2f}x",
            Vec2(text_x, line1_y),
            status_color,
        )

        elapsed_text = self._format_time_text(elapsed_seconds)
        total_text = self._format_time_text(total_seconds)
        elapsed_w = self._measure_ui_text_width(elapsed_text)
        total_w = self._measure_ui_text_width(total_text)
        line2_y = line1_y + 18.0

        right_limit = panel_x + panel_w - 4.0 + float(_REPLAY_WIDGET_TEXT_OFFSET_X)
        total_x = right_limit - total_w
        bar_x_base = text_x + elapsed_w + 6.0
        bar_w = max(8.0, total_x - 6.0 - bar_x_base)
        bar_x = bar_x_base + float(_REPLAY_WIDGET_BAR_OFFSET_X)
        bar_y = line2_y + 5.0 + float(_REPLAY_WIDGET_BAR_OFFSET_Y)
        bar_h = _REPLAY_WIDGET_BAR_HEIGHT
        rl.draw_rectangle(int(bar_x), int(bar_y), int(bar_w), int(bar_h), rl_color(46, 67, 96, 150))
        fill_w = bar_w * progress_ratio
        if fill_w > 0.0:
            rl.draw_rectangle(int(bar_x), int(bar_y), int(fill_w), int(bar_h), rl_color(70, 130, 220, 225))

        self._draw_ui_text(
            elapsed_text,
            Vec2(text_x, line2_y),
            rl_color(220, 220, 220, 210),
        )
        self._draw_ui_text(
            total_text,
            Vec2(total_x, line2_y),
            rl_color(220, 220, 220, 210),
        )

    def open(self) -> None:
        self._small = load_small_font(self._ctx.assets_dir)
        self._hud_state = HudState()
        self._frame_dt_ms = 0.0
        self._grim_mono = None
        self._quest_title = ""

        replay = self._replay
        self._tick_rate = REPLAY_TICK_RATE
        self._dt = REPLAY_TICK_DT
        self._dt_accum = 0.0
        self._clock = FixedStepClock(tick_rate=REPLAY_TICK_RATE)
        self._tick_index = 0
        self._finished = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX
        self._driver = None

        self._audio_rng = Crand(int(replay.run.seed) & 0xFFFFFFFF)
        self._resume_track = None if self._audio is None else self._audio.music.active_track
        self._skip_target = None
        self._stopped_reason = None
        self._played_as_recorded = None
        self._pick = None

        preserve_bugs = bool(replay.run.preserve_bugs)
        rtx_mode = mode_from_rtx_flag(self._rtx)
        replay_config = msgspec.structs.replace(
            self._config,
            display=msgspec.structs.replace(
                self._config.display,
                violence_disabled=int(replay.run.violence_disabled),
            ),
        )

        runtime = WorldRuntime(
            assets_dir=self._ctx.assets_dir,
            preserve_bugs=bool(preserve_bugs),
            config=replay_config,
            audio=self._audio,
            audio_rng=self._audio_rng,
            rtx_mode=rtx_mode,
        )
        self._runtime = runtime
        runtime.reset(
            seed=int(replay.run.seed),
            player_count=int(replay.run.player_count),
        )
        runtime.open_runtime()

        try:
            self._driver = build_runtime_playback_driver(replay, max_ticks=self._max_ticks)
            driver = self._driver
            runtime.start_session(driver.session)
        except ReplayRunnerError as exc:  # pragma: no cover
            raise ValueError(f"unsupported replay game_mode_id: {int(replay.run.game_mode_id)}") from exc

        self._hud_state.preserve_bugs = bool(runtime.world.state.preserve_bugs)

        driver = self._driver
        assert driver is not None, "Replay driver must be initialized before replay view setup"
        terrain_setup = driver.terrain_setup
        if terrain_setup is not None:
            runtime.apply_terrain_setup(terrain_setup)

        quest = driver.quest_definition
        if quest is not None:
            self._quest_title = str(quest.title)
            self._quest_level = quest.level
            self._grim_mono = load_grim_mono_font(self._ctx.assets_dir)

    def close(self) -> None:
        self._small = None
        self._grim_mono = None
        self._driver = None
        if self._runtime is not None:
            self._runtime.close_runtime()
            self._runtime = None
        audio = self._audio
        if audio is not None:
            # The replay's tunes give way to the music that was playing.
            stop_music(audio.music)
            if self._resume_track is not None:
                play_music(audio.music, self._resume_track)
        self._audio_rng = None

    def take_action(self) -> ScreenAction | None:
        if not self.close_requested:
            return None
        self.close_requested = False
        return Route.BACK

    def should_close(self) -> bool:
        return bool(self.close_requested)

    def consume_screenshot_request(self) -> bool:
        return False

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color) -> None:
        font = self._small
        assert font is not None, "small font must be loaded before replay ui draw"
        draw_small_text(font, text, pos, color)

    def _measure_ui_text_width(self, text: str) -> float:
        font = self._small
        assert font is not None, "small font must be loaded before replay ui measurement"
        return float(measure_small_text_width(font, text))

    def _tick_limit(self) -> int:
        replay = self._replay
        total_ticks = len(replay.ticks)
        if self._max_ticks is None:
            return int(total_ticks)
        return min(int(total_ticks), max(0, int(self._max_ticks)))

    def _mark_finished_if_complete(self) -> None:
        tick_limit = int(self._tick_limit())
        if int(self._tick_index) < int(tick_limit):
            return
        self._finished = True
        driver = self._driver
        if driver is not None and driver.complete:
            self._played_as_recorded = not run_result_mismatches(self._replay.result, driver.build_result())

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
            runtime=runtime,
            clock=self._clock,
            start_tick=int(self._tick_index),
            dt_seconds=float(frame_dt),
            max_ticks=max_ticks,
            tick_limit=int(tick_limit),
        )
        self._tick_index = int(advance.next_tick_index)

        apply_presentation_plans(plans=advance.plans, runtime=runtime)
        for tick_result in advance.tick_results:
            for pick in tick_result.payload.perk_picks:
                self._pick = pick
                self._pick_level = int(runtime.world.players[0].level)
                self._pick_seconds = _PICK_POPUP_SECONDS
        if advance.refused_tick is not None:
            self._stopped_reason = f"This run stops playing here (tick {advance.refused_tick})"
            self._finished = True
            return

        self._mark_finished_if_complete()
        self._dt_accum = float(self._clock.accum)

    def _playback_speed(self) -> float:
        return float(_PLAYBACK_SPEED_STEPS[int(self._speed_index)])

    def _change_speed(self, delta: int) -> None:
        idx = int(self._speed_index) + int(delta)
        idx = max(0, min(idx, len(_PLAYBACK_SPEED_STEPS) - 1))
        self._speed_index = idx

    def _skip_forward_seconds(self, seconds: float) -> None:
        if self._finished:
            return
        ticks = int(round(float(seconds) * float(self._tick_rate)))
        start = self._tick_index if self._skip_target is None else self._skip_target
        self._skip_target = min(int(self._tick_limit()), int(start) + ticks)

    def _advance_skip(self) -> None:
        """A frame of the skip: every tick runs, a bounded number per frame, with sound effects muted."""
        target = self._skip_target
        assert target is not None
        ticks = min(_SKIP_TICKS_PER_FRAME, int(target) - int(self._tick_index))
        audio_bridge = self._runtime.audio_bridge if self._runtime is not None else None
        sfx_enabled = audio_bridge.sfx_enabled if audio_bridge is not None else False
        if audio_bridge is not None:
            audio_bridge.sfx_enabled = False
        try:
            if ticks > 0:
                self._clock.reset()
                self._advance_runner(dt_seconds=float(ticks) * float(self._dt), max_ticks=ticks)
        finally:
            if audio_bridge is not None:
                audio_bridge.sfx_enabled = sfx_enabled
        if self._finished or self._tick_index >= target:
            self._skip_target = None
        self._clock.reset()
        self._dt_accum = 0.0

    def update(self, dt: float) -> None:
        self._frame_dt_ms = max(0.0, float(dt)) * 1000.0
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

        self._pick_seconds = max(0.0, self._pick_seconds - max(0.0, float(dt)))
        if self._skip_target is not None and not self._finished:
            self._advance_skip()
        elif not self._finished and bool(self._paused) and bool(self._step_once_pending):
            self._clock.reset()
            self._advance_runner(
                dt_seconds=float(self._dt),
                max_ticks=1,
            )
            self._clock.reset()
            self._step_once_pending = False
            self._dt_accum = 0.0

        elif not self._finished and (not self._paused):
            dt = float(dt)
            if dt < 0.0:
                dt = 0.0
            if dt > 0.1:
                dt = 0.1
            self._advance_runner(
                dt_seconds=dt * self._playback_speed(),
            )

        if self._audio is not None:
            update_audio(self._audio, float(dt), advance_sfx=self._paused or self._finished)


    def _draw_quest_title(self) -> None:
        replay = self._replay
        if replay.run.game_mode_id != GameMode.QUESTS:
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
            timer_ms=float(driver.quest_spawn_state.stage_banner_timer_ms),
        )

    def _draw_quest_complete_banner(self) -> None:
        replay = self._replay
        if replay.run.game_mode_id != GameMode.QUESTS:
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
            creatures=runtime.world.creatures.entries,
            names=runtime.world.state.typo.names.names,
            world_to_screen=runtime.world_to_screen,
            draw_text=self._draw_ui_text,
            measure_text_width=self._measure_ui_text_width,
        )

    def _draw_typing_box(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before Typ-o replay draw"
        driver = self._driver
        draw_typing_box(
            runtime.render_resources.resources.texture(TextureId.UI_IND_PANEL),
            text=runtime.world.state.typo.typing.text,
            game_time_s=0.0 if driver is None else float(driver.elapsed_ms) * 0.001,
            draw_text=self._draw_ui_text,
            measure_text_width=self._measure_ui_text_width,
        )

    def _draw_tutorial_overlays(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before tutorial replay draw"
        draw_tutorial_overlay_panels(
            runtime.world.state.tutorial_overlay,
            draw_text=self._draw_ui_text,
            measure_text_width=self._measure_ui_text_width,
            measure_line_height=lambda: int(
                self._small.cell_size if self._small is not None else 20,
            ),
        )

    def draw(self) -> None:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before replay draw"
        replay = self._replay
        world = runtime.world
        players = world.players
        assert players, "Replay runtime must have at least one player before draw"
        self._draw_world()
        runtime.draw_aim_indicators(
            show_aim=True,
            aim_enhancement_fade=clamp(self._console.cvars["cv_aimEnhancementFade"].value_f, 0.0, 1.0),
        )
        mode_id = replay.run.game_mode_id
        # Native draws the labels and the typing panel every Typ-o frame, the dying ones too.
        show_typo_ui = mode_id == GameMode.TYPO
        quest_progress_ratio: float | None = None
        elapsed_ms = float(runtime.presentation_elapsed_ms)
        match mode_id:
            case GameMode.QUESTS:
                quest_spawn = None if self._driver is None else self._driver.quest_spawn_state
                total = 0 if quest_spawn is None else quest_spawn.total_creatures
                kills = int(world.creatures.kill_count)
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
                alpha=ui_transparency(self._console.cvars["cv_uiTransparency"].value_f),
                game_mode=mode_id,
                small_indicators=self._console.cvars["cv_uiSmallIndicators"].value_f != 0.0,
            ),
            players=players,
            bonus_hud=world.state.bonus_hud,
            elapsed_ms=elapsed_ms,
            # The frame's own delta, as live play uses: offline renders must not
            # depend on how fast the machine draws.
            frame_dt_ms=self._frame_dt_ms,
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
            if self._pick is not None and self._pick_seconds > 0.0:
                self._draw_pick_popup(self._pick)
            if self._finished:
                self._draw_result_panel()

    def _draw_panel(self, x: float, y: float, w: float, h: float) -> None:
        rl.draw_rectangle(int(x), int(y), int(w), int(h), rl_color(0, 0, 0, 190))
        rl.draw_rectangle_lines(int(x), int(y), int(w), int(h), rl_color(120, 120, 140, 200))

    def _draw_pick_popup(self, pick: PerkPick) -> None:
        """The perks the menu offered at a pick, the chosen one highlighted, beside the play area."""
        violence_disabled = int(self._replay.run.violence_disabled)
        line_h = 16.0
        x, y = 12.0, float(canvas.height()) * 0.5 - (len(pick.offered) + 1) * line_h * 0.5
        self._draw_panel(x - 6.0, y - 6.0, 230.0, (len(pick.offered) + 1) * line_h + 12.0)
        fade = min(1.0, self._pick_seconds / 0.5)
        self._draw_ui_text(f"Level {self._pick_level}: perk picked", Vec2(x, y), rl_color(230, 230, 230, int(230 * fade)))
        for index, perk_id in enumerate(pick.offered):
            chosen = index == pick.chosen
            color = rl_color(128, 255, 153, int(255 * fade)) if chosen else rl_color(150, 150, 160, int(200 * fade))
            name = perk_display_name(perk_id, violence_disabled=violence_disabled)
            self._draw_ui_text(f"{'>' if chosen else ' '} {name}", Vec2(x, y + line_h * (index + 1)), color)

    def _draw_result_panel(self) -> None:
        """At the end: how the run ended, its score and time, and whether it played as recorded."""
        result = self._replay.result
        seconds = (result.quest_final_ms if result.quest_final_ms is not None else result.elapsed_ms) / 1000.0
        ending = {
            RunOutcome.DEATH: f"Died at {self._format_time_text(result.elapsed_ms / 1000.0)}",
            RunOutcome.QUEST_COMPLETED: f"Quest completed, final time {seconds:.2f} s",
            RunOutcome.TUTORIAL_COMPLETED: "Tutorial completed",
            RunOutcome.INCOMPLETE: "Left before the end",
        }[RunOutcome(result.outcome)]
        lines = [
            (ending, rl_color(230, 230, 230, 240)),
            (f"Experience {result.players[0].experience if result.players else 0}, kills {result.kills}", rl_color(200, 200, 210, 230)),
        ]
        if self._stopped_reason is not None:
            lines.append((self._stopped_reason, rl_color(255, 128, 128, 240)))
        elif self._played_as_recorded is False:
            lines.append(("This run played differently", rl_color(255, 128, 128, 240)))
        elif self._played_as_recorded:
            lines.append(("Played as recorded", rl_color(128, 255, 153, 240)))
        lines.append(("Esc returns", rl_color(150, 150, 160, 220)))
        line_h = 18.0
        w = max(self._measure_ui_text_width(text) for text, _ in lines) + 24.0
        x = (float(canvas.width()) - w) * 0.5
        y = float(canvas.height()) * 0.5 - len(lines) * line_h * 0.5
        self._draw_panel(x, y - 8.0, w, len(lines) * line_h + 12.0)
        for index, (text, color) in enumerate(lines):
            self._draw_ui_text(text, Vec2(x + 12.0, y + index * line_h), color)
