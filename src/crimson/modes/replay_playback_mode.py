from __future__ import annotations

import msgspec

from grim.assets import TextureId
from grim.audio import AudioState, game_tune_command, init_audio_state, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp
from grim.music import resume_music, stop_music
from grim.rand import Crand, CrandLike
from grim.raylib_api import rl
from grim.view import ViewContext

from ..camera import CameraUpdate
from ..game_modes import GameMode
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
from ..replay.driver.prepare import Keyframe, restore_keyframe
from ..replay.driver.setup import ReplayRunnerError
from ..sim.batch_apply import (
    apply_presentation_plans,
)
from ..sim.clock import FixedStepClock
from ..sim.run_result import run_result_mismatches
from ..ui.hud import (
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


def open_replay_audio(config: CrimsonConfig, ctx: ViewContext, console: ConsoleState) -> AudioState:
    """Audio for a replay played outside the game (`crimson replay play`, rendering, benchmarks), the game's tunes
    queued as the game queues them; the game itself hands its own audio to the replay."""

    audio = init_audio_state(config, ctx.assets_dir, console, Crand(0))
    console.register_command("snd_addGameTune", game_tune_command(console, ctx.assets_dir, lambda: audio))
    console.exec_line("exec music/game_tunes.txt")
    return audio


class ReplayPlaybackMode:
    """Plays a replay in the game's view: the world, the HUD and the mode's own overlays. Video renders and
    benchmarks play it straight through; the viewer (`ReplayViewer`) drives it to seek. It never writes anything."""

    def __init__(
        self,
        ctx: ViewContext,
        *,
        replay: Replay,
        config: CrimsonConfig,
        console: ConsoleState,
        max_ticks: int | None = None,
        rtx: bool = False,
        audio: AudioState | None = None,
        plays_music: bool = True,
    ) -> None:
        self._ctx = ctx
        self._config = config
        self._console = console
        self._max_ticks = max(0, int(max_ticks)) if max_ticks is not None else None
        self._rtx = bool(rtx)
        # Whether the run's own music calls play; the viewer plays the tune the run has wherever it seeks.
        self._plays_music = bool(plays_music)


        self._replay = replay
        self._runtime: WorldRuntime | None = None
        self._small: SmallFontData | None = None
        self._hud_state = HudState()
        self._frame_dt_ms = 0.0
        self._grim_mono: GrimMonoFont | None = None
        self._quest_title = ""
        self._quest_level: QuestLevel | None = None

        self._dt = REPLAY_TICK_DT
        self._clock = FixedStepClock(tick_rate=REPLAY_TICK_RATE)
        self._tick_index = 0

        self._driver: PlaybackDriver | None = None

        self._audio = audio
        self._audio_rng: Crand | None = None
        # The game's music and sound effect randomness when the replay opened, given back when it closes.
        self._resume_track: str | None = None
        self._resume_game_tune_started = False
        self._resume_sfx_rng: CrandLike | None = None
        # Why playback stops before the replay's end: a tick the simulation refused, which ends the run there.
        self.stopped_reason: str | None = None
        self._stopped_tick: int | None = None
        # At the end: whether the run reached the result it recorded.
        self.played_as_recorded: bool | None = None

    @property
    def tick_index(self) -> int:
        return int(self._tick_index)

    @property
    def ticks(self) -> int:
        """The ticks the run plays: the recording's (or `max_ticks` of them), up to a tick the simulation refuses."""
        limit = len(self._replay.ticks) if self._max_ticks is None else min(len(self._replay.ticks), self._max_ticks)
        return limit if self._stopped_tick is None else min(limit, self._stopped_tick)

    @property
    def finished(self) -> bool:
        return self._tick_index >= self.ticks

    @property
    def runtime(self) -> WorldRuntime:
        runtime = self._runtime
        assert runtime is not None, "World runtime must be open before replay playback"
        return runtime

    @property
    def driver(self) -> PlaybackDriver:
        driver = self._driver
        assert driver is not None, "Replay driver must be open before replay playback"
        return driver

    def open(self) -> None:
        self._small = load_small_font(self._ctx.assets_dir)
        self._hud_state = HudState()
        self._frame_dt_ms = 0.0
        self._grim_mono = None
        self._quest_title = ""

        replay = self._replay
        self._clock = FixedStepClock(tick_rate=REPLAY_TICK_RATE)
        self._tick_index = 0
        self._driver = None

        self._audio_rng = Crand(int(replay.run.seed) & 0xFFFFFFFF)
        audio = self._audio
        if audio is not None:
            self._resume_track = audio.music.active_track
            self._resume_game_tune_started = audio.music.game_tune_started
            # The replay's sounds draw their variations from its own randomness, not the game's.
            self._resume_sfx_rng = audio.sfx.rng
            audio.sfx.rng = self._audio_rng
        self.stopped_reason = None
        self._stopped_tick = None
        self.played_as_recorded = None

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
            if self._resume_track is None:
                stop_music(audio.music)
            else:
                resume_music(audio.music, self._resume_track)
            audio.music.game_tune_started = self._resume_game_tune_started
            if self._resume_sfx_rng is not None:
                audio.sfx.rng = self._resume_sfx_rng
        self._audio_rng = None

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color) -> None:
        font = self._small
        assert font is not None, "small font must be loaded before replay ui draw"
        draw_small_text(font, text, pos, color)

    def _measure_ui_text_width(self, text: str) -> float:
        font = self._small
        assert font is not None, "small font must be loaded before replay ui measurement"
        return float(measure_small_text_width(font, text))

    def _advance(self, *, dt_seconds: float, max_ticks: int | None = None) -> int:
        """The ticks `dt_seconds` of replay time covers, at most `max_ticks`, and their presentation."""
        if self.finished:
            return 0
        runtime = self.runtime
        advance = advance_playback_frame(
            driver=self.driver,
            runtime=runtime,
            clock=self._clock,
            start_tick=int(self._tick_index),
            dt_seconds=float(dt_seconds),
            max_ticks=max_ticks,
            tick_limit=int(self.ticks),
        )
        self._tick_index = int(advance.next_tick_index)
        plans = advance.plans
        if not self._plays_music:
            plans = tuple(
                msgspec.structs.replace(plan, trigger_game_tune=False, play_quest_completion_music=False)
                for plan in plans
            )
        apply_presentation_plans(plans=plans, runtime=runtime)
        if advance.refused_tick is not None:
            self._stopped_tick = advance.refused_tick
            self.stopped_reason = f"This run stops playing here (tick {advance.refused_tick})"
        elif self.finished and self.driver.complete:
            self.played_as_recorded = not run_result_mismatches(self._replay.result, self.driver.build_result())
        return len(advance.tick_results)

    def run(self, count: int, *, quiet: bool = False) -> int:
        """Up to `count` ticks straight away, with sound effects off when `quiet`; returns how many ran."""
        bridge = self.runtime.audio_bridge
        sfx_enabled = bridge.sfx_enabled
        bridge.sfx_enabled = sfx_enabled and not quiet
        self._clock.reset()
        try:
            return self._advance(dt_seconds=float(count) * self._dt, max_ticks=count)
        finally:
            bridge.sfx_enabled = sfx_enabled
            self._clock.reset()

    def restore(self, key: Keyframe) -> None:
        """Playback goes back (or ahead) to a keyframe of the preparing pass; the viewer rebuilds the terrain."""
        driver = self.driver
        runtime = self.runtime
        restore_keyframe(driver, key)
        runtime.start_session(driver.session)
        runtime.presentation = msgspec.structs.replace(key.clock)
        runtime.update_camera(CameraUpdate(focus=key.focus, shake=runtime.world.state.camera_shake_offset))
        self._tick_index = key.tick
        self._clock.reset()

    def settle_hud(self) -> None:
        """The HUD's counters at the run's values, as after a seek: the XP count does not count up to them."""
        self._hud_state.survival_xp_smoothed = int(self.runtime.world.players[0].experience)

    def update(self, dt: float) -> None:
        """Straight playback at the replay's own pace."""
        self._frame_dt_ms = max(0.0, float(dt)) * 1000.0
        ran = self._advance(dt_seconds=min(max(0.0, float(dt)), 0.1))
        if self._audio is not None:
            update_audio(self._audio, float(dt), advance_sfx=ran == 0)

    def set_frame_dt(self, dt: float) -> None:
        """The frame's own delta, which the HUD's animations take."""
        self._frame_dt_ms = max(0.0, float(dt)) * 1000.0

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
        driver = self._driver
        if driver is None or driver.quest_spawn_state is None:
            return
        draw_quest_complete_banner_overlay(
            self.runtime.render_resources.resources.texture(TextureId.UI_TEXT_LEVEL_COMPLETE),
            timer_ms=float(driver.quest_spawn_state.completion_transition_ms),
        )

    def _draw_typo_name_labels(self) -> None:
        runtime = self.runtime
        draw_typo_name_labels(
            creatures=runtime.world.creatures.entries,
            names=runtime.world.state.typo.names.names,
            world_to_screen=runtime.world_to_screen,
            draw_text=self._draw_ui_text,
            measure_text_width=self._measure_ui_text_width,
        )

    def _draw_typing_box(self) -> None:
        runtime = self.runtime
        driver = self._driver
        draw_typing_box(
            runtime.render_resources.resources.texture(TextureId.UI_IND_PANEL),
            text=runtime.world.state.typo.typing.text,
            game_time_s=0.0 if driver is None else float(driver.elapsed_ms) * 0.001,
            draw_text=self._draw_ui_text,
            measure_text_width=self._measure_ui_text_width,
        )

    def _draw_tutorial_overlays(self) -> None:
        draw_tutorial_overlay_panels(
            self.runtime.world.state.tutorial_overlay,
            draw_text=self._draw_ui_text,
            measure_text_width=self._measure_ui_text_width,
            measure_line_height=lambda: int(
                self._small.cell_size if self._small is not None else 20,
            ),
        )

    def draw(self) -> None:
        runtime = self.runtime
        replay = self._replay
        world = runtime.world
        players = world.players
        assert players, "Replay runtime must have at least one player before draw"
        runtime.draw()
        runtime.draw_aim_indicators(
            show_aim=True,
            aim_enhancement_fade=clamp(self._console.cvars["cv_aimEnhancementFade"].value_f, 0.0, 1.0),
        )
        mode_id = replay.run.game_mode_id
        # Native draws the labels and the typing panel every Typ-o frame, the dying ones too.
        show_typo_ui = mode_id == GameMode.TYPO
        quest_progress_ratio: float | None = None
        driver = self.driver
        if mode_id == GameMode.QUESTS:
            quest_spawn = driver.quest_spawn_state
            total = 0 if quest_spawn is None else quest_spawn.total_creatures
            kills = int(world.creatures.kill_count)
            quest_progress_ratio = float(kills) / float(total) if total > 0 else None
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
            elapsed_ms=float(driver.elapsed_ms),
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
