from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from crimson.screens.actions import ResultAction, Route, ScoreQuery, ScoreReturnContext, ScreenAction, ShowScores
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.audio import AudioState, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp
from grim.music import play_music, stop_music
from grim.rand import Crand, CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.view import ViewContext

from ..game_modes import GameMode
from ..game_states import GameStateId
from ..input_codes import PadCode, pad_nav_pressed
from ..local_input import PAD_AIM_DIST_MUL_DEFAULT, LocalInputInterpreter
from ..perks.selection import perk_selection_prepared_choices
from ..persistence.highscores import HighScoreRecord
from ..quests.level import QuestLevel
from ..render.rtx.mode import RtxRenderMode
from ..replay import REPLAY_TICK_RATE, Replay, ReplayCodecError, ReplayRecorder, dump_replay_file
from ..replay.checkpoints import (
    DEFAULT_CHECKPOINT_SAMPLE_RATE,
    ReplayCheckpoint,
    ReplayCheckpoints,
    build_checkpoint,
    default_checkpoints_path,
    dump_checkpoints_file,
)
from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINTS_FORMAT_VERSION,
)
from ..replay.ticks import LiveTickSource, step_replay_tick
from ..screens.results.game_over import GameOverUi
from ..screens.ui_timeline import UiTimeline
from ..sim.batch_apply import apply_presentation_plans
from ..sim.clock import FixedStepClock
from ..sim.commands import GameCommand, PerkMenuOpenCommand, PerkPickCommand
from ..sim.input import PlayerInput
from ..sim.presentation_step import DeterministicPresentationPlan
from ..sim.run_init import PreparedRun, initialize_run
from ..sim.run_result import RunOutcome, RunResult, build_run_result
from ..sim.run_spec import RunSpec, RunStatus
from ..sim.sessions import DeterministicSession, DeterministicSessionTick
from ..sim.terrain_generate import TerrainSetup, terrain_generate
from ..sim.timing import ftol_ms_i32
from ..typo.state import TypoCarry
from ..ui.animation import ui_element_timeline_window, ui_elements_max_timeline, ui_transition_alpha
from ..ui.focus import UiFocus
from ..ui.hud import HudRenderContext, HudState, draw_hud_overlay, draw_target_health_bar, ui_transparency
from ..ui.keybind_help import ui_render_keybind_help
from ..world.runtime import WorldRuntime
from .components.highscore_record_builder import build_highscore_record
from .components.perk_menu_controller import PerkMenuController, PerkMenuUiContext
from .components.perk_prompt_controller import PerkPromptState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureDeath, CreaturePool
    from ..game.types import GameState
    from ..persistence.save_status import GameStatus
    from ..sim.state_types import PlayerState
    from ..sim.world_state import WorldEvents, WorldState


class _ModeFrameState(msgspec.Struct, frozen=True):
    dt: float
    dt_ui_ms: float


class BaseGameplayMode:
    # Whether the tick that ends the run starts the run-down; Typ-o starts it after its death animation.
    _RUN_DOWN_ON_OUTCOME = True
    # `gameplay_update_and_render` pauses on F1 and shows the key info; Typ-o's update has no pause.
    _KEY_INFO_PAUSE = True

    def __init__(
        self,
        ctx: ViewContext,
        *,
        default_game_mode_id: GameMode,
        config: CrimsonConfig,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand,
    ) -> None:
        self._assets_root = ctx.assets_dir
        self._small: SmallFontData | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._hud_state = HudState()
        self.default_game_mode_id = default_game_mode_id

        self.config: CrimsonConfig = config
        self._console = console
        self._base_dir = self.config.path.parent

        self.close_requested = False
        self._action: ScreenAction | None = None
        # Native `game_paused_flag` and `pause_keybind_help_alpha_ms`.
        self._paused = False
        self._keybind_help_alpha_ms = 0
        self._status_base: GameStatus | None = None
        self._local_input: LocalInputInterpreter = LocalInputInterpreter()
        self._game_over_ui: GameOverUi = GameOverUi(
            assets_root=self._assets_root,
            base_dir=self._base_dir,
            config=self.config,
            preserve_bugs=ctx.preserve_bugs,
        )

        self.assets_dir = ctx.assets_dir
        # The next run's flags; the run spec carries them into the gameplay state.
        self.hardcore = False
        self.quest_fail_retry_count = 0
        # The runtime owns the run (session, world), audio and render mode; the mode reads them from it.
        self._world_runtime = WorldRuntime(
            assets_dir=self.assets_dir,
            preserve_bugs=bool(ctx.preserve_bugs),
            config=self.config,
            audio=audio,
            audio_rng=audio_rng,
            rtx_mode=RtxRenderMode.CLASSIC,
        )
        self.render_resources = self._world_runtime.render_resources
        self.audio_bridge = self._world_runtime.audio_bridge

        self.camera = Vec2(-1.0, -1.0)
        player_count = self._runtime_player_count()
        self._world_runtime.reset(player_count=max(1, min(4, int(player_count))))
        preserve_bugs = self._world_runtime.preserve_bugs
        self._local_input.set_preserve_bugs(preserve_bugs)
        self._hud_state.preserve_bugs = preserve_bugs

        self._game_over_active = False
        self._game_over_record: HighScoreRecord | None = None
        # The level-up prompt and perk menu `gameplay_update_and_render` runs outside Rush and Typ-o.
        self._perk_prompt = PerkPromptState()
        self._perk_menu_requested = False
        self._counted_level = 1
        self._game_over_banner = "reaper"

        self._ui_mouse = Vec2()
        self._last_dt_ms = 0.0
        # The menu timeline gameplay runs on (GameState.ui once bound), and native `gameplay_transition_latch`.
        self._ui_timeline = UiTimeline()
        # The menu keyboard focus (GameState.focus once bound) for the perk menu, tutorial and game over widgets.
        self._ui_focus = UiFocus()
        self._perk_menu = PerkMenuController(
            timeline=self._ui_timeline, focus=self._ui_focus, play_sfx=self.audio_bridge.play_sfx,
        )
        self._gameplay_transition_latch = False
        # Native `game_state_pending` while gameplay runs the timeline down: the pause menu, or the run's end.
        self._pause_pending = False
        self._run_ending = False
        self._screen_fade: GameState | None = None
        self._terrain_regen_counter = 0
        self._run_reset_seed = 0
        self._replay_recorder: ReplayRecorder | None = None
        self._replay_checkpoints: list[ReplayCheckpoint] = []
        # Checkpoint sidecars are a parity-debugging aid; off unless requested.
        self._replay_checkpoints_enabled = bool(ctx.replay_checkpoints)
        self._replay_checkpoints_last_tick: int | None = None
        self._replay_result: RunResult | None = None
        self._live_ticks = LiveTickSource()
        self._tick_clock = FixedStepClock(tick_rate=REPLAY_TICK_RATE)

    @property
    def world_runtime(self) -> WorldRuntime:
        return self._world_runtime

    @property
    def world(self) -> WorldState:
        return self._world_runtime.world

    @property
    def state(self) -> GameplayState:
        return self._world_runtime.world.state

    @property
    def creatures(self) -> CreaturePool:
        return self._world_runtime.world.creatures

    @property
    def player(self) -> PlayerState:
        return self._world_runtime.world.players[0]

    @property
    def _sim_session(self) -> DeterministicSession | None:
        return self._world_runtime.session

    @property
    def audio(self) -> AudioState | None:
        return self._world_runtime.audio

    @property
    def audio_rng(self) -> CrandLike:
        return self._world_runtime.audio_rng

    @property
    def rtx_mode(self) -> RtxRenderMode:
        return self._world_runtime.rtx_mode

    @property
    def camera(self) -> Vec2:
        return self._world_runtime.camera

    @camera.setter
    def camera(self, value: Vec2) -> None:
        self._world_runtime.camera = value

    @property
    def preserve_bugs(self) -> bool:
        return self._world_runtime.preserve_bugs

    def apply_terrain_setup(self, setup: TerrainSetup) -> None:
        self._world_runtime.apply_terrain_setup(setup)

    def _draw_world(self, *, entity_alpha: float = 1.0) -> None:
        self._world_runtime.draw(entity_alpha=entity_alpha)

    def _draw_aim_indicators(self, *, show_aim: bool, entity_alpha: float = 1.0) -> None:
        # Native clamps `cv_aimEnhancementFade` into 0..1 each time it draws the reticle.
        fade = clamp(self._cvar_float("cv_aimEnhancementFade", 0.7), 0.0, 1.0)
        self._world_runtime.draw_aim_indicators(show_aim=show_aim, aim_enhancement_fade=fade, entity_alpha=entity_alpha)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._world_runtime.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._world_runtime.screen_to_world(pos)

    def _cvar_float(self, name: str, default: float = 0.0) -> float:
        console = self._console
        if console is None:
            return float(default)
        cvar = console.cvars.get(name)
        if cvar is None:
            return float(default)
        return float(cvar.value_f)

    def _hud_small_indicators(self) -> bool:
        return self._cvar_float("cv_uiSmallIndicators", 0.0) != 0.0

    def _config_game_mode_id(self) -> GameMode:
        try:
            return GameMode(self.config.gameplay.mode)
        except ValueError:
            return GameMode.DEMO

    def _draw_hud(self, *, elapsed_ms: float, quest_progress_ratio: float | None = None) -> float:
        """`hud_update_and_render`; returns the HUD's bottom edge."""
        return draw_hud_overlay(
            HudRenderContext(
                resources=self.render_resources.resources,
                state=self._hud_state,
                font=self._small,
                alpha=self._hud_alpha() * ui_transparency(self._cvar_float("cv_uiTransparency", 1.0)),
                game_mode=self._config_game_mode_id(),
                small_indicators=self._hud_small_indicators(),
            ),
            players=self.world.players,
            bonus_hud=self.state.bonus_hud,
            elapsed_ms=elapsed_ms,
            frame_dt_ms=self._last_dt_ms,
            quest_progress_ratio=quest_progress_ratio,
        )

    def _draw_target_health_bar(self, *, alpha: float = 1.0) -> None:
        creatures = self.creatures.entries
        if not creatures:
            return

        # `perks_update_effects` picks the Doctor targets during the update.
        target_indices = list(dict.fromkeys(
            player.doctor_target_creature for player in self.world.players if player.doctor_target_creature != -1
        ))
        for target_idx in target_indices:
            creature = creatures[target_idx]
            if not creature.active:
                continue
            hp = float(creature.hp)
            max_hp = float(creature.max_hp)
            if max_hp <= 0.0:
                continue

            ratio = hp / max_hp
            if ratio < 0.0:
                ratio = 0.0
            if ratio > 1.0:
                ratio = 1.0

            screen_left = self.world_to_screen(creature.pos + Vec2(-32.0, 32.0))
            screen_right = self.world_to_screen(creature.pos + Vec2(32.0, 32.0))
            width = screen_right.x - screen_left.x
            if width <= 1e-3:
                continue
            draw_target_health_bar(pos=screen_left, width=width, ratio=ratio, alpha=alpha)

    def _any_player_alive(self) -> bool:
        return any(player.health > 0.0 for player in self.world.players)

    @property
    def save_status(self) -> GameStatus | None:
        return self._status_base

    def bind_status(self, status: GameStatus) -> None:
        self._status_base = status
        self.state.status = status

    def bind_screen_fade(self, fade: GameState | None) -> None:
        self._screen_fade = fade
        if fade is not None:
            # Gameplay, perk selection and game over all run on the one menu timeline.
            self._ui_timeline = fade.ui
            self._game_over_ui.timeline = fade.ui
            self._ui_focus = fade.focus
            self._game_over_ui.focus = fade.focus
            self._perk_menu.timeline = fade.ui
            self._perk_menu.focus = fade.focus

    def bind_audio(self, audio: AudioState | None, audio_rng: CrandLike) -> None:
        self._world_runtime.audio = audio
        self._world_runtime.audio_rng = audio_rng

    def set_rtx_mode(self, mode: RtxRenderMode) -> None:
        self._world_runtime.rtx_mode = mode

    def _update_audio(self, dt: float) -> None:
        if self.audio is not None:
            update_audio(self.audio, dt, advance_sfx=self._game_over_active)

    def _ui_line_height(self) -> int:
        if self._small is not None:
            return int(self._small.cell_size)
        return 20

    def _ui_text_width(self, text: str) -> int:
        font = self._small
        assert font is not None, "small font must be loaded before ui text measurement"
        return int(measure_small_text_width(font, text))

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color) -> None:
        font = self._small
        assert font is not None, "small font must be loaded before ui text draw"
        draw_small_text(font, text, pos, color)

    def _perk_menu_ui_context(self) -> PerkMenuUiContext:
        return PerkMenuUiContext(
            player=self.player,
            perks=self.state.perks,
            violence_disabled=self.config.display.violence_disabled,
            shadows_enabled=self.config.display.shadows_enabled,
            resources=self.render_resources.resources,
            mouse=self._ui_mouse_pos(),
        )

    def _request_perk_menu(self) -> None:
        """Ask the next tick to open the perk menu; it opens mid-tick, as in native."""

        if self._perk_menu.active or self._perk_menu_requested:
            return
        self._perk_menu_requested = True
        self.enqueue_input_command(PerkMenuOpenCommand(player_index=0))

    def _update_perk_ui(self, *, dt_ui_ms: float) -> None:
        """The level-up prompt and perk menu input of `gameplay_update_and_render`."""

        perk_ctx = self._perk_menu_ui_context()
        pending_count = self._ui_pending_perk_count()
        if self._perk_menu.open:
            choice_index = self._perk_menu.handle_input(
                perk_ctx,
                perk_selection_prepared_choices(self.state),
                dt_ui_ms=float(dt_ui_ms),
            )
            if choice_index is not None:
                self.record_perk_pick_command(int(choice_index), player_index=0)
        if not self._paused:
            self._perk_prompt.tick_pulse(float(dt_ui_ms))
        players = self.world.players
        # Native checks player one, and player two only in a two-player game.
        alive = players[0].health > 0.0 or (len(players) == 2 and players[1].health > 0.0)
        if self._perk_prompt.poll_open_request(
            ctx=perk_ctx,
            config=self.config,
            pending_count=pending_count,
            alive=alive,
            paused=self._paused,
            menu_active=self._perk_menu.active,
            player_count=len(players),
        ):
            self._request_perk_menu()
        self._perk_prompt.tick_timer(
            pending_count=pending_count,
            menu_active=self._perk_menu.active,
            dt_ui_ms=float(dt_ui_ms),
        )
        self._perk_menu.tick_timeline()

    def _draw_perk_prompt(self) -> None:
        self._perk_prompt.draw(ctx=self._perk_menu_ui_context(), config=self.config, ui_text_width=self._ui_text_width)

    def _ui_mouse_pos(self) -> rl.Vector2:
        return self._ui_mouse.to_rl()

    def _update_ui_mouse(self) -> None:
        mouse = canvas.mouse_position()
        screen_w = float(canvas.width())
        screen_h = float(canvas.height())
        self._ui_mouse = Vec2.from_xy(mouse).clamp_rect(
            0.0,
            0.0,
            max(0.0, screen_w - 1.0),
            max(0.0, screen_h - 1.0),
        )

    def _tick_frame(self, dt: float) -> tuple[float, float]:
        dt = float(dt)
        dt_ui_ms = float(min(dt, 0.1) * 1000.0)
        self._last_dt_ms = dt_ui_ms
        self._update_ui_mouse()
        if not (self._game_over_active or self._pause_pending or self._run_ending):
            # The game-over panel advances the timeline itself while it is up, and a gameplay
            # run-down advances it with the simulated ticks.
            self._ui_timeline.advance(int(dt_ui_ms))
            if self._hud_alpha() >= 1.0:
                self._gameplay_transition_latch = False
        if self._KEY_INFO_PAUSE and not self._game_over_active:
            self._update_key_info_pause(int(dt_ui_ms))
        return dt, dt_ui_ms

    def _update_key_info_pause(self, dt_ms: int) -> None:
        """`gameplay_update_and_render`: F1 toggles `game_paused_flag`, and the key info fades with it."""
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F1):
            self._paused = not self._paused
        step = dt_ms * 2 if self._paused else -dt_ms * 4
        self._keybind_help_alpha_ms = min(1000, max(0, self._keybind_help_alpha_ms + step))
        # The world is frozen, but native keeps moving the timeline by the frame, so a pending exit still happens.
        session = self._sim_session
        if self._paused and (self._pause_pending or self._run_ending) and session is not None:
            self._run_down_gameplay(dt_ms, session)

    def _draw_keybind_help(self) -> None:
        if self._keybind_help_alpha_ms <= 0:
            return
        small = self._small
        mono = self._grim_mono
        assert small is not None and mono is not None, "key info needs the loaded fonts"
        ui_render_keybind_help(
            Vec2(float(canvas.width()) * 0.5 - 256.0, float(canvas.height()) * 0.5 - 128.0),
            self._keybind_help_alpha_ms * 0.001,
            config=self.config,
            small=small,
            mono=mono,
        )

    @property
    def game_state_id(self) -> GameStateId:
        """Native `game_state_id` while this run is on screen: its gameplay state, or the perk menu or game over over it."""
        if self._game_over_active:
            return GameStateId.GAME_OVER
        if self._perk_menu.active:
            return GameStateId.PERK_SELECTION
        return GameStateId.TYPO_GAMEPLAY if self.default_game_mode_id == GameMode.TYPO else GameStateId.GAMEPLAY

    def _hud_alpha(self) -> float:
        """`hud_update_and_render`: the HUD fades in with the timeline over `ui_element_table[28]`'s span."""
        return min(1.0, max(0.0, self._ui_timeline.timeline_ms / ui_element_timeline_window(28)[1]))

    def _enter_gameplay_timeline(self) -> None:
        """`game_state_set(GAME_STATE_GAMEPLAY)`."""
        self._paused = False
        self._pause_pending = False
        self._run_ending = False
        self._ui_timeline.enter(ui_elements_max_timeline(GameStateId.GAMEPLAY))

    def _request_pause(self) -> None:
        """`game_frame_update`: Esc makes the pause menu pending; gameplay runs on while the HUD fades out."""
        # Only gameplay takes Esc: not while the perk panel is still sliding out.
        if self._pause_pending or self._run_ending or self._ui_timeline.closing:
            return
        self._pause_pending = True
        self._ui_timeline.begin()

    def _run_down_gameplay(self, dt_ms: int, session: DeterministicSession) -> bool:
        """Advance a pending exit by `dt_ms`; True once the timeline is out and the exit happened.

        Native simulates and moves the timeline by the same `frame_dt_ms`, so the run-down lasts its timeline
        span of simulated time, at most 500ms after the run ends (the verifiers bound recordings by this).
        """
        self._ui_timeline.advance(dt_ms)
        if not self._ui_timeline.ready:
            return False
        if self._run_ending:
            self._run_ending = False
            # The pending state is set again every frame, so the outcome is the one standing now.
            self._finish_run(session.end_outcome())
        else:
            self._pause_pending = False
            self._action = Route.PAUSE
        return True

    def _draw_game_cursor(self) -> None:
        ui_cursor_render(self.render_resources.resources, dt=self._last_dt_ms * 0.001, pos=self._ui_mouse)

    def _begin_mode_update(self, dt: float) -> _ModeFrameState | None:
        self._update_audio(dt)

        frame_dt, frame_dt_ui_ms = self._tick_frame(dt)
        if self._perk_menu.open and (
            rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.FACE_RIGHT)
        ):
            # Escape (or the pad's B) backs out of the perk menu before the mode sees it, so it cannot also pause.
            self.audio_bridge.play_sfx(SfxId.UI_BUTTONCLICK)
            self._perk_menu.close()
        else:
            self._handle_input()
        if self._action == Route.PAUSE:
            return None
        return _ModeFrameState(
            dt=float(frame_dt),
            dt_ui_ms=float(frame_dt_ui_ms),
        )

    def _handle_input(self) -> None:
        raise NotImplementedError

    def enqueue_input_command(self, command: GameCommand) -> None:
        self._live_ticks.submit(command)

    def _debug_cheat_used(self) -> None:
        """Stop recording: cheats change the run outside recorded ticks, so the replay could not verify."""

        if self._replay_recorder is None:
            return
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._replay_result = None
        if self._console is not None:
            self._console.log.log("replay: recording stopped (debug cheat used)")

    def _ui_pending_perk_count(self) -> int:
        """Pending perks the UI may offer right now.

        Picks apply at the start of the next tick, and at high frame rates a
        frame can run no ticks. Until a queued pick applies, the prompt stays
        closed: the pick may spend the last pending perk or kill every player,
        and the recorded commands must stay legal against the state they meet.
        """

        if any(isinstance(command, PerkPickCommand) for command in self._live_ticks.queued_commands):
            return 0
        return int(self.state.perk_selection.pending_count)

    def record_perk_pick_command(self, choice_index: int, *, player_index: int = 0) -> None:
        self.enqueue_input_command(
            PerkPickCommand(
                player_index=int(player_index),
                choice_index=int(choice_index),
            ),
        )

    def _session_elapsed_ms(self) -> float:
        session = self._sim_session
        assert session is not None, "session elapsed requested without an active deterministic session"
        return float(session.elapsed_ms)

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return float(self._world_runtime.presentation_elapsed_ms)

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        mode_name = str(self.__class__.__name__).replace("Mode", "").lower() or "replay"
        return f"{mode_name}_{stamp}"

    def _record_replay_checkpoint(
        self,
        tick_index: int,
        *,
        force: bool = False,
        deaths: Sequence[CreatureDeath] | None = None,
        events: WorldEvents | None = None,
    ) -> None:
        recorder = self._replay_recorder
        if recorder is None:
            return
        if tick_index < 0 or not self._replay_checkpoints_enabled:
            return
        if not force and (tick_index % DEFAULT_CHECKPOINT_SAMPLE_RATE) != 0:
            return
        if self._replay_checkpoints_last_tick == int(tick_index):
            return
        self._replay_checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=self.world,
                elapsed_ms=float(self._replay_checkpoint_elapsed_ms()),
                deaths=deaths,
                events=events,
            ),
        )
        self._replay_checkpoints_last_tick = int(tick_index)

    def _save_replay(self) -> None:
        recorder = self._replay_recorder
        if recorder is None:
            return
        if recorder.tick_index <= 0:
            # Nothing was simulated (e.g. a run left before its first tick).
            self._reset_replay_capture_state(clear_recorder=True)
            return

        self._record_replay_checkpoint(max(0, int(recorder.tick_index) - 1), force=True)
        result = self._replay_result
        assert result is not None, "a non-empty recording has a result snapshot"
        replay = recorder.finish(result)

        stamp = dt.datetime.now(tz=dt.UTC).astimezone().strftime("%Y%m%d_%H%M%S")
        replay_dir = self._base_dir / "replays"
        replay_dir.mkdir(parents=True, exist_ok=True)
        base_name = self._replay_output_basename(stamp=stamp, replay=replay)
        path = replay_dir / f"{base_name}.crd"
        counter = 1
        while path.exists():
            path = replay_dir / f"{base_name}_{counter}.crd"
            counter += 1
        try:
            dump_replay_file(path, replay)
        except ReplayCodecError as exc:
            # Only a run of many hours outgrows the format's size ceiling.
            self._reset_replay_capture_state(clear_recorder=True)
            if self._console is not None:
                self._console.log.log(f"replay: not saved ({exc})")
                self._console.log.flush()
            return
        saved = [path]

        if self._replay_checkpoints_enabled:
            checkpoints_path = default_checkpoints_path(path)
            dump_checkpoints_file(
                checkpoints_path,
                ReplayCheckpoints(
                    version=CHECKPOINTS_FORMAT_VERSION,
                    sample_rate=DEFAULT_CHECKPOINT_SAMPLE_RATE,
                    checkpoints=list(self._replay_checkpoints),
                ),
            )
            saved.append(checkpoints_path)
        self._reset_replay_capture_state(clear_recorder=True)
        if self._console is not None:
            for saved_path in saved:
                self._console.log.log(f"replay: saved {saved_path}")
            self._console.log.flush()

    def _player_name_default(self) -> str:
        return str(self.config.profile.player_name or "")

    def _runtime_player_count(self) -> int:
        return self.config.gameplay.player_count

    def update(self, dt: float) -> None:
        raise NotImplementedError(f"{self.__class__.__name__}.update() must be implemented by gameplay mode")

    def draw(self) -> None:
        raise NotImplementedError(f"{self.__class__.__name__}.draw() must be implemented by gameplay mode")

    def open(self) -> None:
        self.close_requested = False
        self._action = None
        self._paused = False
        self._keybind_help_alpha_ms = 0
        self._small = load_small_font(self._assets_root)
        self._grim_mono = load_grim_mono_font(self._assets_root)
        self._hud_state = HudState()

        self._game_over_active = False
        self._game_over_record = None
        self._game_over_banner = "reaper"
        self._game_over_ui.close()
        self._perk_prompt.reset()
        self._perk_menu.reset()
        self._perk_menu_requested = False
        self._counted_level = 1

        # Native game_over/victory transitions call `sfx_mute_all` on menu + extra
        # tracks before restarting gameplay ("Play Again"), resetting first-hit tune gate.
        if self.audio is not None:
            stop_music(self.audio.music)

        player_count = self._runtime_player_count()
        seed = int(self.state.rng.state)
        self._run_reset_seed = int(seed) & 0xFFFFFFFF

        self._world_runtime.reset(seed=seed, player_count=max(1, min(4, int(player_count))))
        self._world_runtime.open_runtime()
        self._local_input.reset(players=self.world.players)
        self._reset_live_ticks()
        self._reset_replay_capture_state(clear_recorder=False)

        self._ui_mouse = Vec2(float(canvas.width()) * 0.5, float(canvas.height()) * 0.5)
        # A new run: world entities fade in with the timeline until the HUD is fully in.
        self._enter_gameplay_timeline()
        self._gameplay_transition_latch = True

    def _initialize_run(
        self,
        game_mode: GameMode,
        *,
        quest_level: QuestLevel | None = None,
        dictionary_words: tuple[str, ...] = (),
        highscore_names: tuple[str, ...] = (),
        typo_carry: TypoCarry | None = None,
    ) -> PreparedRun:
        status = self._status_base
        spec = RunSpec(
            game_mode_id=game_mode,
            seed=self._run_reset_seed,
            quest_level=quest_level,
            player_count=self._runtime_player_count(),
            hardcore=self.hardcore,
            preserve_bugs=self.state.preserve_bugs,
            quest_fail_retry_count=self.quest_fail_retry_count,
            detail_preset=self.config.display.detail_preset,
            violence_disabled=self.config.display.violence_disabled,
            friendly_fire=self._cvar_float("cv_friendlyFire") != 0.0,
            status=RunStatus() if status is None else RunStatus.from_status_data(status),
            typo_dictionary_words=dictionary_words,
            typo_highscore_names=highscore_names,
            typo_carry=TypoCarry() if typo_carry is None else typo_carry,
        )
        prepared = initialize_run(spec, status=status)
        self._world_runtime.start_session(prepared.session)
        self._local_input.reset(players=self.world.players)
        self.apply_terrain_setup(prepared.terrain)
        self._reset_live_ticks()
        self._replay_recorder = ReplayRecorder(spec)
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._replay_result = None
        return prepared

    def resume(self) -> None:
        self._action = None
        self._reset_gameplay_frame_clock()
        self._enter_gameplay_timeline()

    def close(self) -> None:
        self._game_over_ui.close()
        if self._small is not None:
            self._small = None
        self._reset_live_ticks()
        self._reset_replay_capture_state(clear_recorder=True)
        self._world_runtime.close_runtime()

    def take_action(self) -> ScreenAction | None:
        action = self._action
        self._action = None
        return action

    def _enter_game_over(self) -> None:
        if self._game_over_active:
            return
        self._game_over_record = build_highscore_record(
            state=self.state,
            player=self.player,
            survival_elapsed_ms=int(self._session_elapsed_ms()),
            creature_kill_count=int(self.creatures.kill_count),
        )
        self._game_over_ui.open()
        self._game_over_active = True
        self._save_replay()

    def _finish_run(self, outcome: RunOutcome) -> None:
        """React to the session ending the run; survival, rush and Typ-o show game over."""

        _ = outcome
        self._enter_game_over()

    def _finish_run_if_over(self) -> bool:
        """Between ticks: finish the run if the session's rules say it is over."""

        if self._run_ending:
            return False
        session = self._sim_session
        outcome = session.terminal_outcome() if session is not None else None
        if outcome is None:
            return False
        self._finish_run(outcome)
        return True

    def _update_game_over_ui(self, dt: float) -> None:
        if self.audio is not None and not self._game_over_ui.closing:
            play_music(self.audio.music, "shortie_monk")
        record = self._game_over_record
        if record is None:
            self._enter_game_over()
            record = self._game_over_record
        if record is None:
            return

        action = self._game_over_ui.update(
            dt,
            record=record,
            player_name_default=self._player_name_default(),
            play_sfx=self.audio_bridge.play_sfx,
            rng=self.audio_rng,
            mouse=self._ui_mouse_pos(),
        )
        if action == ResultAction.PLAY_AGAIN:
            self.open()
            return
        if action == ResultAction.HIGH_SCORES:
            self._action = ShowScores(ScoreQuery(self.default_game_mode_id), ScoreReturnContext.capture(self.config))
            return
        if action == ResultAction.MAIN_MENU:
            self._action = Route.MENU
            self.close_requested = True

    def _world_entity_alpha(self) -> float:
        if self._game_over_active:
            return self._game_over_ui.world_entity_alpha()
        # Native `game_state_pending` while the timeline runs down: the pause menu, or the run's end (which only a
        # Typ'o'Shooter run, outside the gameplay states, reads; its end is the game over).
        pending = GameStateId.PAUSE_MENU if self._pause_pending else GameStateId.GAME_OVER if self._run_ending else None
        return ui_transition_alpha(
            self._ui_timeline.timeline_ms, state=self.game_state_id, pending=pending, latch=self._gameplay_transition_latch,
        )

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        # `game_update_generic_menu` renders the world only while `render_pass_mode` holds; the death clears it, so
        # the high scores over a game over show just the terrain.
        alpha = 0.0 if self._game_over_active else self._world_entity_alpha() * entity_alpha
        self._draw_world(entity_alpha=alpha)

    def steal_ground_for_menu(self):
        ground = self.render_resources.ground
        self.render_resources.ground = None
        return ground

    def menu_ground_camera(self) -> Vec2:
        return self.camera

    def console_elapsed_ms(self) -> float:
        return float(self._world_runtime.presentation_elapsed_ms)

    def regenerate_terrain_for_console(self) -> None:
        setup = self._world_runtime.terrain_setup
        if self.render_resources.ground is None or setup is None:
            return
        # Native `generateterrain` runs `terrain_generate_random()` on the live stream, which a replay
        # cannot reproduce from its ticks. The port keeps the gameplay RNG and the current textures, and
        # stamps from a detached rng seeded off the gameplay state plus a counter, so repeats differ.
        self._terrain_regen_counter = (int(self._terrain_regen_counter) + 1) & 0xFFFFFFFF
        terrain_seed = (int(self.state.rng.state) + int(self._terrain_regen_counter)) & 0xFFFFFFFF
        self._world_runtime.apply_terrain_setup(terrain_generate(Crand(terrain_seed), setup.terrain_slots))

    def _draw_screen_fade(self) -> None:
        fade_alpha = 0.0
        if self._screen_fade is not None:
            fade_alpha = float(self._screen_fade.screen_fade_alpha)
        if fade_alpha <= 0.0:
            return
        alpha = int(255 * max(0.0, min(1.0, fade_alpha)))
        rl.draw_rectangle(0, 0, int(canvas.width()), int(canvas.height()), rl.Color(0, 0, 0, alpha))

    def _build_local_inputs(self) -> list[PlayerInput]:
        return self._local_input.build_frame_inputs(
            players=self.world.players,
            config=self.config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self.screen_to_world,
            pad_aim_dist_mul=self._cvar_float("cv_padAimDistMul", PAD_AIM_DIST_MUL_DEFAULT),
        )

    def _reset_gameplay_frame_clock(self) -> None:
        """Paused or menu frames run no ticks: drop undelivered presses and banked time."""

        self._live_ticks.clear_edges()
        self._tick_clock.reset()

    def _reset_live_ticks(self) -> None:
        self._live_ticks = LiveTickSource()
        self._tick_clock.reset()

    def _reset_replay_capture_state(self, *, clear_recorder: bool) -> None:
        if clear_recorder:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._replay_result = None

    def _count_level_ups(self) -> None:
        """`gameplay_update_and_render` counts each level-up in the config and turns the info texts off after 50."""
        level = self.world.players[0].level
        gameplay = self.config.gameplay
        for _ in range(level - self._counted_level):
            gameplay.level_up_count += 1
            if gameplay.level_up_count > 50:
                gameplay.level_up_count = 0
                gameplay.show_info_texts = False
        self._counted_level = level

    def _on_tick_applied(self, tick: DeterministicSessionTick) -> bool:
        """Return False to stop running ticks this frame."""

        self._count_level_ups()
        # The request rode in this tick; the tick opened the menu only if native would have.
        requested = self._perk_menu_requested
        self._perk_menu_requested = False
        if tick.outcome is not None and self._RUN_DOWN_ON_OUTCOME and not self._run_ending:
            # `gameplay_update_and_render`: the end of the run replaces any pending pause and runs the timeline
            # down while the world keeps simulating.
            self._run_ending = True
            self._pause_pending = False
            self._ui_timeline.begin()
        if requested and tick.events.perk_menu_opened:
            self._perk_menu.open_menu()
            return False
        return True

    def _sync_audio(self) -> None:
        self._world_runtime.sync_audio_bridge_state()

    def _run_deterministic_session_ticks(
        self,
        *,
        dt_frame: float,
        session: DeterministicSession,
        recorder: ReplayRecorder | None,
    ) -> None:
        """Poll input once for the frame, then run the ticks its time covers.

        Each tick is recorded before it is simulated, and the simulation steps
        that recorded tick: live play and verification cannot disagree about input.
        """

        if float(dt_frame) <= 0.0:
            return
        self._sync_audio()
        # Presentation only: the corpse decal alpha, never read back by the sim.
        session.terrain_fx.corpses.bodies_transparency = self._cvar_float("cv_terrainBodiesTransparency")
        self._live_ticks.poll(self._build_local_inputs())
        plans: list[DeterministicPresentationPlan] = []
        for _ in range(self._tick_clock.advance(float(dt_frame))):
            tick = self._live_ticks.next_tick()
            tick_index = recorder.record(tick) if recorder is not None else None
            step = step_replay_tick(session, tick)
            self._world_runtime.advance_presentation_clock(dt_sim=step.dt_sim)
            plans.append(step.presentation)
            if tick_index is not None:
                self._record_replay_checkpoint(
                    tick_index,
                    force=step.events.perk_menu_opened,
                    deaths=step.events.deaths,
                    events=step.events,
                )
            if recorder is not None:
                # The replay result is the state after the last recorded tick:
                # UI work between ticks (perk menu previews, the high-score tag
                # draw at game over) must not leak into it.
                self._replay_result = build_run_result(session, outcome=step.outcome or session.end_outcome())
            # Mode callbacks can save the finished replay, so record the tick first.
            if not self._on_tick_applied(step) or (step.outcome is not None and not self._RUN_DOWN_ON_OUTCOME):
                break
            if (self._pause_pending or self._run_ending) and self._run_down_gameplay(ftol_ms_i32(step.dt_sim), session):
                break
        apply_presentation_plans(plans=plans, runtime=self._world_runtime)
