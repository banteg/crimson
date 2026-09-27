from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from crimson.screens.actions import ResultAction, Route, ScoreQuery, ScoreReturnContext, ScreenAction, ShowScores
from grim import canvas
from grim.audio import AudioState, play_music, stop_music, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer
from grim.view import ViewContext

from ..game_modes import GameMode
from ..local_input import LocalInputInterpreter
from ..perks import PerkId
from ..perks.runtime.effects_context import creature_find_in_radius
from ..perks.selection import perk_selection_open_choices
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
from ..sim.batch_apply import apply_presentation_plans
from ..sim.clock import FixedStepClock
from ..sim.commands import GameCommand, PerkMenuOpenCommand, PerkPickCommand
from ..sim.input import PlayerInput
from ..sim.presentation_step import DeterministicPresentationPlan
from ..sim.run_init import PreparedRun, initialize_run
from ..sim.run_result import RunResult, build_run_result
from ..sim.run_spec import RunSpec, RunStatus
from ..sim.sessions import DeterministicSession, DeterministicSessionTick
from ..terrain_slots import TerrainSlotTriplet
from ..ui.hud import HudState, draw_target_health_bar
from ..world.runtime import WorldRuntime
from .components.perk_menu_controller import PerkMenuController, PerkMenuRuntime, PerkMenuUiContext

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureDeath, CreaturePool
    from ..game.types import GameState
    from ..persistence.save_status import GameStatus
    from ..sim.state_types import PlayerState
    from ..sim.world_state import WorldEvents, WorldState


class _ModePerkMenuRuntime(PerkMenuRuntime):
    mode: BaseGameplayMode

    def on_close(self) -> None:
        self.mode._perk_menu_closed()

    def play_sfx(self, sfx_id: SfxId) -> None:
        self.mode.audio_bridge.play_sfx(sfx_id)


class _ModeFrameState(msgspec.Struct, frozen=True):
    dt: float
    dt_ui_ms: float


class BaseGameplayMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        default_game_mode_id: GameMode,
        demo_mode_active: bool = False,
        quest_fail_retry_count: int = 0,
        hardcore: bool = False,
        config: CrimsonConfig,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand,
    ) -> None:
        self._assets_root = ctx.assets_dir
        self._small: SmallFontData | None = None
        self._hud_state = HudState()
        self.default_game_mode_id = default_game_mode_id

        self.config: CrimsonConfig = config
        self._console = console
        self._base_dir = self.config.path.parent

        self.close_requested = False
        self._action: ScreenAction | None = None
        self._paused = False
        self._status_base: GameStatus | None = None
        self._status_sim: GameStatus | None = None
        self._local_input: LocalInputInterpreter = LocalInputInterpreter()
        self._game_over_ui: GameOverUi = GameOverUi(
            assets_root=self._assets_root,
            base_dir=self._base_dir,
            config=self.config,
            preserve_bugs=ctx.preserve_bugs,
        )

        self.assets_dir = ctx.assets_dir
        self.demo_mode_active = bool(demo_mode_active)
        self.quest_fail_retry_count = int(quest_fail_retry_count)
        self.hardcore = bool(hardcore)
        self.preserve_bugs = bool(ctx.preserve_bugs)
        self.audio = audio
        self.audio_rng = audio_rng
        self.rtx_mode = RtxRenderMode.CLASSIC
        self._world_runtime = WorldRuntime(
            assets_dir=self.assets_dir,
            demo_mode_active=bool(self.demo_mode_active),
            quest_fail_retry_count=int(self.quest_fail_retry_count),
            hardcore=bool(self.hardcore),
            preserve_bugs=bool(self.preserve_bugs),
            config=self.config,
            audio=self.audio,
            audio_rng=self.audio_rng,
            rtx_mode=self.rtx_mode,
        )
        self.render_resources = self._world_runtime.render_resources
        self.audio_bridge = self._world_runtime.audio_bridge
        self.terrain_runtime = self._world_runtime.terrain_runtime

        self.camera = Vec2(-1.0, -1.0)
        self._sync_world_runtime_config()
        player_count = self._runtime_player_count()
        self._world_runtime.reset(player_count=max(1, min(4, int(player_count))))
        self._bind_world()

        self._game_over_active = False
        self._game_over_record: HighScoreRecord | None = None
        self._game_over_banner = "reaper"

        self._ui_mouse = Vec2()
        self._cursor_pulse_time = 0.0
        self._last_dt_ms = 0.0
        self._screen_fade: GameState | None = None
        self._terrain_regen_counter = 0
        self._run_reset_seed = 0
        self._replay_recorder: ReplayRecorder | None = None
        self._replay_checkpoints: list[ReplayCheckpoint] = []
        # Checkpoint sidecars are a parity-debugging aid; off unless requested.
        self._replay_checkpoints_enabled = bool(ctx.replay_checkpoints)
        self._replay_checkpoints_last_tick: int | None = None
        self._replay_result: RunResult | None = None
        self._sim_session: DeterministicSession | None = None
        self._live_ticks = LiveTickSource()
        self._tick_clock = FixedStepClock(tick_rate=REPLAY_TICK_RATE)

    @property
    def world_runtime(self) -> WorldRuntime:
        return self._world_runtime

    @property
    def world(self) -> WorldState:
        return self._world_runtime.world

    @property
    def camera(self) -> Vec2:
        return self._world_runtime.camera

    @camera.setter
    def camera(self, value: Vec2) -> None:
        self._world_runtime.camera = value

    def _sync_world_runtime_config(self) -> None:
        runtime = self._world_runtime
        runtime.demo_mode_active = bool(self.demo_mode_active)
        runtime.quest_fail_retry_count = int(self.quest_fail_retry_count)
        runtime.hardcore = bool(self.hardcore)
        runtime.preserve_bugs = bool(self.preserve_bugs)
        runtime.config = self.config
        runtime.audio = self.audio
        runtime.audio_rng = self.audio_rng
        runtime.rtx_mode = self.rtx_mode

    def apply_terrain_setup(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
        seed: int,
    ) -> None:
        self.terrain_runtime.apply_terrain_setup(terrain_slots=terrain_slots, seed=seed)

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._world_runtime.draw(
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

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

    def _draw_target_health_bar(self, *, alpha: float = 1.0) -> None:
        creatures = self.creatures.entries
        if not creatures:
            return

        target_indices: list[int] = []
        target_players = self.world.players[:1] if self.state.preserve_bugs else self.world.players
        for target_player in target_players:
            if not self.state.preserve_bugs and float(target_player.health) <= 0.0:
                continue
            if self.state.perks[PerkId.DOCTOR] <= 0:
                continue
            target_idx = creature_find_in_radius(
                creatures,
                pos=target_player.aim,
                radius=12.0,
                start_index=0,
            )
            if target_idx == -1:
                continue
            if target_idx in target_indices:
                continue
            target_indices.append(int(target_idx))

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

    def _bind_world(self) -> None:
        self.state: GameplayState = self.world.state
        self.creatures: CreaturePool = self.world.creatures
        self.player: PlayerState = self.world.players[0]
        preserve_bugs = self.state.preserve_bugs
        self._local_input.set_preserve_bugs(preserve_bugs)
        self._hud_state.preserve_bugs = preserve_bugs
        self._game_over_ui.preserve_bugs = preserve_bugs
        self.state.status = self._status_sim

    def _any_player_alive(self) -> bool:
        return any(player.health > 0.0 for player in self.world.players)

    @property
    def save_status(self) -> GameStatus | None:
        return self._status_base

    @property
    def sim_status(self) -> GameStatus | None:
        return self._status_sim

    def bind_status(self, status: GameStatus | None) -> None:
        self._status_base = status
        self._status_sim = status
        self.state.status = status

    def bind_screen_fade(self, fade: GameState | None) -> None:
        self._screen_fade = fade

    def bind_audio(self, audio: AudioState | None, audio_rng: Crand) -> None:
        self.audio = audio
        self.audio_rng = audio_rng
        self._world_runtime.audio = audio
        self._world_runtime.audio_rng = audio_rng

    def set_rtx_mode(self, mode: RtxRenderMode) -> None:
        self.rtx_mode = mode
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

    def _perk_menu_runtime(self) -> PerkMenuRuntime:
        return _ModePerkMenuRuntime(mode=self)

    def _perk_menu_closed(self) -> None:
        return None

    def _perk_menu_ui_context(self) -> PerkMenuUiContext:
        return PerkMenuUiContext(
            player=self.player,
            perks=self.state.perks,
            violence_disabled=self.config.display.violence_disabled,
            shadows_enabled=self.config.display.shadows_enabled,
            resources=self.render_resources.resources,
            mouse=self._ui_mouse_pos(),
        )

    def _open_perk_menu_ui(
        self,
        *,
        menu: PerkMenuController,
        players: list[PlayerState],
        game_mode: GameMode,
        player_count: int,
    ) -> None:
        if menu.active:
            return
        recorder = getattr(self, "_replay_recorder", None)
        if recorder is not None:
            self._record_replay_checkpoint(max(0, int(recorder.tick_index) - 1), force=True)
        choices = perk_selection_open_choices(
            self.state,
            players,
            self.state.perk_selection,
            game_mode=game_mode,
            player_count=int(player_count),
        )
        assert choices, "perk menu open requires prepared perk choices"
        menu.open_menu()
        self.enqueue_input_command(PerkMenuOpenCommand(player_index=0))

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

    def _tick_frame(self, dt: float, *, clamp_cursor_pulse: bool = False) -> tuple[float, float]:
        dt = float(dt)
        dt_ui_ms = float(min(dt, 0.1) * 1000.0)
        self._last_dt_ms = dt_ui_ms

        self._update_ui_mouse()

        pulse_dt = float(min(dt, 0.1)) if clamp_cursor_pulse else dt
        self._cursor_pulse_time += pulse_dt * 1.1

        return dt, dt_ui_ms

    def _begin_mode_update(self, dt: float) -> _ModeFrameState | None:
        self._update_audio(dt)

        frame_dt, frame_dt_ui_ms = self._tick_frame(dt)
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
        self._small = load_small_font(self._assets_root)
        self._hud_state = HudState()

        self._game_over_active = False
        self._game_over_record = None
        self._game_over_banner = "reaper"
        self._game_over_ui.close()

        # Native game_over/victory transitions call `sfx_mute_all` on menu + extra
        # tracks before restarting gameplay ("Play Again"), resetting first-hit tune gate.
        stop_music(self.audio)

        player_count = self._runtime_player_count()
        seed = int(self.state.rng.state)
        self._run_reset_seed = int(seed) & 0xFFFFFFFF

        self._sync_world_runtime_config()
        self._world_runtime.reset(seed=seed, player_count=max(1, min(4, int(player_count))))
        self._world_runtime.open_runtime()
        self._bind_world()
        self._local_input.reset(players=self.world.players)
        self._reset_live_ticks()
        self._reset_replay_capture_state(clear_recorder=False)

        self._ui_mouse = Vec2(float(canvas.width()) * 0.5, float(canvas.height()) * 0.5)
        self._cursor_pulse_time = 0.0

    def _initialize_run(
        self,
        game_mode: GameMode,
        *,
        quest_level: QuestLevel | None = None,
        dictionary_words: tuple[str, ...] = (),
        highscore_names: tuple[str, ...] = (),
    ) -> PreparedRun:
        status = self.state.status
        spec = RunSpec(
            game_mode_id=game_mode,
            seed=self._run_reset_seed,
            quest_level=quest_level,
            player_count=self._runtime_player_count(),
            hardcore=self.hardcore,
            preserve_bugs=self.state.preserve_bugs,
            demo=self.demo_mode_active,
            quest_fail_retry_count=self.quest_fail_retry_count,
            detail_preset=self.config.display.detail_preset,
            violence_disabled=self.config.display.violence_disabled,
            status=RunStatus() if status is None else RunStatus.from_status_data(status.as_data()),
            typo_dictionary_words=dictionary_words,
            typo_highscore_names=highscore_names,
        )
        prepared = initialize_run(spec, status=status)
        self._world_runtime.load_world_state(prepared.session.world)
        self._status_sim = prepared.session.world.state.status
        self._bind_world()
        self._local_input.reset(players=self.world.players)
        self.apply_terrain_setup(terrain_slots=prepared.terrain.terrain_slots, seed=prepared.terrain.terrain_seed)
        self._reset_live_ticks()
        self._replay_recorder = ReplayRecorder(spec)
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._replay_result = None
        return prepared

    def resume(self) -> None:
        self._action = None
        self._reset_gameplay_frame_clock()

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
        raise NotImplementedError

    def _update_game_over_ui(self, dt: float) -> None:
        if self.audio is not None and not self._game_over_ui.closing:
            play_music(self.audio, "shortie_monk")
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
        if not self._game_over_active:
            return 1.0
        return float(self._game_over_ui.world_entity_alpha())

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        alpha = float(entity_alpha)
        if alpha < 0.0:
            alpha = 0.0
        elif alpha > 1.0:
            alpha = 1.0
        self._draw_world(draw_aim_indicators=False, entity_alpha=self._world_entity_alpha() * alpha)

    def steal_ground_for_menu(self):
        ground = self.render_resources.ground
        self.render_resources.ground = None
        return ground

    def adopt_ground_from_menu(self, ground: GroundRenderer | None) -> None:
        if ground is None:
            return
        current = self.render_resources.ground
        if current is not None and current is not ground:
            current.close()
        self.render_resources.ground = ground

    def menu_ground_camera(self) -> Vec2:
        return self.camera

    def console_elapsed_ms(self) -> float:
        return float(self._world_runtime.presentation_elapsed_ms)

    def prepare_demo_trial_overlay_frame(self) -> None:
        self._world_runtime.update_camera()
        self._sync_audio()

    def regenerate_terrain_for_console(self) -> None:
        if self.render_resources.ground is None:
            return
        # Keep this deterministic without consuming gameplay RNG.
        self._terrain_regen_counter = (int(self._terrain_regen_counter) + 1) & 0xFFFFFFFF
        terrain_seed = (int(self.state.rng.state) + int(self._terrain_regen_counter)) & 0xFFFFFFFF
        self.render_resources.ground.schedule_generate(seed=terrain_seed)

    def _draw_screen_fade(self) -> None:
        fade_alpha = 0.0
        if self._screen_fade is not None:
            fade_alpha = float(self._screen_fade.screen_fade_alpha)
        if fade_alpha <= 0.0:
            return
        alpha = int(255 * max(0.0, min(1.0, fade_alpha)))
        rl.draw_rectangle(0, 0, int(canvas.width()), int(canvas.height()), rl.Color(0, 0, 0, alpha))

    def _build_local_inputs(self, *, dt: float) -> list[PlayerInput]:
        return self._local_input.build_frame_inputs(
            players=self.world.players,
            config=self.config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self.screen_to_world,
            dt=float(dt),
            creatures=self.creatures.entries,
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

    def _on_tick_applied(self, tick: DeterministicSessionTick) -> bool:
        _ = tick
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
        self._live_ticks.poll(self._build_local_inputs(dt=float(dt_frame)))
        plans: list[DeterministicPresentationPlan] = []
        for _ in range(self._tick_clock.advance(float(dt_frame))):
            tick = self._live_ticks.next_tick()
            tick_index = recorder.record(tick) if recorder is not None else None
            step = step_replay_tick(session, tick)
            self._world_runtime.advance_presentation_clock(
                dt_sim=step.dt_sim,
                game_tune_started=session.game_tune_started,
            )
            plans.append(step.presentation)
            if tick_index is not None:
                self._record_replay_checkpoint(tick_index, deaths=step.events.deaths, events=step.events)
            if recorder is not None:
                # The replay result is the state after the last recorded tick:
                # UI work between ticks (perk menu previews, the high-score tag
                # draw at game over) must not leak into it.
                self._replay_result = build_run_result(session, outcome=step.outcome or session.end_outcome())
            # Mode callbacks can save the finished replay, so record the tick
            # first. The run's final tick ends the frame.
            if not self._on_tick_applied(step) or step.outcome is not None:
                break
        apply_presentation_plans(plans=plans, runtime=self._world_runtime, apply_audio=True)
