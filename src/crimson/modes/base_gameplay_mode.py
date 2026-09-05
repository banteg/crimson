from __future__ import annotations

import datetime as dt
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.audio import AudioState, stop_music, update_audio
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
from ..local_input import LocalInputInterpreter, clear_input_edges
from ..perks import PerkId
from ..perks.helpers import perk_count_get
from ..perks.runtime.effects_context import creature_find_in_radius
from ..perks.selection import perk_selection_open_choices
from ..persistence.highscores import HighScoreRecord
from ..render.rtx.mode import RtxRenderMode
from ..replay import Replay, ReplayClaimedStatsSnapshot, dump_replay
from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINTS_FORMAT_VERSION,
)
from ..replay.checkpoints import (
    ReplayCheckpoint,
    ReplayCheckpoints,
    build_checkpoint,
    default_checkpoints_path,
    dump_checkpoints_file,
)
from ..screens.results.game_over import GameOverUi
from ..sim.batch_apply import (
    PresentationTickOutput,
    apply_presentation_outputs,
    apply_sim_metadata_tick_result,
)
from ..sim.clock import FixedStepClock
from ..sim.frame_pump import advance_tick_runner_frame
from ..sim.hooks import (
    TickResult,
)
from ..sim.input import PlayerInput
from ..sim.input_providers import (
    FrameContext,
    GameCommand,
    InputStatus,
    LocalInputProvider,
    LocalInputRuntime,
    PerkMenuOpenCommand,
    PerkPickCommand,
)
from ..sim.sessions import DeterministicSession, DeterministicSessionTick
from ..sim.tick_runner import TickRunner
from ..terrain_slots import TerrainSlotTriplet
from ..ui.hud import HudState, draw_target_health_bar
from ..weapon_runtime import most_used_weapon_id_for_player
from ..world.runtime import WorldRuntime
from .components.highscore_record_builder import shots_from_state
from .components.perk_menu_controller import PerkMenuController, PerkMenuRuntime, PerkMenuUiContext

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureDeath, CreaturePool
    from ..game.types import GameState
    from ..gameplay import GameplayState
    from ..persistence.save_status import GameStatus
    from ..replay import ReplayRecorder
    from ..sim.state_types import PlayerState
    from ..sim.world_state import WorldEvents


class _ModeLocalInputRuntime(LocalInputRuntime):
    mode: BaseGameplayMode

    def capture_frame_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        return self.mode._build_local_inputs(dt=float(frame_ctx.dt_seconds))


class _ModePerkMenuRuntime(PerkMenuRuntime):
    mode: BaseGameplayMode

    def on_close(self) -> None:
        self.mode._perk_menu_closed()

    def play_sfx(self, sfx_id: SfxId) -> None:
        self.mode.audio_bridge.router.play_sfx(sfx_id)


class _ModeFrameState(msgspec.Struct, frozen=True):
    dt: float
    dt_ui_ms: float


class BaseGameplayMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        world_size: float,
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
        self._action: str | None = None
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
        self.world_size = float(world_size)
        self.demo_mode_active = bool(demo_mode_active)
        self.quest_fail_retry_count = int(quest_fail_retry_count)
        self.hardcore = bool(hardcore)
        self.preserve_bugs = bool(ctx.preserve_bugs)
        self.audio = audio
        self.audio_rng = audio_rng
        self.rtx_mode = RtxRenderMode.CLASSIC
        self._world_runtime = WorldRuntime(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            quest_fail_retry_count=int(self.quest_fail_retry_count),
            hardcore=bool(self.hardcore),
            preserve_bugs=bool(self.preserve_bugs),
            config=self.config,
            audio=self.audio,
            audio_rng=self.audio_rng,
            rtx_mode=self.rtx_mode,
        )
        self.sim_world = self._world_runtime.sim_world
        self.render_resources = self._world_runtime.render_resources
        self.audio_bridge = self._world_runtime.audio_bridge
        self.terrain_runtime = self._world_runtime.terrain_runtime
        self.renderer = self._world_runtime.renderer
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
        self._replay_checkpoints_sample_rate = 60
        self._replay_checkpoints_last_tick: int | None = None
        self._runtime_updates_per_frame = 0
        self._input_stall_count = 0
        self._ticks_advanced_per_frame = 0
        self._sim_ms = 0.0
        self._presentation_plan_ms = 0.0
        self._presentation_apply_ms = 0.0
        self._queued_input_commands: list[GameCommand] = []
        self._sim_session: DeterministicSession | None = None
        self._tick_input_provider: LocalInputProvider | None = None
        self._tick_runner: TickRunner | None = None
        self._tick_runner_session: DeterministicSession | None = None
        self._tick_runner_frame_index = 0
        self._tick_runner_next_tick_index = 0
        self._tick_runner_local_clock: FixedStepClock | None = None

    @property
    def world_runtime(self) -> WorldRuntime:
        return self._world_runtime

    @property
    def camera(self) -> Vec2:
        return self._world_runtime.camera

    @camera.setter
    def camera(self, value: Vec2) -> None:
        self._world_runtime.camera = value

    def _sync_world_runtime_config(self) -> None:
        runtime = self._world_runtime
        runtime.world_size = float(self.world_size)
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
        return self.renderer.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self.renderer.screen_to_world(pos)

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
        target_players = self.sim_world.players[:1] if self.state.preserve_bugs else self.sim_world.players
        for target_player in target_players:
            if not self.state.preserve_bugs and float(target_player.health) <= 0.0:
                continue
            if perk_count_get(target_player, PerkId.DOCTOR) <= 0:
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
            draw_target_health_bar(pos=screen_left, width=width, ratio=ratio, alpha=alpha, scale=width / 64.0)

    def _bind_world(self) -> None:
        self.state: GameplayState = self.sim_world.state
        self.creatures: CreaturePool = self.sim_world.creatures
        self.player: PlayerState = self.sim_world.players[0]
        preserve_bugs = self.state.preserve_bugs
        self._local_input.set_preserve_bugs(preserve_bugs)
        self._hud_state.preserve_bugs = preserve_bugs
        self._game_over_ui.preserve_bugs = preserve_bugs
        self.state.status = self._status_sim

    def _any_player_alive(self) -> bool:
        return any(player.health > 0.0 for player in self.sim_world.players)

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
            update_audio(self.audio, dt)

    def _ui_line_height(self, scale: float = 1.0) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _ui_text_width(self, text: str, scale: float = 1.0) -> int:
        _ = scale
        font = self._small
        assert font is not None, "small font must be loaded before ui text measurement"
        return int(measure_small_text_width(font, text))

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color, scale: float = 1.0) -> None:
        _ = scale
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
            violence_disabled=self.config.display.violence_disabled,
            preserve_bugs=bool(self.state.preserve_bugs),
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
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
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
        self._reset_frame_telemetry()
        self._handle_input()
        if self._action == "open_pause_menu":
            return None
        return _ModeFrameState(
            dt=float(frame_dt),
            dt_ui_ms=float(frame_dt_ui_ms),
        )

    def _handle_input(self) -> None:
        raise NotImplementedError

    def set_runtime_updates_per_frame(self, value: int) -> None:
        self._runtime_updates_per_frame = max(0, int(value))

    def enqueue_input_command(self, command: GameCommand) -> None:
        provider = self._tick_input_provider
        if provider is None:
            self._queued_input_commands.append(command)
            return
        if not provider.supports_command_submission():
            self._queued_input_commands.append(command)
            return
        provider.submit_command(command)

    def _flush_queued_input_commands(
        self,
        *,
        provider: LocalInputProvider,
    ) -> None:
        if not self._queued_input_commands:
            return
        if not provider.supports_command_submission():
            return
        for command in self._queued_input_commands:
            provider.submit_command(command)
        self._queued_input_commands.clear()

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
        return float(self.sim_world.presentation_elapsed_ms)

    def _replay_claimed_stats_complete(self) -> bool:
        return False

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        return int(self._replay_checkpoint_elapsed_ms())

    def _replay_claimed_shots(self) -> tuple[int, int]:
        return shots_from_state(self.state, player_index=int(self.player.index))

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        mode_name = str(self.__class__.__name__).replace("Mode", "").lower() or "replay"
        return f"{mode_name}_{stamp}"

    def _replay_skip_save_when_empty(self, *, recorder: ReplayRecorder) -> bool:
        _ = recorder
        return False

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
        if tick_index < 0:
            return
        if not force and (tick_index % int(self._replay_checkpoints_sample_rate or 1)) != 0:
            return
        if self._replay_checkpoints_last_tick == int(tick_index):
            return
        self._replay_checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=self.sim_world.world_state,
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
        if self._replay_skip_save_when_empty(recorder=recorder):
            self._replay_recorder = None
            self._replay_checkpoints.clear()
            self._replay_checkpoints_last_tick = None
            return

        self._record_replay_checkpoint(max(0, int(recorder.tick_index) - 1), force=True)
        replay = recorder.finish()

        shots_fired, shots_hit = self._replay_claimed_shots()
        most_used_weapon_id = most_used_weapon_id_for_player(
            self.state,
            player_index=int(self.player.index),
            fallback_weapon_id=self.player.weapon.weapon_id,
        )
        claimed_stats = ReplayClaimedStatsSnapshot(
            complete=bool(self._replay_claimed_stats_complete()),
            ticks=int(recorder.tick_index),
            elapsed_ms=int(self._replay_claimed_stats_elapsed_ms()),
            score_xp=int(self.player.experience),
            kills=int(self.creatures.kill_count),
            most_used_weapon_id=most_used_weapon_id,
            shots_fired=int(shots_fired),
            shots_hit=int(shots_hit),
        )
        replay = msgspec.structs.replace(
            replay,
            header=msgspec.structs.replace(
                replay.header,
                claimed_stats=claimed_stats,
            ),
        )

        data = dump_replay(replay)
        stamp = dt.datetime.now(tz=dt.UTC).astimezone().strftime("%Y%m%d_%H%M%S")
        replay_dir = self._base_dir / "replays"
        replay_dir.mkdir(parents=True, exist_ok=True)
        base_name = self._replay_output_basename(stamp=stamp, replay=replay)
        path = replay_dir / f"{base_name}.crd"
        counter = 1
        while path.exists():
            path = replay_dir / f"{base_name}_{counter}.crd"
            counter += 1
        path.write_bytes(data)

        checkpoints_path = default_checkpoints_path(path)
        dump_checkpoints_file(
            checkpoints_path,
            ReplayCheckpoints(
                version=CHECKPOINTS_FORMAT_VERSION,
                sample_rate=int(self._replay_checkpoints_sample_rate or 0),
                checkpoints=list(self._replay_checkpoints),
            ),
        )
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        if self._console is not None:
            self._console.log.log(f"replay: saved {path}")
            self._console.log.log(f"replay: saved {checkpoints_path}")
            self._console.log.flush()

    def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
        return (
            int(self._runtime_updates_per_frame),
            int(self._input_stall_count),
            int(self._ticks_advanced_per_frame),
            float(self._sim_ms),
            float(self._presentation_plan_ms),
            float(self._presentation_apply_ms),
        )

    def _reset_frame_telemetry(self) -> None:
        self._input_stall_count = 0
        self._ticks_advanced_per_frame = 0
        # Placeholder stage timers before profiler hooks land in later slices.
        self._sim_ms = 0.0
        self._presentation_plan_ms = 0.0
        self._presentation_apply_ms = 0.0

    def _player_name_default(self) -> str:
        return str(self.config.profile.player_name or "")

    def _runtime_player_count(self) -> int:
        return self.config.gameplay.player_count

    def _deterministic_detail_preset(self) -> int:
        return self.config.display.detail_preset

    def _deterministic_violence_disabled(self) -> int:
        return self.config.display.violence_disabled

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
        self._local_input.reset(players=self.sim_world.players)
        self._reset_tick_runner_state()
        self._reset_replay_capture_state(clear_recorder=False)

        self._ui_mouse = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5)
        self._cursor_pulse_time = 0.0

    def close(self) -> None:
        self._game_over_ui.close()
        if self._small is not None:
            self._small = None
        self._reset_tick_runner_state()
        self._reset_replay_capture_state(clear_recorder=True)
        self._world_runtime.close_runtime()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _enter_game_over(self) -> None:
        raise NotImplementedError

    def _update_game_over_ui(self, dt: float) -> None:
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
            play_sfx=self.audio_bridge.router.play_sfx,
            rng=None,
            mouse=self._ui_mouse_pos(),
        )
        if action == "play_again":
            self.open()
            return
        if action == "high_scores":
            self._action = "open_high_scores"
            return
        if action == "main_menu":
            self._action = "back_to_menu"
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
        if current is not None and current is not ground and current.render_target is not None:
            rl.unload_render_texture(current.render_target)
            current.render_target = None
        self.render_resources.ground = ground

    def menu_ground_camera(self) -> Vec2:
        return self.camera

    def console_elapsed_ms(self) -> float:
        return float(self.sim_world.presentation_elapsed_ms)

    def prepare_demo_trial_overlay_frame(self) -> None:
        self._world_runtime.update_camera(0.0)
        self._sync_audio_and_ground()

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
        rl.draw_rectangle(0, 0, int(rl.get_screen_width()), int(rl.get_screen_height()), rl.Color(0, 0, 0, alpha))

    def _build_local_inputs(self, *, dt: float) -> list[PlayerInput]:
        return self._local_input.build_frame_inputs(
            players=self.sim_world.players,
            config=self.config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self.screen_to_world,
            dt=float(dt),
            creatures=self.creatures.entries,
        )

    @staticmethod
    def _clear_local_input_edges(inputs: list[PlayerInput]) -> list[PlayerInput]:
        return clear_input_edges(inputs)

    @staticmethod
    def _deterministic_tick_rate() -> int:
        return 60

    def _gameplay_tick_rate(self) -> int:
        return int(self._deterministic_tick_rate())

    def _gameplay_tick_dt(
        self,
        *,
        session: DeterministicSession | None = None,
    ) -> float:
        _ = session
        return 1.0 / float(self._gameplay_tick_rate())

    def _reset_gameplay_frame_clock(self) -> None:
        if self._tick_input_provider is not None:
            self._tick_input_provider.clear_pending_edges()
        clock = self._tick_runner_local_clock
        if clock is not None:
            clock.reset()

    def _reset_tick_runner_state(self) -> None:
        self._tick_input_provider = None
        self._tick_runner = None
        self._tick_runner_session = None
        self._tick_runner_frame_index = 0
        self._tick_runner_next_tick_index = 0
        self._tick_runner_local_clock = None

    def _reset_replay_capture_state(self, *, clear_recorder: bool) -> None:
        self._queued_input_commands.clear()
        if clear_recorder:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def _ensure_tick_runner(self, *, session: DeterministicSession) -> tuple[TickRunner, LocalInputProvider]:
        if self._tick_runner is not None and self._tick_runner_session is session:
            assert self._tick_input_provider is not None
            return self._tick_runner, self._tick_input_provider
        provider = LocalInputProvider(
            player_count=len(self.sim_world.players),
            runtime=_ModeLocalInputRuntime(mode=self),
        )
        self._flush_queued_input_commands(provider=provider)
        runner = TickRunner(session=session, input_provider=provider)
        self._tick_runner = runner
        self._tick_input_provider = provider
        self._tick_runner_session = session
        self._tick_runner_frame_index = 0
        self._tick_runner_next_tick_index = 0
        self._tick_runner_local_clock = FixedStepClock(tick_rate=self._gameplay_tick_rate())
        return runner, provider

    def _record_replay_checkpoint_from_tick(
        self,
        *,
        tick_index: int | None,
        tick: DeterministicSessionTick,
    ) -> None:
        if tick_index is None:
            return
        world_events = tick.events
        self._record_replay_checkpoint(
            int(tick_index),
            deaths=world_events.deaths,
            events=world_events,
        )

    def _on_tick_applied(
        self,
        tick: DeterministicSessionTick,
        dt_tick: float,
    ) -> bool:
        _ = tick, dt_tick
        return True

    def _sync_audio_and_ground(self) -> None:
        self._world_runtime.sync_audio_bridge_state()
        if self.render_resources.ground is not None:
            self.render_resources.ground.process_pending()

    def _run_deterministic_session_ticks(
        self,
        *,
        dt_frame: float,
        session: DeterministicSession,
        recorder: ReplayRecorder | None,
    ) -> None:
        if float(dt_frame) <= 0.0:
            return
        self._sync_audio_and_ground()
        session.detail_preset = int(self._deterministic_detail_preset())
        session.violence_disabled = int(self._deterministic_violence_disabled())
        runner, _provider = self._ensure_tick_runner(
            session=session,
        )
        local_clock = self._tick_runner_local_clock
        if local_clock is None:
            local_clock = FixedStepClock(tick_rate=int(self._gameplay_tick_rate()))
            self._tick_runner_local_clock = local_clock

        candidate_ticks = int(local_clock.advance(float(dt_frame)))
        tick_dt = float(local_clock.dt_tick)
        outputs: list[PresentationTickOutput] = []
        self._presentation_plan_ms = 0.0

        def after_tick(result: TickResult) -> bool:
            self._presentation_plan_ms += session.last_presentation_plan_ms
            if recorder is not None:
                result.replay_tick_index = recorder.record_tick(
                    result.source_tick.inputs,
                    commands=result.source_tick.commands,
                )
            outputs.append(
                apply_sim_metadata_tick_result(
                    sim_world=self.sim_world,
                    tick_result=result,
                    game_tune_started=session.game_tune_started,
                ),
            )
            self._ticks_advanced_per_frame += 1
            self._record_replay_checkpoint_from_tick(tick_index=result.replay_tick_index, tick=result.payload)
            # Mode callbacks can save the finished replay; record this tick first.
            return self._on_tick_applied(result.payload, tick_dt)

        sim_ns_start = time.perf_counter_ns()
        advance = advance_tick_runner_frame(
            runner=runner,
            start_tick=int(self._tick_runner_next_tick_index),
            frame_index=int(self._tick_runner_frame_index),
            ticks_requested=int(candidate_ticks),
            dt_seconds=float(dt_frame),
            tick_dt_seconds=float(tick_dt),
            is_replay=False,
            refund_clock=local_clock,
            after_tick=after_tick,
        )
        self._tick_runner_frame_index = int(advance.frame_index)
        self._tick_runner_next_tick_index = int(advance.next_tick_index)
        batch = advance.batch
        self._sim_ms = float((time.perf_counter_ns() - sim_ns_start) / 1_000_000.0)

        apply_ns_start = time.perf_counter_ns()
        apply_presentation_outputs(outputs=outputs, runtime=self._world_runtime, apply_audio=True)
        self._presentation_apply_ms = float((time.perf_counter_ns() - apply_ns_start) / 1_000_000.0)
        if batch.batch_status is InputStatus.STALLED and int(batch.ticks_completed) <= 0:
            self._input_stall_count += 1
