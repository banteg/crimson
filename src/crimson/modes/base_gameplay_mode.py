from __future__ import annotations

import datetime as dt
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Literal, TypeAlias, cast

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

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..local_input import LocalInputInterpreter, clear_input_edges
from ..net.debug_log import lan_debug_log
from ..net.deterministic_status import build_lan_deterministic_status
from ..net.lockstep_protocol import (
    TickFrame,
)
from ..net.lockstep_runtime import LockstepRuntime
from ..net.rollback_resync_v5 import (
    ModeStateSnapshotV2,
    ReplayStateSnapshotV2,
    RollbackResyncV5Error,
    decode_mode_snapshot,
    encode_mode_snapshot,
)
from ..net.rollback_runtime import RollbackRuntime
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
from ..replay.input_codec import pack_player_input, unpack_player_input
from ..screens.results.game_over import GameOverUi
from ..sim.batch_apply import (
    PresentationTickOutput,
    apply_presentation_outputs,
    apply_sim_metadata_tick_result,
)
from ..sim.clock import FixedStepClock
from ..sim.frame_pump import advance_tick_runner_frame
from ..sim.hooks import (
    LanFrameSample,
    LanTickSync,
    TickResult,
)
from ..sim.input import PlayerInput
from ..sim.input_providers import (
    FrameContext,
    GameCommand,
    InputStatus,
    LocalInputProvider,
    PerkMenuOpenCommand,
    PerkPickCommand,
    ResolvedTick,
    TickSupply,
)
from ..sim.presentation_reactions import (
    PostApplyReaction,
    apply_post_apply_reaction,
    build_post_apply_reaction,
)
from ..sim.sessions import DeterministicSession, DeterministicSessionTick
from ..sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from ..terrain_slots import TerrainSlotTriplet
from ..ui.hud import HudState, draw_target_health_bar
from ..weapon_runtime import most_used_weapon_id_for_player
from ..world.runtime import WorldRuntime
from .components.highscore_record_builder import shots_from_state
from .components.perk_menu_controller import PerkMenuController, PerkMenuUiContext

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureDeath, CreaturePool
    from ..game.types import GameState
    from ..gameplay import GameplayState
    from ..persistence.save_status import GameStatus, GameStatusData
    from ..replay import ReplayRecorder
    from ..sim.state_types import PlayerState
    from ..sim.world_state import WorldEvents

LanRuntime = LockstepRuntime | RollbackRuntime


class _AppliedBatchTick(msgspec.Struct):
    tick: DeterministicSessionTick
    replay_tick_index: int | None
    frame_tick_index: int | None = None


class _BatchApplyOutcome(msgspec.Struct, frozen=True):
    ticks_applied: int = 0
    stopped: bool = False
    stop_after_finalize: bool = False
    presentation_outputs: tuple[PresentationTickOutput, ...] = ()
    post_apply_reactions: tuple[PostApplyReaction, ...] = ()


class _ModeFrameState(msgspec.Struct, frozen=True):
    dt: float
    dt_ui_ms: float


LanStepAction = Literal["continue", "stop_before_finalize", "stop_after_finalize"]

LanSession: TypeAlias = DeterministicSession


class _LanRuntimeInputProvider:
    def __init__(self, *, player_count: int, tick_rate: int) -> None:
        _ = player_count
        self._runtime: LanRuntime | None = None
        self._role: str = ""
        self._samples_by_runner_tick: dict[int, LanFrameSample] = {}
        self._before_pop: Callable[[], bool] | None = None
        self._pop_blocked = False
        self._capture_clock = FixedStepClock(tick_rate=max(1, int(tick_rate)))

    def bind_runtime(self, runtime: LanRuntime | None) -> None:
        self._runtime = runtime
        self._samples_by_runner_tick.clear()
        self._pop_blocked = False

    def set_role(self, role: str) -> None:
        self._role = str(role)

    def set_before_pop(self, callback: Callable[[], bool] | None) -> None:
        self._before_pop = callback
        self._pop_blocked = False

    @property
    def pop_blocked(self) -> bool:
        return bool(self._pop_blocked)

    @property
    def capture_tick_dt(self) -> float:
        return self._capture_clock.dt_tick

    def advance_capture_ticks(self, dt: float) -> int:
        return self._capture_clock.advance(dt)

    def reset_capture_clock(self) -> None:
        self._capture_clock.reset()

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        self._samples_by_runner_tick.clear()
        self._pop_blocked = False

    def take_frame_sample(self, runner_tick_index: int) -> LanFrameSample | None:
        return self._samples_by_runner_tick.pop(int(runner_tick_index), None)

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        self._pop_blocked = False
        before_pop = self._before_pop
        if before_pop is not None and (not bool(before_pop())):
            self._pop_blocked = True
            return TickSupply(status=InputStatus.STALLED, tick=None)
        runtime = self._runtime
        if runtime is None:
            return TickSupply(status=InputStatus.STALLED, tick=None)
        frame = runtime.pop_tick_frame()
        if frame is None:
            return TickSupply(status=InputStatus.STALLED, tick=None)
        frame_tick_index = int(frame.tick_index)
        frame_inputs = tuple(list(packed) for packed in frame.frame_inputs)
        player_inputs = tuple(unpack_player_input(packed) for packed in frame_inputs)
        self._samples_by_runner_tick[int(tick_index)] = LanFrameSample(
            frame_tick_index=int(frame_tick_index),
            frame_inputs=tuple(frame_inputs),
            commands=tuple(frame.commands),
        )
        return TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=int(tick_index),
                dt_seconds=float(default_dt_seconds),
                inputs=player_inputs,
                commands=tuple(frame.commands),
            ),
        )

    def supports_command_submission(self) -> bool:
        return self._runtime is not None and str(self._role) == "host"

    def submit_command(self, command: GameCommand) -> None:
        runtime = self._runtime
        if runtime is None:
            return
        if str(self._role) != "host":
            return
        if isinstance(runtime, LockstepRuntime):
            runtime.submit_local_command(command)


class _LanTickSyncRuntime(msgspec.Struct, frozen=True):
    role: str
    provider: _LanRuntimeInputProvider
    lockstep_runtime: object | None = None

    def prepare_tick_result(self, tick_result: TickResult) -> None:
        source_tick = tick_result.source_tick
        sample = self.provider.take_frame_sample(int(source_tick.tick_index))
        if sample is None:
            raise RuntimeError("lan tick runner completed without runtime frame metadata")
        if tuple(source_tick.commands) != tuple(sample.commands):
            raise RuntimeError("lan tick result commands diverged from canonical frame")
        tick_result.lan_sync = LanTickSync(
            frame_tick_index=int(sample.frame_tick_index),
            frame_inputs=tuple(sample.frame_inputs),
        )

    def finalize_tick_result(self, tick_result: TickResult) -> None:
        sync = tick_result.lan_sync
        if sync is None:
            raise RuntimeError("lan tick result missing frame metadata")
        if str(self.role) != "host" or self.lockstep_runtime is None:
            return
        runtime = cast(LockstepRuntime, self.lockstep_runtime)
        runtime.broadcast_tick_frame(
            TickFrame(
                tick_index=int(sync.frame_tick_index),
                frame_inputs=[list(packed) for packed in sync.frame_inputs],
                commands=list(tick_result.source_tick.commands),
            ),
        )


class _BatchApplyRuntime(msgspec.Struct, frozen=True):
    mode: BaseGameplayMode
    session: DeterministicSession
    recorder: ReplayRecorder | None = None
    lan_tick_sync: _LanTickSyncRuntime | None = None
    mode_tick_dt: float | None = None

    def ensure_replay_tick_index(self, tick_result: TickResult) -> int | None:
        replay_tick_index = tick_result.replay_tick_index
        if replay_tick_index is None and self.recorder is not None:
            replay_tick_index = int(
                self.recorder.record_tick(
                    list(tick_result.source_tick.inputs),
                    commands=list(tick_result.source_tick.commands),
                ),
            )
            tick_result.replay_tick_index = replay_tick_index
        return replay_tick_index

    def prepare_tick_result(self, tick_result: TickResult) -> int | None:
        if self.lan_tick_sync is not None:
            self.lan_tick_sync.prepare_tick_result(tick_result)
        if tick_result.lan_sync is None:
            return None
        return int(tick_result.lan_sync.frame_tick_index)

    def tick_applied_action(self, applied: _AppliedBatchTick) -> LanStepAction:
        if self.mode_tick_dt is None:
            return "continue"
        frame_tick_index = applied.frame_tick_index
        if self.lan_tick_sync is not None and frame_tick_index is None:
            raise RuntimeError("lan tick runner completed without runtime frame metadata")
        return self.mode._lan_on_tick_applied(
            applied.tick,
            None if frame_tick_index is None else int(frame_tick_index),
            float(self.mode_tick_dt),
        )

    def record_checkpoint(self, replay_tick_index: int | None, tick: DeterministicSessionTick) -> None:
        if replay_tick_index is None:
            return
        self.mode._record_replay_checkpoint_from_tick(
            tick_index=int(replay_tick_index),
            tick=tick,
        )

    def finalize_tick_result(self, tick_result: TickResult) -> None:
        if self.lan_tick_sync is None:
            return
        self.lan_tick_sync.finalize_tick_result(tick_result)


# LAN lockstep must keep presentation-step RNG consumption identical across peers.
# These knobs currently affect deterministic simulation (not just rendering), so
# we force stable values while in a LAN match.
LAN_SIM_DETAIL_PRESET = 5
LAN_SIM_VIOLENCE_DISABLED = 0


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
        self._lan_status: GameStatus | None = None
        self._lan_status_data: GameStatusData | None = None
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
        self.lan_player_rings_enabled = False
        self.lan_local_aim_indicators_only = False
        self.lan_local_player_slot_index = 0
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
        self._lan_runtime: LanRuntime | None = None
        self._rollback_runtime: RollbackRuntime | None = None
        self._lan_local_slot_index = 0
        self._lan_seed_override: int | None = None
        self._lan_start_tick = 0
        self._lan_enabled = False
        self._lan_role = ""
        self._lan_expected_players = 1
        self._lan_connected_players = 1
        self._lan_waiting_for_players = False
        self._lan_trace_last_ms = -1000.0
        self._lan_terrain_pending_last = False
        self._lan_terrain_pending_since_ms = 0
        self._lan_initial_terrain_ready = False
        self._runtime_updates_per_frame = 0
        self._input_stall_count = 0
        self._ticks_advanced_per_frame = 0
        self._sim_ms = 0.0
        self._presentation_plan_ms = 0.0
        self._presentation_apply_ms = 0.0
        self._queued_input_commands: list[GameCommand] = []
        self._network_input_provider = _LanRuntimeInputProvider(
            player_count=max(0, len(self.sim_world.players)),
            tick_rate=int(self._deterministic_tick_rate()),
        )
        self._sim_session: DeterministicSession | None = None
        self._tick_input_provider: LocalInputProvider | _LanRuntimeInputProvider | None = None
        self._tick_runner: TickRunner | None = None
        self._tick_runner_session: DeterministicSession | None = None
        self._tick_runner_is_networked = False
        self._tick_runner_network_role = ""
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

    @property
    def lan_player_rings_enabled(self) -> bool:
        return bool(self._world_runtime.lan_player_rings_enabled)

    @lan_player_rings_enabled.setter
    def lan_player_rings_enabled(self, value: bool) -> None:
        self._world_runtime.lan_player_rings_enabled = bool(value)

    @property
    def lan_local_aim_indicators_only(self) -> bool:
        return bool(self._world_runtime.lan_local_aim_indicators_only)

    @lan_local_aim_indicators_only.setter
    def lan_local_aim_indicators_only(self, value: bool) -> None:
        self._world_runtime.lan_local_aim_indicators_only = bool(value)

    @property
    def lan_local_player_slot_index(self) -> int:
        return int(self._world_runtime.lan_local_player_slot_index)

    @lan_local_player_slot_index.setter
    def lan_local_player_slot_index(self, value: int) -> None:
        self._world_runtime.lan_local_player_slot_index = int(value)

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

    def _refresh_effective_status(self, *, reset_lan_status: bool) -> None:
        if self._lan_enabled:
            if reset_lan_status or self._lan_status is None:
                self._lan_status = build_lan_deterministic_status(status=self._lan_status_data)
            self._status_sim = self._lan_status
        else:
            self._lan_status = None
            self._lan_status_data = None
            self._status_sim = self._status_base

        # Keep the currently-bound world state in sync (note that `open()` resets
        # the underlying simulation state, so `_bind_world()` also re-applies it).
        self.state.status = self._status_sim

    def bind_lan_runtime(self, runtime: LanRuntime | None) -> None:
        previous_runtime = self._lan_runtime
        self._lan_runtime = runtime
        self._rollback_runtime = runtime if isinstance(runtime, RollbackRuntime) else None
        self._network_input_provider.bind_runtime(runtime)
        if previous_runtime is not runtime and bool(self._tick_runner_is_networked):
            self._reset_tick_runner_state()
        slot_index = 0 if runtime is None else int(runtime.local_slot_index)
        self._lan_local_slot_index = max(0, min(3, int(slot_index)))

    def _lockstep_runtime(self) -> LockstepRuntime | None:
        runtime = self._lan_runtime
        if isinstance(runtime, LockstepRuntime):
            return runtime
        return None

    def set_lan_match_start(
        self,
        *,
        seed: int,
        start_tick: int = 0,
        status: GameStatusData | None = None,
    ) -> None:
        self._lan_seed_override = int(seed)
        self._lan_start_tick = int(start_tick)
        if status is not None:
            self._lan_status_data = status
            if self._lan_enabled:
                self._refresh_effective_status(reset_lan_status=True)

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

    def _lan_player_rings_enabled(self) -> bool:
        if not self._lan_enabled:
            return False
        return self._cvar_float("cv_lanPlayerRings", 0.0) != 0.0

    def _sync_lan_visual_flags(self) -> None:
        self.lan_player_rings_enabled = self._lan_player_rings_enabled()
        self.lan_local_aim_indicators_only = self._lan_enabled
        self.lan_local_player_slot_index = max(0, min(3, int(self._lan_local_slot_index)))

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
        # `GameplayState.status` is the simulation status (LAN may override it
        # with a deterministic session-local status to avoid split brain).
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
        self._refresh_effective_status(reset_lan_status=False)

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

    def _perk_menu_play_sfx(self) -> Callable[[SfxId], None] | None:
        return self.audio_bridge.router.play_sfx

    def _perk_menu_ui_context(self) -> PerkMenuUiContext:
        return PerkMenuUiContext(
            player=self.player,
            violence_disabled=self.config.display.violence_disabled,
            preserve_bugs=bool(self.state.preserve_bugs),
            fx_detail=self.config.display.fx_detail_enabled(level=0, default=False),
            resources=self.render_resources.resources,
            mouse=self._ui_mouse_pos(),
            play_sfx=self._perk_menu_play_sfx(),
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
        perk_ctx = self._perk_menu_ui_context()
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
        menu.open_menu(play_sfx=perk_ctx.play_sfx)
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
        self._trace_lan_state_heartbeat()

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
        provider: LocalInputProvider | _LanRuntimeInputProvider,
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
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
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

    def set_lan_runtime(
        self,
        *,
        enabled: bool,
        role: str,
        expected_players: int,
        connected_players: int,
        waiting_for_players: bool,
    ) -> None:
        role = str(role)
        expected_players = max(1, min(4, int(expected_players)))
        connected_players = max(0, min(expected_players, int(connected_players)))

        prev_enabled = self._lan_enabled
        prev_role = str(self._lan_role)
        if (
            self._lan_enabled == enabled
            and str(self._lan_role) == role
            and int(self._lan_expected_players) == int(expected_players)
            and int(self._lan_connected_players) == int(connected_players)
            and self._lan_waiting_for_players == waiting_for_players
        ):
            self._sync_lan_visual_flags()
            return
        self._lan_enabled = enabled
        self._lan_role = role
        self._lan_expected_players = int(expected_players)
        self._lan_connected_players = int(connected_players)
        self._lan_waiting_for_players = waiting_for_players
        self._network_input_provider.set_role(self._lan_role)
        self._sync_lan_visual_flags()
        self._lan_trace_last_ms = -1000.0
        if prev_enabled != self._lan_enabled:
            self._refresh_effective_status(reset_lan_status=True)
            self._reset_tick_runner_state()
        elif prev_role != str(self._lan_role):
            self._reset_tick_runner_state()
        lan_debug_log(
            "set_lan_runtime",
            mode=self.__class__.__name__,
            enabled=self._lan_enabled,
            role=str(self._lan_role),
            expected_players=int(self._lan_expected_players),
            connected_players=int(self._lan_connected_players),
            waiting_for_players=self._lan_waiting_for_players,
            player_rings=self.lan_player_rings_enabled,
        )

    def _lan_wait_gate_active(self) -> bool:
        if not self._lan_enabled:
            return False
        if not self._lan_waiting_for_players:
            return False
        return int(self._lan_connected_players) < int(self._lan_expected_players)

    def _lan_terrain_generation_pending(self) -> bool:
        if not self._lan_enabled:
            return False
        if self._lan_initial_terrain_ready:
            return False
        ground = self.render_resources.ground
        if ground is None:
            return False
        return ground.generation_pending()

    def _trace_lan_terrain_generation(self) -> None:
        if not self._lan_enabled:
            self._lan_terrain_pending_last = False
            self._lan_initial_terrain_ready = False
            return
        ground = self.render_resources.ground
        if ground is None:
            self._lan_terrain_pending_last = False
            self._lan_initial_terrain_ready = True
            return

        pending = self._lan_terrain_generation_pending()
        now_ms = int(time.monotonic() * 1000.0)
        if pending and (not self._lan_terrain_pending_last):
            self._lan_terrain_pending_since_ms = int(now_ms)
            lan_debug_log(
                "lan_terrain_generate_begin",
                mode=self.__class__.__name__,
                role=str(self._lan_role),
                slot=int(self._lan_local_slot_index),
            )
        if (not pending) and self._lan_terrain_pending_last:
            duration_ms = max(0, int(now_ms) - int(self._lan_terrain_pending_since_ms))
            rt_ready = ground.render_target_ready()
            lan_debug_log(
                "lan_terrain_generate_done",
                mode=self.__class__.__name__,
                role=str(self._lan_role),
                slot=int(self._lan_local_slot_index),
                duration_ms=int(duration_ms),
                render_target_ready=rt_ready,
                texture_failed=ground.texture_failed,
            )
        self._lan_terrain_pending_last = pending
        if not pending:
            self._lan_initial_terrain_ready = True

    def _trace_lan_state_heartbeat(self) -> None:
        if not self._lan_enabled:
            return
        elapsed_ms = float(self.sim_world.presentation_elapsed_ms)
        if (elapsed_ms - float(self._lan_trace_last_ms)) < 1000.0:
            return
        self._lan_trace_last_ms = float(elapsed_ms)
        lan_debug_log(
            "mode_heartbeat",
            mode=self.__class__.__name__,
            elapsed_ms=int(elapsed_ms),
            role=str(self._lan_role),
            expected_players=int(self._lan_expected_players),
            connected_players=int(self._lan_connected_players),
            waiting_for_players=self._lan_waiting_for_players,
            wait_gate_active=self._lan_wait_gate_active(),
            local_players=len(self.sim_world.players),
        )

    def _draw_lan_debug_info(self, *, x: float, y: float, line_h: float) -> float:
        if (not debug_enabled()) or (not self._lan_enabled):
            return float(y)

        role = str(self._lan_role or "?")
        expected = int(self._lan_expected_players)
        connected = int(self._lan_connected_players)
        slot = int(self._lan_local_slot_index)
        state = "waiting" if self._lan_wait_gate_active() else "active"
        self._draw_ui_text(
            f"lan: role={role} slot={slot} players={connected}/{expected} state={state}",
            Vec2(float(x), float(y)),
            rl.Color(130, 180, 240, 255),
            scale=0.9,
        )
        y += float(line_h)

        runtime = self._lan_runtime
        if runtime is not None:
            for line in runtime.debug_overlay_lines():
                self._draw_ui_text(
                    str(line),
                    Vec2(float(x), float(y)),
                    rl.Color(232, 197, 117, 255),
                    scale=0.85,
                )
                y += float(line_h)

        self._draw_ui_text(
            "telemetry:"
            f" runtime_updates={int(self._runtime_updates_per_frame)}"
            f" ticks={int(self._ticks_advanced_per_frame)}"
            f" stalls={int(self._input_stall_count)}",
            Vec2(float(x), float(y)),
            rl.Color(130, 180, 240, 255),
            scale=0.8,
        )
        y += float(line_h)
        self._draw_ui_text(
            "timers(ms):"
            f" sim={float(self._sim_ms):.3f}"
            f" plan={float(self._presentation_plan_ms):.3f}"
            f" apply={float(self._presentation_apply_ms):.3f}",
            Vec2(float(x), float(y)),
            rl.Color(130, 180, 240, 255),
            scale=0.8,
        )
        y += float(line_h)

        if self._lan_wait_gate_active():
            self._draw_ui_text(
                "lan(wait): simulation paused until all peers are ready",
                Vec2(float(x), float(y)),
                rl.Color(130, 180, 240, 255),
                scale=0.9,
            )
            y += float(line_h)

        return float(y)

    def _draw_lan_wait_overlay(self) -> None:
        if not self._lan_wait_gate_active():
            return

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if screen_w <= 0.0 or screen_h <= 0.0:
            return

        rl.draw_rectangle(
            0,
            0,
            int(screen_w),
            int(screen_h),
            rl.Color(8, 12, 18, 148),
        )

        panel_w = min(560.0, max(320.0, screen_w - 80.0))
        panel_h = 156.0
        panel_x = 0.5 * (screen_w - panel_w)
        panel_y = max(36.0, 0.17 * screen_h)

        rl.draw_rectangle(
            int(panel_x),
            int(panel_y),
            int(panel_w),
            int(panel_h),
            rl.Color(17, 24, 34, 230),
        )
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(panel_x, panel_y, panel_w, panel_h),
            2.0,
            rl.Color(108, 170, 230, 220),
        )

        dots = "." * int((self._cursor_pulse_time * 2.5) % 4)
        title = f"Waiting for LAN players{dots}"
        connected = int(self._lan_connected_players)
        expected = int(self._lan_expected_players)
        status = f"Connected peers: {connected}/{expected}"
        role = "Host" if str(self._lan_role) == "host" else "Client"
        role_line = f"Role: {role}"
        hint = (
            "Match will start automatically when all peers are connected."
            if role == "Host"
            else "Waiting for host to finish lobby and start the match."
        )

        text_x = panel_x + 22.0
        text_y = panel_y + 20.0
        line_h = float(self._ui_line_height(scale=0.95))
        self._draw_ui_text(title, Vec2(text_x, text_y), rl.Color(230, 237, 247, 255), scale=0.95)
        self._draw_ui_text(status, Vec2(text_x, text_y + line_h * 1.4), rl.Color(169, 214, 255, 255), scale=0.9)
        self._draw_ui_text(role_line, Vec2(text_x, text_y + line_h * 2.4), rl.Color(169, 214, 255, 255), scale=0.9)
        self._draw_ui_text(hint, Vec2(text_x, text_y + line_h * 3.5), rl.Color(186, 196, 214, 255), scale=0.82)

        if debug_enabled():
            self._draw_ui_text(
                "Debug: waiting for all peers before simulation starts",
                Vec2(text_x, text_y + line_h * 4.5),
                rl.Color(232, 197, 117, 255),
                scale=0.8,
            )

    def _net_replay_snapshot_state(self) -> ReplayStateSnapshotV2 | None:
        recorder = self._replay_recorder
        if recorder is None:
            return None
        return ReplayStateSnapshotV2(
            tick_index=int(recorder.tick_index),
            recorded_tick_count=int(recorder.recorded_tick_count),
        )

    def _store_net_runtime_snapshot(
        self,
        *,
        snapshot: ModeStateSnapshotV2,
    ) -> None:
        runtime = self._rollback_runtime
        if runtime is None:
            return
        tick = max(0, int(snapshot.tick_index))
        if (tick % 4) != 0:
            return
        payload = encode_mode_snapshot(snapshot=snapshot)
        runtime.store_local_snapshot(int(tick), payload)

    def _consume_net_runtime_recovery(self, *, mode_name: Literal["survival", "rush", "quests"]) -> None:
        runtime = self._rollback_runtime
        if runtime is None:
            return
        rollback_from = runtime.pop_rollback_from()
        if rollback_from is not None:
            lan_debug_log(
                "rollback_requested",
                mode=str(mode_name),
                role=str(self._lan_role),
                from_tick=int(rollback_from),
            )

        pending = runtime.pop_resync_snapshot()
        if pending is None:
            return
        tick_index, payload = pending
        try:
            snapshot = decode_mode_snapshot(payload)
        except RollbackResyncV5Error as exc:
            runtime.error = f"resync_decode_error:{exc}"
            return
        if str(snapshot.mode) != str(mode_name):
            runtime.error = "resync_mode_mismatch"
            return
        if int(snapshot.tick_index) != int(tick_index):
            runtime.error = "resync_tick_mismatch"
            return
        self._apply_resync_snapshot(snapshot)
        self._reset_tick_runner_state()
        runtime.mark_resync_applied(int(tick_index))

    def _apply_resync_snapshot(self, snapshot: ModeStateSnapshotV2) -> None:
        raise NotImplementedError(f"{self.__class__.__name__}._apply_resync_snapshot() must be implemented")

    def _player_name_default(self) -> str:
        return str(self.config.profile.player_name or "")

    def _runtime_player_count(self) -> int:
        return self.config.gameplay.player_count

    def _deterministic_detail_preset(self) -> int:
        if self._lan_enabled:
            return int(LAN_SIM_DETAIL_PRESET)
        return self.config.display.detail_preset

    def _deterministic_violence_disabled(self) -> int:
        if self._lan_enabled:
            return int(LAN_SIM_VIOLENCE_DISABLED)
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
        seed_source = "lan_override" if self._lan_seed_override is not None else "session_state"
        if self._lan_seed_override is not None:
            seed = int(self._lan_seed_override)
        else:
            seed = int(self.state.rng.state)
        self._run_reset_seed = int(seed) & 0xFFFFFFFF

        # Reset LAN sim status at the start of each run so per-session usage
        # counts (weapon bias) start from a consistent baseline across peers.
        self._refresh_effective_status(reset_lan_status=True)

        self._sync_world_runtime_config()
        self._world_runtime.reset(seed=seed, player_count=max(1, min(4, int(player_count))))
        self._world_runtime.open_runtime()
        self._bind_world()
        ground = self.render_resources.ground
        lan_debug_log(
            "mode_world_reset",
            mode=self.__class__.__name__,
            seed=int(self._run_reset_seed),
            seed_source=str(seed_source),
            rng_state=int(self.sim_world.state.rng.state),
            world_size=float(self.world_size),
            player_count=len(self.sim_world.players),
            lan_enabled=self._lan_enabled,
            lan_role=str(self._lan_role),
            lan_slot=int(self._lan_local_slot_index),
            base_status_quest_unlock_index=int(self._status_base.quest_unlock_index)
            if self._status_base is not None
            else 0,
            base_status_quest_unlock_index_full=int(self._status_base.quest_unlock_index_full)
            if self._status_base is not None
            else 0,
            sim_status_quest_unlock_index=int(self._status_sim.quest_unlock_index)
            if self._status_sim is not None
            else 0,
            sim_status_quest_unlock_index_full=int(self._status_sim.quest_unlock_index_full)
            if self._status_sim is not None
            else 0,
            detail_preset=self.config.display.detail_preset,
            violence_disabled=self.config.display.violence_disabled,
            sim_detail_preset=int(self._deterministic_detail_preset()),
            sim_violence_disabled=int(self._deterministic_violence_disabled()),
            screen_w=int(rl.get_screen_width()),
            screen_h=int(rl.get_screen_height()),
            render_w=int(rl.get_render_width()),
            render_h=int(rl.get_render_height()),
            terrain_texture_scale=float(ground.texture_scale) if ground is not None else 0.0,
        )
        self._local_input.reset(players=self.sim_world.players)
        self._network_input_provider = _LanRuntimeInputProvider(
            player_count=max(0, len(self.sim_world.players)),
            tick_rate=int(self._deterministic_tick_rate()),
        )
        self._reset_lan_capture_clock()
        self._reset_tick_runner_state()
        self._reset_replay_capture_state(clear_recorder=False)

        self._ui_mouse = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5)
        self._cursor_pulse_time = 0.0
        self._lan_terrain_pending_last = False
        self._lan_terrain_pending_since_ms = 0
        self._lan_initial_terrain_ready = False

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
        clock = self._tick_runner_local_clock
        if clock is not None:
            clock.reset()

    def _reset_tick_runner_state(self) -> None:
        self._tick_input_provider = None
        self._tick_runner = None
        self._tick_runner_session = None
        self._tick_runner_is_networked = False
        self._tick_runner_network_role = ""
        self._tick_runner_frame_index = 0
        self._tick_runner_next_tick_index = 0
        self._tick_runner_local_clock = None

    def _reset_replay_capture_state(self, *, clear_recorder: bool) -> None:
        self._queued_input_commands.clear()
        if clear_recorder:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def _lan_capture_tick_dt(self) -> float:
        return float(self._network_input_provider.capture_tick_dt)

    def _advance_lan_capture_ticks(self, dt: float) -> int:
        return int(self._network_input_provider.advance_capture_ticks(float(dt)))

    def _reset_lan_capture_clock(self) -> None:
        self._network_input_provider.reset_capture_clock()

    def _build_lan_tick_sync_runtime(
        self,
        *,
        lockstep_runtime: LockstepRuntime | None,
        role: str,
        provider: _LanRuntimeInputProvider,
    ) -> _LanTickSyncRuntime:
        return _LanTickSyncRuntime(
            role=str(role),
            provider=provider,
            lockstep_runtime=lockstep_runtime if role == "host" else None,
        )

    def _ensure_tick_runner(
        self,
        *,
        session: DeterministicSession,
        is_networked: bool,
        lan_runtime: LanRuntime | None = None,
        lockstep_runtime: LockstepRuntime | None = None,
        role: str = "",
    ) -> tuple[
        TickRunner,
        LocalInputProvider | _LanRuntimeInputProvider,
    ]:
        _ = lockstep_runtime
        runner = self._tick_runner
        provider = self._tick_input_provider
        if (
            runner is not None
            and provider is not None
            and self._tick_runner_session is session
            and bool(self._tick_runner_is_networked) == bool(is_networked)
            and ((not bool(is_networked)) or str(self._tick_runner_network_role) == str(role))
        ):
            if bool(is_networked):
                if not isinstance(provider, _LanRuntimeInputProvider):
                    raise TypeError("networked tick runner provider must be _LanRuntimeInputProvider")
                provider.bind_runtime(lan_runtime)
                provider.set_role(str(role))
                provider.set_before_pop(None)
                self._tick_runner_local_clock = None
            elif self._tick_runner_local_clock is None:
                self._tick_runner_local_clock = FixedStepClock(
                    tick_rate=int(self._gameplay_tick_rate()),
                )
            return (runner, provider)

        if bool(is_networked):
            provider = self._network_input_provider
            provider.bind_runtime(lan_runtime)
            provider.set_role(str(role))
            provider.set_before_pop(None)
        else:
            provider = LocalInputProvider(
                player_count=max(0, len(self.sim_world.players)),
                build_inputs=lambda frame_ctx: self._build_local_inputs(dt=float(frame_ctx.dt_seconds)),
            )
        self._flush_queued_input_commands(provider=provider)

        runner = TickRunner(
            session=session,
            input_provider=provider,
            config=TickRunnerConfig(),
        )
        self._tick_runner = runner
        self._tick_input_provider = provider
        self._tick_runner_session = session
        self._tick_runner_is_networked = bool(is_networked)
        self._tick_runner_network_role = str(role) if bool(is_networked) else ""
        self._tick_runner_frame_index = 0
        self._tick_runner_next_tick_index = 0
        self._tick_runner_local_clock = (
            None if bool(is_networked) else FixedStepClock(tick_rate=int(self._gameplay_tick_rate()))
        )
        return (runner, provider)

    def _record_replay_checkpoint_from_tick(
        self,
        *,
        tick_index: int | None,
        tick: DeterministicSessionTick,
    ) -> None:
        if tick_index is None:
            return
        world_events = tick.step.events
        self._record_replay_checkpoint(
            int(tick_index),
            deaths=world_events.deaths,
            events=world_events,
        )

    def _lan_mode_name(self) -> Literal["survival", "rush", "quests"]:
        raise NotImplementedError

    def _lan_match_session(self) -> DeterministicSession | None:
        raise NotImplementedError

    def _lan_prepare_frame(self, role: str, dt_ui_ms: float, session: LanSession, dt_tick: float) -> bool:
        _ = role, dt_ui_ms, session, dt_tick
        return True

    def _lan_allow_frame_pop(self) -> bool:
        return True

    def _lan_on_tick_applied(
        self,
        tick: DeterministicSessionTick,
        frame_tick_index: int | None,
        dt_tick: float,
    ) -> LanStepAction:
        _ = tick, frame_tick_index, dt_tick
        return "continue"

    def _lan_on_paused(self, dt: float) -> None:
        _ = dt

    def _update_lan_match(self, *, dt: float, dt_ui_ms: float = 0.0) -> None:
        runtime = self._lan_runtime
        if runtime is None:
            return
        session = self._lan_match_session()
        if session is None:
            return
        lockstep_runtime = self._lockstep_runtime()
        role = self._prepare_lan_match_runtime(mode_name=self._lan_mode_name())
        if role is None:
            return
        self._trace_lan_terrain_generation()
        if bool(self._lan_terrain_generation_pending()):
            self._reset_lan_capture_clock()
            return

        if bool(self._paused):
            self._reset_gameplay_frame_clock()
            self._lan_on_paused(float(dt))
            return

        dt_tick = float(self._lan_capture_tick_dt())
        if not self._lan_prepare_frame(
            str(role),
            float(dt_ui_ms),
            session,
            float(dt_tick),
        ):
            return

        if role == "join":
            if self._consume_lan_tick_frames(
                runtime=runtime,
                lockstep_runtime=lockstep_runtime,
                session=session,
                role=role,
                dt_tick=float(dt_tick),
            ):
                return

        ticks_to_capture = self._advance_lan_capture_ticks(float(dt))
        self._queue_lan_local_inputs(
            runtime=runtime,
            ticks_to_capture=int(ticks_to_capture),
            dt=float(dt),
        )
        self._consume_lan_tick_frames(
            runtime=runtime,
            lockstep_runtime=lockstep_runtime,
            session=session,
            role=role,
            dt_tick=float(dt_tick),
        )

    def _prepare_lan_match_runtime(self, *, mode_name: Literal["survival", "rush", "quests"]) -> str | None:
        runtime = self._lan_runtime
        if runtime is None:
            return None
        role = str(self._lan_role)
        self._consume_net_runtime_recovery(mode_name=mode_name)
        if str(runtime.error or ""):
            self.close_requested = True
            return None
        self._sync_audio_and_ground()
        if role == "host" and (not bool(runtime.host_remote_inputs_ready())):
            return None
        return role

    def _queue_lan_local_inputs(
        self,
        *,
        runtime: LanRuntime,
        ticks_to_capture: int,
        dt: float,
    ) -> None:
        if int(ticks_to_capture) <= 0:
            return
        input_frame = self._build_local_inputs(dt=dt)
        # In LAN sessions each peer is a single local player, so always sample
        # inputs using the configured Player 1 bindings (index 0). The network
        # slot mapping is handled by the lockstep runtime.
        local_input_index = 0
        for tick_offset in range(int(ticks_to_capture)):
            inputs = input_frame if tick_offset == 0 else self._clear_local_input_edges(input_frame)
            local_input = PlayerInput()
            if 0 <= local_input_index < len(inputs):
                local_input = inputs[local_input_index]
            runtime.queue_local_input(pack_player_input(local_input))

    def _consume_lan_tick_frames(
        self,
        *,
        runtime: LanRuntime,
        lockstep_runtime: LockstepRuntime | None,
        session: DeterministicSession,
        role: str,
        dt_tick: float,
    ) -> bool:
        runner, provider = self._ensure_tick_runner(
            session=session,
            is_networked=True,
            lan_runtime=runtime,
            lockstep_runtime=lockstep_runtime,
            role=str(role),
        )
        if not isinstance(provider, _LanRuntimeInputProvider):
            raise TypeError("networked tick runner provider must be _LanRuntimeInputProvider")
        provider.bind_runtime(runtime)
        provider.set_before_pop(self._lan_allow_frame_pop)
        sim_ns_start = time.perf_counter_ns()
        ticks_requested = 1 if float(dt_tick) > 0.0 else 0
        # LAN always requests exactly 0 or 1 ticks per frame. This ensures
        # mode tick-apply stop actions never discard simulated-but-unapplied ticks.
        assert ticks_requested <= 1
        advance = advance_tick_runner_frame(
            runner=runner,
            start_tick=int(self._tick_runner_next_tick_index),
            frame_index=int(self._tick_runner_frame_index),
            ticks_requested=int(ticks_requested),
            dt_seconds=float(dt_tick),
            tick_dt_seconds=float(dt_tick),
            is_networked=True,
            is_replay=False,
        )
        self._tick_runner_frame_index = int(advance.frame_index)
        self._tick_runner_next_tick_index = int(advance.next_tick_index)
        batch = advance.batch
        sim_ms = (time.perf_counter_ns() - sim_ns_start) / 1_000_000.0
        self._sim_ms += float(sim_ms)
        self._presentation_plan_ms += float(
            sum(max(0.0, float(row.payload.presentation_plan_ms)) for row in batch.completed_results),
        )

        ticks_applied = 0
        stop_after_finalize = False
        if int(batch.ticks_completed) <= 0:
            if provider.pop_blocked:
                return False
        else:
            lan_tick_sync = self._build_lan_tick_sync_runtime(
                lockstep_runtime=lockstep_runtime,
                role=str(role),
                provider=provider,
            )

            apply_ns_start = time.perf_counter_ns()
            outcome = self._process_tick_batch_results(
                batch=batch,
                runtime=_BatchApplyRuntime(
                    mode=self,
                    session=session,
                    recorder=self._replay_recorder,
                    lan_tick_sync=lan_tick_sync,
                    mode_tick_dt=float(dt_tick),
                ),
            )
            self._apply_batch_presentation_outputs(
                outputs=outcome.presentation_outputs,
                post_apply_reactions=outcome.post_apply_reactions,
                apply_audio=True,
                update_camera=True,
            )
            apply_ms = (time.perf_counter_ns() - apply_ns_start) / 1_000_000.0
            ticks_applied = int(outcome.ticks_applied)
            stop_after_finalize = bool(outcome.stop_after_finalize)
            self._presentation_apply_ms += float(apply_ms)
        if int(ticks_applied) <= 0:
            self._input_stall_count += 1
        return bool(stop_after_finalize)

    def _sync_audio_and_ground(self) -> None:
        self._world_runtime.sync_audio_bridge_state()
        if self.render_resources.ground is not None:
            self.render_resources.ground.process_pending()

    def _apply_batch_presentation_outputs(
        self,
        *,
        outputs: tuple[PresentationTickOutput, ...],
        post_apply_reactions: tuple[PostApplyReaction, ...] = (),
        apply_audio: bool,
        update_camera: bool,
    ) -> None:
        if post_apply_reactions and len(post_apply_reactions) != len(outputs):
            raise RuntimeError("post-apply reactions must align with presentation outputs")
        reaction_by_tick = {
            int(output.tick_index): reaction for output, reaction in zip(outputs, post_apply_reactions, strict=False)
        }
        apply_presentation_outputs(
            outputs=outputs,
            runtime=self._world_runtime,
            on_output_applied=lambda output: self._apply_tick_post_apply_reaction(
                reaction_by_tick.get(int(output.tick_index), PostApplyReaction()),
                dt_seconds=float(output.dt_sim),
            ),
            apply_audio=bool(apply_audio),
            update_camera=bool(update_camera),
        )

    def _build_tick_post_apply_reaction(self, *, tick_result: TickResult) -> PostApplyReaction:
        return build_post_apply_reaction(tick_result=tick_result)

    def _apply_tick_post_apply_reaction(self, reaction: PostApplyReaction, *, dt_seconds: float) -> None:
        _ = dt_seconds
        apply_post_apply_reaction(
            reaction=reaction,
            play_sfx=self.audio_bridge.router.play_sfx,
        )

    def _process_tick_batch_results(
        self,
        *,
        batch: TickBatchResult,
        runtime: _BatchApplyRuntime,
    ) -> _BatchApplyOutcome:
        ticks_applied = 0
        stop_after_finalize = False
        presentation_outputs: list[PresentationTickOutput] = []
        post_apply_reactions: list[PostApplyReaction] = []

        for tick_result in batch.completed_results:
            tick = tick_result.payload
            replay_tick_index = runtime.ensure_replay_tick_index(tick_result)
            applied = _AppliedBatchTick(
                tick=tick,
                replay_tick_index=replay_tick_index,
                frame_tick_index=runtime.prepare_tick_result(tick_result),
            )

            presentation_outputs.append(
                apply_sim_metadata_tick_result(
                    sim_world=self.sim_world,
                    tick_result=tick_result,
                    game_tune_started=bool(runtime.session.game_tune_started),
                ),
            )
            post_apply_reactions.append(
                self._build_tick_post_apply_reaction(
                    tick_result=tick_result,
                ),
            )
            self._ticks_advanced_per_frame += 1
            ticks_applied += 1

            action = runtime.tick_applied_action(applied)
            if action == "stop_before_finalize":
                return _BatchApplyOutcome(
                    ticks_applied=int(ticks_applied),
                    stopped=True,
                    stop_after_finalize=False,
                    presentation_outputs=tuple(presentation_outputs),
                    post_apply_reactions=tuple(post_apply_reactions),
                )

            runtime.record_checkpoint(replay_tick_index, tick)

            runtime.finalize_tick_result(tick_result)

            if action == "stop_after_finalize":
                stop_after_finalize = True
                return _BatchApplyOutcome(
                    ticks_applied=int(ticks_applied),
                    stopped=True,
                    stop_after_finalize=bool(stop_after_finalize),
                    presentation_outputs=tuple(presentation_outputs),
                    post_apply_reactions=tuple(post_apply_reactions),
                )

        return _BatchApplyOutcome(
            ticks_applied=int(ticks_applied),
            stopped=False,
            stop_after_finalize=bool(stop_after_finalize),
            presentation_outputs=tuple(presentation_outputs),
            post_apply_reactions=tuple(post_apply_reactions),
        )

    def _run_deterministic_session_ticks(
        self,
        *,
        dt_frame: float,
        session: DeterministicSession,
        recorder: ReplayRecorder | None,
        stop_on_mode_tick: bool = False,
    ) -> None:
        if float(dt_frame) <= 0.0:
            return
        self._sync_audio_and_ground()
        session.detail_preset = int(self._deterministic_detail_preset())
        session.violence_disabled = int(self._deterministic_violence_disabled())
        runner, provider = self._ensure_tick_runner(
            session=session,
            is_networked=False,
        )
        if not isinstance(provider, LocalInputProvider):
            raise TypeError("local tick runner provider must be LocalInputProvider")
        local_clock = self._tick_runner_local_clock
        if local_clock is None:
            local_clock = FixedStepClock(tick_rate=int(self._gameplay_tick_rate()))
            self._tick_runner_local_clock = local_clock

        candidate_ticks = int(local_clock.advance(float(dt_frame)))
        tick_dt = float(local_clock.dt_tick)
        sim_ns_start = time.perf_counter_ns()
        advance = advance_tick_runner_frame(
            runner=runner,
            start_tick=int(self._tick_runner_next_tick_index),
            frame_index=int(self._tick_runner_frame_index),
            ticks_requested=int(candidate_ticks),
            dt_seconds=float(dt_frame),
            tick_dt_seconds=float(tick_dt),
            is_networked=False,
            is_replay=False,
            refund_clock=local_clock,
        )
        self._tick_runner_frame_index = int(advance.frame_index)
        self._tick_runner_next_tick_index = int(advance.next_tick_index)
        batch = advance.batch
        self._sim_ms = float((time.perf_counter_ns() - sim_ns_start) / 1_000_000.0)
        self._presentation_plan_ms = float(
            sum(max(0.0, float(row.payload.presentation_plan_ms)) for row in batch.completed_results),
        )

        apply_ns_start = time.perf_counter_ns()
        outcome = self._process_tick_batch_results(
            batch=batch,
            runtime=_BatchApplyRuntime(
                mode=self,
                session=session,
                recorder=recorder,
                mode_tick_dt=float(tick_dt) if bool(stop_on_mode_tick) else None,
            ),
        )
        self._apply_batch_presentation_outputs(
            outputs=outcome.presentation_outputs,
            post_apply_reactions=outcome.post_apply_reactions,
            apply_audio=True,
            update_camera=True,
        )
        self._presentation_apply_ms = float((time.perf_counter_ns() - apply_ns_start) / 1_000_000.0)
        if batch.batch_status is InputStatus.STALLED and int(batch.ticks_completed) <= 0:
            self._input_stall_count += 1
