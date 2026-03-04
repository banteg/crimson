from __future__ import annotations

import datetime as dt
import hashlib
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

import msgspec

from grim.assets import PaqTextureCache
from grim.audio import AudioState, stop_music, update_audio
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..game_world import GameWorld
from ..local_input import LocalInputInterpreter, clear_input_edges
from ..net.debug_log import lan_debug_log
from ..net.deterministic_status import build_lan_deterministic_status
from ..net.lockstep_protocol import STATE_HASH_PERIOD_TICKS, TickFrame
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
from ..perks.selection import perk_selection_pick
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
from ..replay.types import PackedPlayerInput
from ..sim.clock import FixedStepClock
from ..sim.hooks import (
    CheckpointHook,
    NetworkSyncHook,
    ProfilerHook,
    ReplayRecorderHook,
    TickContext,
    TickHashes,
    TickHook,
    TickHookBus,
    TickResult,
)
from ..sim.input import PlayerInput
from ..sim.input_providers import FrameContext, InputCommand, LocalInputProvider, NetworkInputProvider
from ..sim.sessions import DeterministicSessionStepTick
from ..sim.tick_runner import TickRunner, TickRunnerConfig
from ..sim.timing import FrameTiming
from ..ui.game_over import GameOverUi
from ..ui.hud import HudAssets, HudState, draw_target_health_bar, load_hud_assets
from ..weapon_runtime import most_used_weapon_id_for_player
from .components.highscore_record_builder import shots_from_state

if TYPE_CHECKING:
    from ..creatures.runtime import CreaturePool
    from ..game.types import GameState
    from ..gameplay import GameplayState
    from ..net.lockstep_protocol import StatusSnapshot
    from ..persistence.save_status import GameStatus
    from ..replay import ReplayRecorder
    from ..sim.state_types import PlayerState

LanRuntime = LockstepRuntime | RollbackRuntime


LanStepAction = Literal["continue", "stop_before_finalize", "stop_after_finalize"]


@dataclass(frozen=True, slots=True)
class LanTickStep:
    frame_tick_index: int
    frame_inputs: tuple[PackedPlayerInput, ...]
    tick: DeterministicSessionStepTick
    local_command_hash: str
    host_state_hash: str
    replay_tick_index: int | None


@dataclass(frozen=True, slots=True)
class _LanFrameSample:
    frame_tick_index: int
    frame_inputs: tuple[PackedPlayerInput, ...]
    remote_command_hash: str
    remote_state_hash: str


class _LanRuntimeInputProvider(NetworkInputProvider):
    def __init__(self, *, player_count: int, tick_rate: int) -> None:
        self._runtime: LanRuntime | None = None
        self._samples_by_runner_tick: dict[int, _LanFrameSample] = {}
        self._before_pop: Callable[[], bool] | None = None
        self._pop_blocked = False
        self._capture_clock = FixedStepClock(tick_rate=max(1, int(tick_rate)))
        super().__init__(player_count=player_count, resolve_tick_input=self._resolve_tick_input)

    def bind_runtime(self, runtime: LanRuntime | None) -> None:
        self._runtime = runtime
        self._samples_by_runner_tick.clear()
        self._pop_blocked = False

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
        super().begin_frame(frame_ctx)
        self._samples_by_runner_tick.clear()
        self._pop_blocked = False

    def take_frame_sample(self, runner_tick_index: int) -> _LanFrameSample | None:
        return self._samples_by_runner_tick.pop(int(runner_tick_index), None)

    def _resolve_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        self._pop_blocked = False
        before_pop = self._before_pop
        if before_pop is not None and (not bool(before_pop())):
            self._pop_blocked = True
            return None
        runtime = self._runtime
        if runtime is None:
            return None
        frame = runtime.pop_tick_frame()
        if frame is None:
            return None
        frame_tick_index = int(frame.tick_index)
        frame_inputs = tuple(list(packed) for packed in frame.frame_inputs)
        player_inputs = [unpack_player_input(packed) for packed in frame_inputs]
        self._samples_by_runner_tick[int(tick_index)] = _LanFrameSample(
            frame_tick_index=int(frame_tick_index),
            frame_inputs=tuple(frame_inputs),
            remote_command_hash=str(frame.command_hash or ""),
            remote_state_hash=str(frame.state_hash or ""),
        )
        return player_inputs


class _GameplayTickObserverHook:
    def __init__(self, *, replay_hook: ReplayRecorderHook) -> None:
        self._replay_hook = replay_hook
        self._on_tick: Callable[[DeterministicSessionStepTick, int | None], bool] | None = None

    def bind(self, on_tick: Callable[[DeterministicSessionStepTick, int | None], bool] | None) -> None:
        self._on_tick = on_tick

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> bool:
        callback = self._on_tick
        if callback is None:
            return False
        payload = result.payload
        if payload is None:
            return False
        tick = cast(DeterministicSessionStepTick, payload)
        replay_tick_index = self._replay_hook.recorded_tick_by_runner_tick.get(int(ctx.tick_index))
        return bool(callback(tick, replay_tick_index))

class DeterministicSessionLike(Protocol):
    detail_preset: int
    gore_disabled: int
    game_tune_started: bool

    def timing_for_dt(self, dt: float) -> FrameTiming: ...

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
    ) -> DeterministicSessionStepTick: ...


# LAN lockstep must keep presentation-step RNG consumption identical across peers.
# These knobs currently affect deterministic simulation (not just rendering), so
# we force stable values while in a LAN match.
LAN_SIM_DETAIL_PRESET = 5
LAN_SIM_FX_TOGGLE = 0


class BaseGameplayMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        world_size: float,
        default_game_mode_id: GameMode,
        demo_mode_active: bool = False,
        difficulty_level: int = 0,
        hardcore: bool = False,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
    ) -> None:
        self._assets_root = ctx.assets_dir
        self._small: SmallFontData | None = None
        self._hud_assets: HudAssets | None = None
        self._hud_state = HudState()

        mode_id = int(default_game_mode_id)
        if config is None:
            base_dir = Path.cwd()
            resolved_config = CrimsonConfig(path=base_dir / "crimson.cfg", data=default_crimson_cfg_data())
            resolved_config.game_mode = mode_id
        else:
            resolved_config = config
            base_dir = resolved_config.path.parent
        self.config: CrimsonConfig = resolved_config
        self._console = console
        self._base_dir = base_dir

        self.close_requested = False
        self._action: str | None = None
        self._paused = False
        self._status_base: GameStatus | None = None
        self._status_sim: GameStatus | None = None
        self._lan_status: GameStatus | None = None
        self._lan_status_snapshot: StatusSnapshot | None = None
        self._local_input: LocalInputInterpreter = LocalInputInterpreter()
        self._game_over_ui: GameOverUi = GameOverUi(
            assets_root=self._assets_root,
            base_dir=self._base_dir,
            config=self.config,
            preserve_bugs=ctx.preserve_bugs,
        )

        self.world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=float(world_size),
            demo_mode_active=demo_mode_active,
            difficulty_level=int(difficulty_level),
            hardcore=hardcore,
            preserve_bugs=ctx.preserve_bugs,
            texture_cache=texture_cache,
            config=self.config,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._bind_world()

        self._game_over_active = False
        self._game_over_record: HighScoreRecord | None = None
        self._game_over_banner = "reaper"

        self._ui_mouse = Vec2()
        self._cursor_pulse_time = 0.0
        self._last_dt_ms = 0.0
        self._screen_fade: GameState | None = None
        self._terrain_regen_counter = 0
        self._bootstrap_seed = 0
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
        self._network_input_provider = _LanRuntimeInputProvider(
            player_count=max(0, len(self.world.sim_world.players)),
            tick_rate=int(self._deterministic_tick_rate()),
        )
        self._gameplay_input_provider: LocalInputProvider | None = None
        self._gameplay_tick_runner: TickRunner | None = None
        self._gameplay_tick_runner_session: DeterministicSessionLike | None = None
        self._gameplay_replay_hook: ReplayRecorderHook | None = None
        self._gameplay_checkpoint_hook: CheckpointHook | None = None
        self._gameplay_network_sync_hook: NetworkSyncHook | None = None
        self._gameplay_profiler_hook: ProfilerHook | None = None
        self._gameplay_observer_hook: _GameplayTickObserverHook | None = None
        self._lan_tick_runner: TickRunner | None = None
        self._lan_tick_runner_session: DeterministicSessionLike | None = None
        self._lan_replay_hook: ReplayRecorderHook | None = None
        self._lan_checkpoint_hook: CheckpointHook | None = None
        self._lan_network_sync_hook: NetworkSyncHook | None = None
        self._lan_profiler_hook: ProfilerHook | None = None
        self._pending_input_commands: list[InputCommand] = []

    def _refresh_effective_status(self, *, reset_lan_status: bool) -> None:
        if self._lan_enabled:
            if reset_lan_status or self._lan_status is None:
                self._lan_status = build_lan_deterministic_status(snapshot=self._lan_status_snapshot)
            self._status_sim = self._lan_status
        else:
            self._lan_status = None
            self._lan_status_snapshot = None
            self._status_sim = self._status_base

        # Keep the currently-bound world state in sync (note that `open()` resets
        # the underlying `GameWorld.state`, so `_bind_world()` also re-applies it).
        self.state.status = self._status_sim

    def bind_lan_runtime(self, runtime: LanRuntime | None) -> None:
        self._lan_runtime = runtime
        self._rollback_runtime = runtime if isinstance(runtime, RollbackRuntime) else None
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
        status_snapshot: StatusSnapshot | None = None,
    ) -> None:
        self._lan_seed_override = int(seed)
        self._lan_start_tick = int(start_tick)
        if status_snapshot is not None:
            self._lan_status_snapshot = status_snapshot
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
        self.world.lan_player_rings_enabled = self._lan_player_rings_enabled()
        self.world.lan_local_aim_indicators_only = self._lan_enabled
        self.world.lan_local_player_slot_index = max(0, min(3, int(self._lan_local_slot_index)))

    def _config_game_mode_id(self) -> GameMode:
        try:
            return GameMode(self.config.game_mode)
        except ValueError:
            return GameMode.DEMO

    def _draw_target_health_bar(self, *, alpha: float = 1.0) -> None:
        creatures = self.creatures.entries
        if not creatures:
            return

        target_indices: list[int] = []
        target_players = (
            self.world.sim_world.players[:1] if self.state.preserve_bugs else self.world.sim_world.players
        )
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

            screen_left = self.world.world_to_screen(creature.pos + Vec2(-32.0, 32.0))
            screen_right = self.world.world_to_screen(creature.pos + Vec2(32.0, 32.0))
            width = screen_right.x - screen_left.x
            if width <= 1e-3:
                continue
            draw_target_health_bar(pos=screen_left, width=width, ratio=ratio, alpha=alpha, scale=width / 64.0)

    def _bind_world(self) -> None:
        self.state: GameplayState = self.world.sim_world.state
        self.creatures: CreaturePool = self.world.sim_world.creatures
        self.player: PlayerState = self.world.sim_world.players[0]
        preserve_bugs = self.state.preserve_bugs
        self._local_input.set_preserve_bugs(preserve_bugs)
        self._hud_state.preserve_bugs = preserve_bugs
        self._game_over_ui.preserve_bugs = preserve_bugs
        # `GameplayState.status` is the simulation status (LAN may override it
        # with a deterministic session-local status to avoid split brain).
        self.state.status = self._status_sim

    def _any_player_alive(self) -> bool:
        return any(player.health > 0.0 for player in self.world.sim_world.players)

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

    def bind_audio(self, audio: AudioState | None, audio_rng: random.Random | None) -> None:
        self.world.audio = audio
        self.world.audio_rng = audio_rng

    def set_rtx_mode(self, mode: RtxRenderMode) -> None:
        self.world.rtx_mode = mode

    def _update_audio(self, dt: float) -> None:
        if self.world.audio is not None:
            update_audio(self.world.audio, dt)

    def _ui_line_height(self, scale: float = 1.0) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _ui_text_width(self, text: str, scale: float = 1.0) -> int:
        if self._small is not None:
            return int(measure_small_text_width(self._small, text, scale))
        return int(rl.measure_text(text, int(20 * scale)))

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, pos, scale, color)
        else:
            rl.draw_text(text, int(pos.x), int(pos.y), int(20 * scale), color)

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

    def set_runtime_updates_per_frame(self, value: int) -> None:
        self._runtime_updates_per_frame = max(0, int(value))

    def _enqueue_input_command(self, command: InputCommand) -> None:
        provider = self._gameplay_input_provider
        if provider is not None:
            provider.push_command(command)
            return
        self._pending_input_commands.append(command)

    def _take_pending_input_commands(self) -> list[InputCommand]:
        pending = list(self._pending_input_commands)
        self._pending_input_commands.clear()
        return pending

    def _record_perk_pick_command(self, choice_index: int, *, player_index: int = 0) -> None:
        recorder = self._replay_recorder
        if recorder is not None:
            recorder.record_perk_pick(player_index=int(player_index), choice_index=int(choice_index))
        self._enqueue_input_command(
            InputCommand(
                name="perk_pick",
                payload={"choice_index": int(choice_index)},
            ),
        )

    def _apply_input_command(self, command: InputCommand, *, dt_tick: float) -> None:
        _ = command, dt_tick

    def _apply_perk_pick_input_command(
        self,
        command: InputCommand,
        *,
        dt_tick: float,
        game_mode: GameMode,
        perk_context: object,
    ) -> bool:
        if str(command.name) != "perk_pick":
            return False
        raw_choice_index = command.payload.get("choice_index")
        if not isinstance(raw_choice_index, int):
            raise TypeError("perk_pick command requires integer payload['choice_index']")
        ctx = cast(Any, perk_context)
        picked = perk_selection_pick(
            ctx.state,
            ctx.players,
            ctx.perk_state,
            int(raw_choice_index),
            game_mode=game_mode,
            player_count=int(ctx.player_count),
            dt=float(dt_tick),
            creatures=ctx.creatures,
        )
        if picked is not None and self.world.audio_bridge.router is not None:
            self.world.audio_bridge.router.play_sfx("sfx_ui_bonus")
        return True

    def _consume_pending_input_commands(self, *, dt_tick: float) -> None:
        for command in self._take_pending_input_commands():
            self._apply_input_command(command, dt_tick=float(dt_tick))

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return float(self.world.sim_world.elapsed_ms)

    def _replay_claimed_stats_complete(self) -> bool:
        return False

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        return int(self._replay_checkpoint_elapsed_ms())

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        _ = replay
        mode_name = str(self.__class__.__name__).replace("Mode", "").lower() or "replay"
        return f"{mode_name}_{stamp}"

    def _replay_emit_terminal_event_checkpoint(self, replay: Replay, *, terminal_tick: int) -> bool:
        _ = replay, terminal_tick
        return False

    def _replay_skip_save_when_empty(self, *, recorder: ReplayRecorder) -> bool:
        _ = recorder
        return False

    def _record_replay_checkpoint(
        self,
        tick_index: int,
        *,
        force: bool = False,
        rng_marks: dict[str, int] | None = None,
        deaths: list[object] | tuple[object, ...] | None = None,
        events: object | None = None,
        command_hash: str | None = None,
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
                world=self.world.sim_world.world_state,
                elapsed_ms=float(self._replay_checkpoint_elapsed_ms()),
                rng_marks=rng_marks,
                deaths=deaths,
                events=events,
                command_hash=command_hash,
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

        shots_fired, shots_hit = shots_from_state(self.state, player_index=int(self.player.index))
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

        terminal_tick = int(recorder.tick_index)
        if self._replay_emit_terminal_event_checkpoint(replay, terminal_tick=terminal_tick):
            self._record_replay_checkpoint(terminal_tick, force=True)

        data = dump_replay(replay)
        digest = hashlib.sha256(data).hexdigest()
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
                replay_sha256=digest,
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
        self._sync_lan_visual_flags()
        self._lan_trace_last_ms = -1000.0
        if prev_enabled != self._lan_enabled:
            self._refresh_effective_status(reset_lan_status=True)
        lan_debug_log(
            "set_lan_runtime",
            mode=self.__class__.__name__,
            enabled=self._lan_enabled,
            role=str(self._lan_role),
            expected_players=int(self._lan_expected_players),
            connected_players=int(self._lan_connected_players),
            waiting_for_players=self._lan_waiting_for_players,
            player_rings=self.world.lan_player_rings_enabled,
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
        ground = self.world.render_resources.ground
        if ground is None:
            return False
        return ground.generation_pending()

    def _trace_lan_terrain_generation(self) -> None:
        if not self._lan_enabled:
            self._lan_terrain_pending_last = False
            self._lan_initial_terrain_ready = False
            return
        ground = self.world.render_resources.ground
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

    def _update_lan_wait_gate_debug_override(self) -> None:
        if not self._lan_wait_gate_active():
            return
        if (not debug_enabled()) or (not rl.is_key_pressed(rl.KeyboardKey.KEY_F10)):
            return
        self._lan_connected_players = int(self._lan_expected_players)
        self._lan_waiting_for_players = False
        lan_debug_log(
            "wait_gate_override",
            mode=self.__class__.__name__,
            role=str(self._lan_role),
            connected_players=int(self._lan_connected_players),
            expected_players=int(self._lan_expected_players),
        )

    def _trace_lan_state_heartbeat(self) -> None:
        if not self._lan_enabled:
            return
        elapsed_ms = float(self.world.sim_world.elapsed_ms)
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
            local_players=int(len(self.world.sim_world.players)),
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
            self._draw_ui_text(
                "debug: F10 force start (temporary bring-up override)",
                Vec2(float(x), float(y)),
                rl.Color(130, 180, 240, 255),
                scale=0.8,
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
                "Debug override: press F10 to force start",
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
        runtime.mark_resync_applied(int(tick_index))

    def _player_name_default(self) -> str:
        return str(self.config.player_name or "")

    def _deterministic_detail_preset(self) -> int:
        if self._lan_enabled:
            return int(LAN_SIM_DETAIL_PRESET)
        return self.config.detail_preset

    def _deterministic_gore_disabled(self) -> int:
        if self._lan_enabled:
            return int(LAN_SIM_FX_TOGGLE)
        return self.config.gore_disabled

    def update(self, dt: float) -> None:
        raise NotImplementedError(f"{self.__class__.__name__}.update() must be implemented by gameplay mode")

    def draw(self) -> None:
        raise NotImplementedError(f"{self.__class__.__name__}.draw() must be implemented by gameplay mode")

    def open(self) -> None:
        self.close_requested = False
        self._action = None
        self._paused = False
        self._small = load_small_font(self._assets_root)

        self._hud_assets = load_hud_assets(self._assets_root)
        self._hud_state = HudState()

        self._game_over_active = False
        self._game_over_record = None
        self._game_over_banner = "reaper"
        self._game_over_ui.close()

        # Native game_over/victory transitions call `sfx_mute_all` on menu + extra
        # tracks before restarting gameplay ("Play Again"), resetting first-hit tune gate.
        stop_music(self.world.audio)

        player_count = self.config.player_count
        seed_source = "lan_override" if self._lan_seed_override is not None else "random"
        if self._lan_seed_override is not None:
            seed = int(self._lan_seed_override)
        else:
            seed = random.getrandbits(32)
        self._bootstrap_seed = int(seed) & 0xFFFFFFFF

        # Reset LAN sim status at the start of each run so per-session usage
        # counts (weapon bias) start from a consistent baseline across peers.
        self._refresh_effective_status(reset_lan_status=True)

        self.world.reset(seed=seed, player_count=max(1, min(4, player_count)))
        self.world.open()
        self._bind_world()
        ground = self.world.render_resources.ground
        lan_debug_log(
            "mode_world_reset",
            mode=self.__class__.__name__,
            seed=int(self._bootstrap_seed),
            seed_source=str(seed_source),
            rng_state=int(self.world.sim_world.state.rng.state),
            world_size=float(self.world.world_size),
            player_count=int(len(self.world.sim_world.players)),
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
            detail_preset=self.config.detail_preset,
            gore_disabled=self.config.gore_disabled,
            sim_detail_preset=int(self._deterministic_detail_preset()),
            sim_gore_disabled=int(self._deterministic_gore_disabled()),
            screen_w=int(rl.get_screen_width()),
            screen_h=int(rl.get_screen_height()),
            render_w=int(rl.get_render_width()),
            render_h=int(rl.get_render_height()),
            terrain_texture_scale=float(ground.texture_scale) if ground is not None else 0.0,
        )
        self._local_input.reset(players=self.world.sim_world.players)
        self._network_input_provider = _LanRuntimeInputProvider(
            player_count=max(0, len(self.world.sim_world.players)),
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
            rl.unload_texture(self._small.texture)
            self._small = None
        self._hud_assets = None
        self._reset_tick_runner_state()
        self._reset_replay_capture_state(clear_recorder=True)
        self.world.close()

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
            play_sfx=self.world.audio_bridge.router.play_sfx,
            rand=None,
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
        self.world.draw(draw_aim_indicators=False, entity_alpha=self._world_entity_alpha() * alpha)

    def steal_ground_for_menu(self):
        ground = self.world.render_resources.ground
        self.world.render_resources.ground = None
        return ground

    def adopt_ground_from_menu(self, ground: GroundRenderer | None) -> None:
        if ground is None:
            return
        current = self.world.render_resources.ground
        if current is not None and current is not ground and current.render_target is not None:
            rl.unload_render_texture(current.render_target)
            current.render_target = None
        self.world.render_resources.ground = ground
        self.world.sync_ground_settings()

    def menu_ground_camera(self) -> Vec2:
        return self.world.camera

    def console_elapsed_ms(self) -> float:
        return float(self.world.sim_world.elapsed_ms)

    def regenerate_terrain_for_console(self) -> None:
        if self.world.render_resources.ground is None:
            return
        # Keep this deterministic without consuming gameplay RNG.
        self._terrain_regen_counter = (int(self._terrain_regen_counter) + 1) & 0xFFFFFFFF
        terrain_seed = (int(self.state.rng.state) + int(self._terrain_regen_counter)) & 0xFFFFFFFF
        self.world.render_resources.ground.schedule_generate(seed=terrain_seed, layers=3)

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
            players=self.world.sim_world.players,
            config=self.config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self.world.screen_to_world,
            dt=float(dt),
            creatures=self.creatures.entries,
        )

    @staticmethod
    def _clear_local_input_edges(inputs: list[PlayerInput]) -> list[PlayerInput]:
        return clear_input_edges(inputs)

    @staticmethod
    def _deterministic_tick_rate() -> int:
        return 60

    def _new_tick_runner(
        self,
        *,
        session: DeterministicSessionLike,
        input_provider: object,
        hooks: list[TickHook],
        tick_rate: int,
        is_networked: bool,
    ) -> TickRunner:
        return TickRunner(
            session=session,
            input_provider=cast(Any, input_provider),
            hook_bus=TickHookBus(hooks),
            config=TickRunnerConfig(
                tick_rate=int(tick_rate),
                is_networked=bool(is_networked),
                is_replay=False,
            ),
        )

    @staticmethod
    def _reset_profiler_hook(profiler: ProfilerHook) -> None:
        profiler.sim_ms = 0.0
        profiler.presentation_plan_ms = 0.0
        profiler.presentation_apply_ms = 0.0

    def _gameplay_tick_rate(self) -> int:
        runner = self._gameplay_tick_runner
        if runner is not None:
            return int(runner.clock.tick_rate)
        return int(self._deterministic_tick_rate())

    def _gameplay_tick_dt(self, *, session: DeterministicSessionLike | None = None) -> float:
        if session is not None:
            runner, *_ = self._ensure_gameplay_tick_runner(session=session)
            return float(runner.clock.dt_tick)
        runner = self._gameplay_tick_runner
        if runner is not None:
            return float(runner.clock.dt_tick)
        return 1.0 / float(self._deterministic_tick_rate())

    def _reset_gameplay_tick_runner_clock(self) -> None:
        runner = self._gameplay_tick_runner
        if runner is not None:
            runner.reset_clock()

    def _reset_tick_runner_state(self) -> None:
        self._gameplay_input_provider = None
        self._gameplay_tick_runner = None
        self._gameplay_tick_runner_session = None
        self._gameplay_replay_hook = None
        self._gameplay_checkpoint_hook = None
        self._gameplay_network_sync_hook = None
        self._gameplay_profiler_hook = None
        self._gameplay_observer_hook = None
        self._lan_tick_runner = None
        self._lan_tick_runner_session = None
        self._lan_replay_hook = None
        self._lan_checkpoint_hook = None
        self._lan_network_sync_hook = None
        self._lan_profiler_hook = None

    def _reset_replay_capture_state(self, *, clear_recorder: bool) -> None:
        self._pending_input_commands.clear()
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

    def _ensure_gameplay_tick_runner(
        self,
        *,
        session: DeterministicSessionLike,
    ) -> tuple[
        TickRunner,
        LocalInputProvider,
        ReplayRecorderHook,
        CheckpointHook,
        NetworkSyncHook,
        ProfilerHook,
        _GameplayTickObserverHook,
    ]:
        runner = self._gameplay_tick_runner
        provider = self._gameplay_input_provider
        replay_hook = self._gameplay_replay_hook
        checkpoint_hook = self._gameplay_checkpoint_hook
        network_sync_hook = self._gameplay_network_sync_hook
        profiler_hook = self._gameplay_profiler_hook
        observer_hook = self._gameplay_observer_hook
        if (
            runner is not None
            and provider is not None
            and replay_hook is not None
            and checkpoint_hook is not None
            and network_sync_hook is not None
            and profiler_hook is not None
            and observer_hook is not None
            and self._gameplay_tick_runner_session is session
        ):
            return (
                runner,
                provider,
                replay_hook,
                checkpoint_hook,
                network_sync_hook,
                profiler_hook,
                observer_hook,
            )

        provider = LocalInputProvider(
            player_count=max(0, len(self.world.sim_world.players)),
            build_inputs=lambda frame_ctx: self._build_local_inputs(dt=float(frame_ctx.dt_seconds)),
            command_consumer=lambda command, dt_tick: self._apply_input_command(command, dt_tick=float(dt_tick)),
        )
        for command in self._take_pending_input_commands():
            provider.push_command(command)
        replay_hook = ReplayRecorderHook(None)
        observer_hook = _GameplayTickObserverHook(replay_hook=replay_hook)
        checkpoint_hook = CheckpointHook(replay_recorder_hook=replay_hook, on_checkpoint=None)
        network_sync_hook = NetworkSyncHook(on_hash=None)
        profiler_hook = ProfilerHook()
        runner = self._new_tick_runner(
            session=session,
            input_provider=provider,
            hooks=[
                replay_hook,
                observer_hook,
                checkpoint_hook,
                network_sync_hook,
                profiler_hook,
            ],
            tick_rate=int(self._deterministic_tick_rate()),
            is_networked=bool(self._lan_enabled),
        )
        self._gameplay_tick_runner = runner
        self._gameplay_input_provider = provider
        self._gameplay_tick_runner_session = session
        self._gameplay_replay_hook = replay_hook
        self._gameplay_checkpoint_hook = checkpoint_hook
        self._gameplay_network_sync_hook = network_sync_hook
        self._gameplay_profiler_hook = profiler_hook
        self._gameplay_observer_hook = observer_hook
        return (
            runner,
            provider,
            replay_hook,
            checkpoint_hook,
            network_sync_hook,
            profiler_hook,
            observer_hook,
        )

    def _record_replay_checkpoint_from_tick(
        self,
        *,
        tick_index: int | None,
        tick: DeterministicSessionStepTick,
    ) -> None:
        if tick_index is None:
            return
        world_events = tick.step.events
        self._record_replay_checkpoint(
            int(tick_index),
            rng_marks=tick.rng_marks,
            deaths=world_events.deaths,
            events=world_events,
            command_hash=str(tick.step.command_hash),
        )

    def _lan_mode_name(self) -> Literal["survival", "rush", "quests"]:
        raise NotImplementedError

    def _lan_match_session(self) -> DeterministicSessionLike | None:
        raise NotImplementedError

    def _on_lan_paused(self, *, dt: float) -> None:
        _ = dt

    def _prepare_lan_match_frame(
        self,
        *,
        role: str,
        dt: float,
        dt_ui_ms: float,
        lockstep_runtime: LockstepRuntime | None,
        session: DeterministicSessionLike,
        dt_tick: float,
    ) -> bool:
        _ = role, dt, dt_ui_ms, lockstep_runtime, session, dt_tick
        return True

    def _before_lan_tick_step(
        self,
        *,
        role: str,
        lockstep_runtime: LockstepRuntime | None,
        session: DeterministicSessionLike,
        dt_tick: float,
    ) -> None:
        _ = role, lockstep_runtime, session, dt_tick

    def _lan_allow_frame_pop(
        self,
        *,
        role: str,
        lockstep_runtime: LockstepRuntime | None,
        session: DeterministicSessionLike,
        dt_tick: float,
    ) -> bool:
        _ = role, lockstep_runtime, session, dt_tick
        return True

    def _after_lan_join_consume(
        self,
        *,
        lockstep_runtime: LockstepRuntime | None,
        session: DeterministicSessionLike,
        dt_tick: float,
    ) -> bool:
        _ = lockstep_runtime, session, dt_tick
        return False

    def _on_lan_tick_applied(
        self,
        *,
        role: str,
        lockstep_runtime: LockstepRuntime | None,
        session: DeterministicSessionLike,
        step: LanTickStep,
        dt_tick: float,
    ) -> LanStepAction:
        _ = role, lockstep_runtime, session, step, dt_tick
        return "continue"

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
            self._reset_gameplay_tick_runner_clock()
            self._on_lan_paused(dt=float(dt))
            return

        dt_tick = float(self._lan_capture_tick_dt())
        if not self._prepare_lan_match_frame(
            role=str(role),
            dt=float(dt),
            dt_ui_ms=float(dt_ui_ms),
            lockstep_runtime=lockstep_runtime,
            session=session,
            dt_tick=float(dt_tick),
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
            if self._after_lan_join_consume(
                lockstep_runtime=lockstep_runtime,
                session=session,
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

    def _lan_state_hash_for_tick(
        self,
        *,
        tick_index: int,
        elapsed_ms: float,
        creature_count_world_step: int,
    ) -> str:
        return str(
            build_checkpoint(
                tick_index=int(tick_index),
                world=self.world.sim_world.world_state,
                elapsed_ms=float(elapsed_ms),
                creature_count_override=int(creature_count_world_step),
            ).state_hash,
        )

    @staticmethod
    def _lan_should_emit_state_hash(*, tick_index: int) -> bool:
        return int(tick_index) < 5 or (int(tick_index) % int(STATE_HASH_PERIOD_TICKS)) == 0

    def _ensure_lan_tick_runner(
        self,
        *,
        session: DeterministicSessionLike,
    ) -> tuple[
        TickRunner,
        _LanRuntimeInputProvider,
        ReplayRecorderHook,
        CheckpointHook,
        NetworkSyncHook,
        ProfilerHook,
    ]:
        runner = self._lan_tick_runner
        provider = self._network_input_provider
        replay_hook = self._lan_replay_hook
        checkpoint_hook = self._lan_checkpoint_hook
        network_sync_hook = self._lan_network_sync_hook
        profiler = self._lan_profiler_hook
        if (
            runner is not None
            and self._lan_tick_runner_session is session
            and replay_hook is not None
            and checkpoint_hook is not None
            and network_sync_hook is not None
            and profiler is not None
        ):
            return runner, provider, replay_hook, checkpoint_hook, network_sync_hook, profiler

        replay_hook = ReplayRecorderHook(None)
        checkpoint_hook = CheckpointHook(
            replay_recorder_hook=replay_hook,
            on_checkpoint=None,
        )
        network_sync_hook = NetworkSyncHook(on_hash=None)
        profiler = ProfilerHook()
        runner = self._new_tick_runner(
            session=session,
            input_provider=provider,
            hooks=[
                replay_hook,
                checkpoint_hook,
                network_sync_hook,
                profiler,
            ],
            tick_rate=int(self._deterministic_tick_rate()),
            is_networked=True,
        )
        self._lan_tick_runner = runner
        self._lan_tick_runner_session = session
        self._lan_replay_hook = replay_hook
        self._lan_checkpoint_hook = checkpoint_hook
        self._lan_network_sync_hook = network_sync_hook
        self._lan_profiler_hook = profiler
        return runner, provider, replay_hook, checkpoint_hook, network_sync_hook, profiler

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
        session: DeterministicSessionLike,
        role: str,
        dt_tick: float,
    ) -> bool:
        runner, provider, replay_hook, checkpoint_hook, network_sync_hook, profiler = self._ensure_lan_tick_runner(
            session=session,
        )
        replay_hook.set_recorder(self._replay_recorder)
        replay_hook.clear_recorded_ticks()
        checkpoint_hook.set_on_checkpoint(None)
        network_sync_hook.set_on_hash(None)
        network_sync_hook.clear_recorded_hashes()
        provider.bind_runtime(runtime)
        provider.set_before_pop(
            lambda: self._lan_allow_frame_pop(
                role=str(role),
                lockstep_runtime=lockstep_runtime,
                session=session,
                dt_tick=float(dt_tick),
            ),
        )
        self._reset_profiler_hook(profiler)
        ticks_applied = 0
        stop_after_finalize = False

        while True:
            self._consume_pending_input_commands(dt_tick=float(dt_tick))
            self._before_lan_tick_step(
                role=str(role),
                lockstep_runtime=lockstep_runtime,
                session=session,
                dt_tick=float(dt_tick),
            )
            result = runner.advance_frame(
                float(dt_tick),
                max_ticks=1,
            )
            if bool(result.stalled) or int(result.ticks_completed) <= 0:
                if provider.pop_blocked:
                    return False
                break

            stop_requested = False
            for tick_result in result.completed_results:
                payload = tick_result.payload
                if payload is None:
                    continue
                tick = cast(DeterministicSessionStepTick, payload)
                runner_tick_index = int(tick_result.tick_index)
                sample = provider.take_frame_sample(runner_tick_index)
                if sample is None:
                    raise RuntimeError("lan tick runner completed without runtime frame metadata")
                frame_tick_index = int(sample.frame_tick_index)
                frame_inputs = tuple(sample.frame_inputs)
                replay_tick_index = replay_hook.recorded_tick_by_runner_tick.pop(runner_tick_index, None)
                hashes = network_sync_hook.recorded_hashes_by_runner_tick.pop(runner_tick_index, None)
                local_command_hash = str(
                    hashes.command_hash if hashes is not None else tick.step.command_hash,
                )
                remote_command_hash = str(sample.remote_command_hash)
                remote_state_hash = str(sample.remote_state_hash)
                elapsed_ms = float(tick.elapsed_ms)
                creature_count_world_step = int(tick.creature_count_world_step)

                if role == "join":
                    if remote_command_hash and remote_command_hash != local_command_hash:
                        runtime.note_desync(
                            kind="command_hash",
                            tick_index=int(frame_tick_index),
                            expected=str(remote_command_hash),
                            actual=str(local_command_hash),
                        )
                    if remote_state_hash:
                        local_state_hash = self._lan_state_hash_for_tick(
                            tick_index=int(frame_tick_index),
                            elapsed_ms=float(elapsed_ms),
                            creature_count_world_step=int(creature_count_world_step),
                        )
                        if local_state_hash != remote_state_hash:
                            runtime.note_desync(
                                kind="state_hash",
                                tick_index=int(frame_tick_index),
                                expected=str(remote_state_hash),
                                actual=str(local_state_hash),
                            )

                host_state_hash = ""
                if role == "host" and self._lan_should_emit_state_hash(tick_index=int(frame_tick_index)):
                    host_state_hash = self._lan_state_hash_for_tick(
                        tick_index=int(frame_tick_index),
                        elapsed_ms=float(elapsed_ms),
                        creature_count_world_step=int(creature_count_world_step),
                    )

                self._apply_sim_step_result(
                    step=tick.step,
                    game_tune_started=bool(session.game_tune_started),
                    apply_audio=True,
                    update_camera=True,
                )
                self._ticks_advanced_per_frame += 1
                ticks_applied += 1

                lan_step = LanTickStep(
                    frame_tick_index=int(frame_tick_index),
                    frame_inputs=tuple(frame_inputs),
                    tick=tick,
                    local_command_hash=str(local_command_hash),
                    host_state_hash=str(host_state_hash),
                    replay_tick_index=replay_tick_index,
                )
                action = self._on_lan_tick_applied(
                    role=str(role),
                    lockstep_runtime=lockstep_runtime,
                    session=session,
                    step=lan_step,
                    dt_tick=float(dt_tick),
                )
                if action == "stop_before_finalize":
                    stop_requested = True
                    break

                if replay_tick_index is not None:
                    self._record_replay_checkpoint_from_tick(
                        tick_index=int(replay_tick_index),
                        tick=tick,
                    )

                if role == "host" and lockstep_runtime is not None:
                    lockstep_runtime.broadcast_tick_frame(
                        TickFrame(
                            tick_index=int(frame_tick_index),
                            frame_inputs=[list(packed) for packed in frame_inputs],
                            command_hash=str(local_command_hash),
                            state_hash=str(host_state_hash),
                        ),
                    )
                if action == "stop_after_finalize":
                    stop_after_finalize = True
                    stop_requested = True
                    break

            if stop_requested:
                break

        self._sim_ms += float(profiler.sim_ms)
        self._presentation_plan_ms += float(profiler.presentation_plan_ms)
        self._presentation_apply_ms += float(profiler.presentation_apply_ms)
        if int(ticks_applied) <= 0:
            self._input_stall_count += 1
        return bool(stop_after_finalize)

    def _sync_audio_and_ground(self) -> None:
        if self.world.audio_bridge.router is not None:
            self.world.audio_bridge.router.audio = self.world.audio
            self.world.audio_bridge.router.audio_rng = self.world.audio_rng
            self.world.audio_bridge.router.demo_mode_active = self.world.demo_mode_active
        if self.world.render_resources.ground is not None:
            self.world.sync_ground_settings()
            self.world.render_resources.ground.process_pending()

    def _apply_sim_step_result(
        self,
        *,
        step: object,
        game_tune_started: bool,
        apply_audio: bool,
        update_camera: bool,
    ) -> None:
        deterministic_step = cast(Any, step)
        self.world.sim_world.apply_step_metadata(
            events=deterministic_step.events,
            presentation=deterministic_step.presentation,
            command_hash=str(deterministic_step.command_hash),
            dt_sim=float(deterministic_step.dt_sim),
            game_tune_started=bool(game_tune_started),
        )
        self.world.sync_audio_bridge_state()
        self.world.audio_bridge.apply_plan(
            plan=deterministic_step.presentation,
            apply_audio=bool(apply_audio),
        )
        if update_camera:
            self.world.update_camera(float(deterministic_step.dt_sim))

    def _run_deterministic_session_ticks(
        self,
        *,
        dt_frame: float,
        session: DeterministicSessionLike,
        recorder: ReplayRecorder | None,
        on_tick: Callable[[DeterministicSessionStepTick, int | None], bool],
        on_checkpoint: Callable[[int, DeterministicSessionStepTick], None] | None = None,
        on_hash: Callable[[int, TickHashes], None] | None = None,
    ) -> None:
        if float(dt_frame) <= 0.0:
            return
        self._sync_audio_and_ground()
        session.detail_preset = int(self._deterministic_detail_preset())
        session.gore_disabled = int(self._deterministic_gore_disabled())

        runner, _provider, replay_hook, checkpoint_hook, net_sync_hook, profiler_hook, observer_hook = (
            self._ensure_gameplay_tick_runner(
                session=session,
            )
        )
        replay_hook.set_recorder(recorder)
        replay_hook.clear_recorded_ticks()
        checkpoint_hook.set_on_checkpoint(
            (
                (lambda tick_index, tick: on_checkpoint(int(tick_index), cast(DeterministicSessionStepTick, tick)))
                if on_checkpoint is not None
                else None
            ),
        )
        net_sync_hook.set_on_hash(on_hash)
        observer_hook.bind(on_tick)
        self._reset_profiler_hook(profiler_hook)

        batch = runner.advance_frame(
            float(dt_frame),
        )
        observer_hook.bind(None)

        for tick_result in batch.completed_results:
            payload = tick_result.payload
            if payload is None:
                continue
            tick_row = cast(DeterministicSessionStepTick, payload)
            self._apply_sim_step_result(
                step=tick_row.step,
                game_tune_started=session.game_tune_started,
                apply_audio=True,
                update_camera=True,
            )
            self._ticks_advanced_per_frame += 1
        self._sim_ms = float(profiler_hook.sim_ms)
        self._presentation_plan_ms = float(profiler_hook.presentation_plan_ms)
        self._presentation_apply_ms = float(profiler_hook.presentation_apply_ms)
        if bool(batch.stalled) and int(batch.ticks_completed) <= 0:
            self._input_stall_count += 1
