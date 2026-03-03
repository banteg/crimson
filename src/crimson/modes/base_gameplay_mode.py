from __future__ import annotations

import random
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

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
from ..persistence.highscores import HighScoreRecord
from ..render.rtx.mode import RtxRenderMode
from ..sim.input import PlayerInput
from ..sim.sessions import DeterministicSessionTick
from ..sim.timing import FrameTiming
from ..ui.game_over import GameOverUi
from ..ui.hud import HudAssets, HudState, draw_target_health_bar, load_hud_assets

if TYPE_CHECKING:
    from ..creatures.runtime import CreaturePool
    from ..game.types import GameState
    from ..gameplay import GameplayState
    from ..net.lockstep_protocol import StatusSnapshot
    from ..persistence.save_status import GameStatus
    from ..replay import ReplayRecorder
    from ..sim.state_types import PlayerState

LanRuntime = LockstepRuntime | RollbackRuntime

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
    ) -> DeterministicSessionTick: ...

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
        target_players = self.world.players[:1] if self.state.preserve_bugs else self.world.players
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
        self.state: GameplayState = self.world.state
        self.creatures: CreaturePool = self.world.creatures
        self.player: PlayerState = self.world.players[0]
        preserve_bugs = self.state.preserve_bugs
        self._local_input.set_preserve_bugs(preserve_bugs)
        self._hud_state.preserve_bugs = preserve_bugs
        self._game_over_ui.preserve_bugs = preserve_bugs
        # `GameplayState.status` is the simulation status (LAN may override it
        # with a deterministic session-local status to avoid split brain).
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
        ground = self.world.ground
        if ground is None:
            return False
        return ground.generation_pending()

    def _trace_lan_terrain_generation(self) -> None:
        if not self._lan_enabled:
            self._lan_terrain_pending_last = False
            self._lan_initial_terrain_ready = False
            return
        ground = self.world.ground
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
        elapsed_ms = float(self.world._elapsed_ms)
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
            local_players=int(len(self.world.players)),
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
        ground = self.world.ground
        lan_debug_log(
            "mode_world_reset",
            mode=self.__class__.__name__,
            seed=int(self._bootstrap_seed),
            seed_source=str(seed_source),
            rng_state=int(self.world.state.rng.state),
            world_size=float(self.world.world_size),
            player_count=int(len(self.world.players)),
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
        self._local_input.reset(players=self.world.players)

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
            play_sfx=self.world.audio_router.play_sfx,
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
        ground = self.world.ground
        self.world.ground = None
        return ground

    def adopt_ground_from_menu(self, ground: GroundRenderer | None) -> None:
        if ground is None:
            return
        current = self.world.ground
        if current is not None and current is not ground and current.render_target is not None:
            rl.unload_render_texture(current.render_target)
            current.render_target = None
        self.world.ground = ground
        self.world._sync_ground_settings()

    def menu_ground_camera(self) -> Vec2:
        return self.world.camera

    def console_elapsed_ms(self) -> float:
        return float(self.world._elapsed_ms)

    def regenerate_terrain_for_console(self) -> None:
        if self.world.ground is None:
            return
        # Keep this deterministic without consuming gameplay RNG.
        self._terrain_regen_counter = (int(self._terrain_regen_counter) + 1) & 0xFFFFFFFF
        terrain_seed = (int(self.state.rng.state) + int(self._terrain_regen_counter)) & 0xFFFFFFFF
        self.world.ground.schedule_generate(seed=terrain_seed, layers=3)

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
            players=self.world.players,
            config=self.config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self.world.screen_to_world,
            dt=float(dt),
            creatures=self.creatures.entries,
        )

    @staticmethod
    def _clear_local_input_edges(inputs: list[PlayerInput]) -> list[PlayerInput]:
        return clear_input_edges(inputs)

    def _run_deterministic_session_ticks(
        self,
        *,
        ticks_to_run: int,
        dt_tick: float,
        input_frame: list[PlayerInput],
        session: DeterministicSessionLike,
        recorder: ReplayRecorder | None,
        on_tick: Callable[[DeterministicSessionTick, int | None], bool],
    ) -> None:
        if self.world.audio_router is not None:
            self.world.audio_router.audio = self.world.audio
            self.world.audio_router.audio_rng = self.world.audio_rng
            self.world.audio_router.demo_mode_active = self.world.demo_mode_active
        if self.world.ground is not None:
            self.world._sync_ground_settings()
            self.world.ground.process_pending()
        session.detail_preset = int(self._deterministic_detail_preset())
        session.gore_disabled = int(self._deterministic_gore_disabled())

        for tick_offset in range(int(ticks_to_run)):
            inputs = input_frame if tick_offset == 0 else self._clear_local_input_edges(input_frame)
            if recorder is not None:
                tick_index: int | None = recorder.record_tick(inputs)
            else:
                tick_index = None
            timing = session.timing_for_dt(float(dt_tick))
            tick = session.step_tick(
                timing=timing,
                inputs=inputs,
            )
            self.world.apply_step_result(
                tick.step,
                game_tune_started=session.game_tune_started,
                apply_audio=True,
                update_camera=True,
            )
            if on_tick(tick, tick_index):
                break
