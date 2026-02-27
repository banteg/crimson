from __future__ import annotations

import datetime as dt
import hashlib
import random
from collections.abc import Sequence
from dataclasses import dataclass, replace

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..net.debug_log import lan_debug_log
from ..net.protocol import STATE_HASH_PERIOD_TICKS, TickFrame
from ..replay import ReplayClaimedStatsSnapshot, ReplayHeader, ReplayRecorder, ReplayStatusSnapshot, dump_replay
from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINTS_FORMAT_VERSION,
)
from ..replay.checkpoints import (
    ReplayCheckpoint,
    ReplayCheckpoints,
    build_checkpoint,
    default_checkpoints_path,
    dump_checkpoints_file,
    resolve_checkpoint_sample_rate,
)
from ..replay.input_codec import pack_player_input, unpack_player_input
from ..replay.types import WEAPON_USAGE_COUNT
from ..sim.bootstrap import run_terrain_bootstrap
from ..sim.clock import FixedStepClock
from ..sim.input import PlayerInput
from ..sim.sessions import DeterministicSessionTick, RushDeterministicSession
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import load_perk_menu_assets
from ..weapon_runtime import most_used_weapon_id_for_player, weapon_assign_player
from ..weapons import WeaponId
from .base_gameplay_mode import BaseGameplayMode
from .components.highscore_record_builder import build_highscore_record_for_game_over, shots_from_state

WORLD_SIZE = 1024.0
RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(slots=True)
class _RushState:
    elapsed_ms: float = 0.0
    spawn_cooldown_ms: float = 0.0


class RushMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=int(GameMode.RUSH),
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._rush = _RushState()

        self._ui_assets = None
        self._sim_clock = FixedStepClock(tick_rate=60)
        self._lan_capture_clock = FixedStepClock(tick_rate=60)
        self._replay_recorder: ReplayRecorder | None = None
        self._replay_checkpoints: list[ReplayCheckpoint] = []
        self._replay_checkpoints_sample_rate: int = 60
        self._replay_checkpoints_last_tick: int | None = None
        self._sim_session: RushDeterministicSession | None = None

    def _record_replay_checkpoint(
        self,
        tick_index: int,
        *,
        force: bool = False,
        rng_marks: dict[str, int] | None = None,
        deaths: Sequence[object] | None = None,
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
                world=self.world.world_state,
                elapsed_ms=float(self._rush.elapsed_ms),
                rng_marks=rng_marks,
                deaths=deaths,
                events=events,
                command_hash=command_hash,
            ),
        )
        self._replay_checkpoints_last_tick = int(tick_index)

    def _enforce_rush_loadout(self) -> None:
        for player in self.world.players:
            if int(player.weapon_id) != RUSH_WEAPON_ID:
                weapon_assign_player(player, RUSH_WEAPON_ID)
            # `rush_mode_update` forces weapon+ammo every frame; keep ammo topped up.
            player.ammo = float(max(0, int(player.clip_size)))

    def open(self) -> None:
        super().open()
        self._ui_assets = load_perk_menu_assets(self._assets_root)
        self._rush = _RushState()
        self._sim_clock.reset()
        self._lan_capture_clock.reset()

        status = self.state.status
        base_status = self.save_status
        sim_unlock_index = int(status.quest_unlock_index) if status is not None else 0
        sim_unlock_index_full = int(status.quest_unlock_index_full) if status is not None else 0
        status_unlock_index = int(base_status.quest_unlock_index) if base_status is not None else int(sim_unlock_index)
        status_unlock_index_full = (
            int(base_status.quest_unlock_index_full)
            if base_status is not None
            else int(sim_unlock_index_full)
        )
        quest_unlock_index = int(sim_unlock_index)
        bootstrap = run_terrain_bootstrap(
            self.state.rng,
            quest_unlock_index=int(quest_unlock_index),
            width=int(self.world.world_size),
            height=int(self.world.world_size),
            layers=3,
        )
        lan_debug_log(
            "terrain_bootstrap",
            mode="RushMode",
            lan_enabled=bool(self._lan_enabled),
            lan_role=str(self._lan_role),
            status_quest_unlock_index=int(status_unlock_index),
            status_quest_unlock_index_full=int(status_unlock_index_full),
            sim_quest_unlock_index=int(sim_unlock_index),
            sim_quest_unlock_index_full=int(sim_unlock_index_full),
            quest_unlock_index=int(quest_unlock_index),
            seed_before=int(bootstrap.seed_before),
            seed_after=int(bootstrap.seed_after),
            selection_draws=int(bootstrap.selection_draws),
            stamping_draws=int(bootstrap.stamping_draws),
            terrain_base=int(bootstrap.terrain_ids[0]),
            terrain_overlay=int(bootstrap.terrain_ids[1]),
            terrain_detail=int(bootstrap.terrain_ids[2]),
            terrain_seed=int(bootstrap.terrain_seed),
        )
        self.world.apply_bootstrap_terrain(
            terrain_ids=bootstrap.terrain_ids,
            seed=bootstrap.terrain_seed,
            layers=3,
        )
        self._sim_session = RushDeterministicSession(
            world=self.world.world_state,
            world_size=float(self.world.world_size),
            damage_scale_by_type=self.world._damage_scale_by_type,
            fx_queue=self.world.fx_queue,
            fx_queue_rotated=self.world.fx_queue_rotated,
            detail_preset=5,
            fx_toggle=0,
            game_tune_started=bool(self.world._game_tune_started),
            clear_fx_queues_each_tick=False,
            enforce_loadout=self._enforce_rush_loadout,
        )
        self._enforce_rush_loadout()
        weapon_usage_counts: tuple[int, ...] = ()
        if status is not None:
            raw_counts = status.data.get("weapon_usage_counts")
            if isinstance(raw_counts, list):
                coerced: list[int] = []
                for value in raw_counts[:WEAPON_USAGE_COUNT]:
                    try:
                        coerced.append(int(value) & 0xFFFFFFFF)
                    except (TypeError, ValueError, OverflowError):
                        coerced.append(0)
                weapon_usage_counts = tuple(coerced)
        if len(weapon_usage_counts) != WEAPON_USAGE_COUNT:
            weapon_usage_counts = tuple(weapon_usage_counts) + (0,) * max(
                0, WEAPON_USAGE_COUNT - len(weapon_usage_counts),
            )
            weapon_usage_counts = weapon_usage_counts[:WEAPON_USAGE_COUNT]
        status_snapshot = ReplayStatusSnapshot(
            quest_unlock_index=int(status.quest_unlock_index) if status is not None else 0,
            quest_unlock_index_full=int(status.quest_unlock_index_full)
            if status is not None
            else 0,
            weapon_usage_counts=weapon_usage_counts,
        )
        record_replay = (not bool(self._lan_enabled)) or str(self._lan_role) == "host"
        if record_replay:
            self._replay_recorder = ReplayRecorder(
                ReplayHeader(
                    game_mode_id=int(GameMode.RUSH),
                    seed=int(self.state.rng.state),
                    bootstrap_kind="terrain_v1",
                    bootstrap_seed=int(self._bootstrap_seed),
                    tick_rate=int(self._sim_clock.tick_rate),
                    difficulty_level=int(self.world.difficulty_level),
                    hardcore=bool(self.world.hardcore),
                    preserve_bugs=bool(self.state.preserve_bugs),
                    detail_preset=int(self._deterministic_detail_preset()),
                    fx_toggle=int(self._deterministic_fx_toggle()),
                    world_size=float(self.world.world_size),
                    player_count=len(self.world.players),
                    status=status_snapshot,
                ),
            )
            tick_rate = int(self._replay_recorder.header.tick_rate)
            self._replay_checkpoints_sample_rate = resolve_checkpoint_sample_rate(tick_rate)
        else:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def close(self) -> None:
        if self._ui_assets is not None:
            self._ui_assets = None
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._sim_session = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = "back_to_menu"
                self.close_requested = True
            return

        if (not bool(self._lan_enabled)) and rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

    def _enter_game_over(self) -> None:
        if self._game_over_active:
            return

        game_mode_id = self.config.game_mode
        record = build_highscore_record_for_game_over(
            state=self.state,
            player=self.player,
            survival_elapsed_ms=int(self._rush.elapsed_ms),
            creature_kill_count=int(self.creatures.kill_count),
            game_mode_id=game_mode_id,
        )

        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True
        self._save_replay()

    def _save_replay(self) -> None:
        recorder = self._replay_recorder
        if recorder is None:
            return
        self._record_replay_checkpoint(max(0, recorder.tick_index - 1), force=True)
        replay = recorder.finish()
        shots_fired, shots_hit = shots_from_state(self.state, player_index=int(self.player.index))
        most_used_weapon_id = most_used_weapon_id_for_player(
            self.state,
            player_index=int(self.player.index),
            fallback_weapon_id=int(self.player.weapon_id),
        )
        replay = replace(
            replay,
            header=replace(
                replay.header,
                claimed_stats=ReplayClaimedStatsSnapshot(
                    complete=bool(self._game_over_active),
                    ticks=int(recorder.tick_index),
                    elapsed_ms=int(self._rush.elapsed_ms),
                    score_xp=int(self.player.experience),
                    kills=int(self.creatures.kill_count),
                    most_used_weapon_id=int(most_used_weapon_id),
                    shots_fired=int(shots_fired),
                    shots_hit=int(shots_hit),
                ),
            ),
        )
        data = dump_replay(replay)
        digest = hashlib.sha256(data).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        replay_dir = self._base_dir / "replays"
        replay_dir.mkdir(parents=True, exist_ok=True)
        kills = int(self.creatures.kill_count)
        base_name = f"rush_{stamp}_kills{kills}"
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

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame = self._tick_frame(dt)[0]
        self._handle_input()
        if self._action == "open_pause_menu":
            return

        if self._game_over_active:
            self._update_game_over_ui(dt)
            return

        if bool(self._lan_enabled) and self._lan_runtime is not None:
            self._update_lan_match(dt_frame=dt_frame)
            return

        any_alive = any(player.health > 0.0 for player in self.world.players)
        sim_active = (not self._paused) and any_alive

        self._update_lan_wait_gate_debug_override()
        if self._lan_wait_gate_active():
            self._sim_clock.reset()
            return

        if not sim_active:
            self._sim_clock.reset()
            if not any_alive:
                self._enter_game_over()
            return

        ticks_to_run = self._sim_clock.advance(dt_frame)
        if ticks_to_run <= 0:
            return

        dt_tick = float(self._sim_clock.dt_tick)
        input_frame = self._build_local_inputs(dt_frame=dt_frame)
        session = self._sim_session
        if session is None:
            return

        def _on_tick(tick: DeterministicSessionTick, tick_index: int | None) -> bool:
            self._rush.elapsed_ms = float(tick.elapsed_ms)
            self._rush.spawn_cooldown_ms = float(session.spawn_cooldown_ms)
            world_events = tick.step.events

            if tick_index is not None:
                self._record_replay_checkpoint(
                    int(tick_index),
                    rng_marks=tick.rng_marks,
                    deaths=world_events.deaths,
                    events=world_events,
                    command_hash=str(tick.step.command_hash),
                )

            if not any(player.health > 0.0 for player in self.world.players):
                self._enter_game_over()
                return True
            return False

        self._run_deterministic_session_ticks(
            ticks_to_run=int(ticks_to_run),
            dt_tick=dt_tick,
            input_frame=input_frame,
            session=session,
            recorder=self._replay_recorder,
            on_tick=_on_tick,
        )

    def _update_lan_match(self, *, dt_frame: float) -> None:
        runtime = self._lan_runtime
        if runtime is None:
            return
        session = self._sim_session
        if session is None:
            return

        runtime.update()
        role = str(self._lan_role)
        self._consume_net_runtime_recovery(mode_name="rush")
        if str(runtime.error or ""):
            self.close_requested = True
            return
        if self.world.audio_router is not None:
            self.world.audio_router.audio = self.world.audio
            self.world.audio_router.audio_rng = self.world.audio_rng
            self.world.audio_router.demo_mode_active = self.world.demo_mode_active
        if self.world.ground is not None:
            self.world._sync_ground_settings()
            self.world.ground.process_pending()
        self._trace_lan_terrain_generation()
        if bool(self._lan_terrain_generation_pending()):
            self._lan_capture_clock.reset()
            return

        if role == "host" and (not bool(runtime.host_remote_inputs_ready())):
            return

        if bool(self._paused):
            self._sim_clock.reset()
            return
        session.detail_preset = int(self._deterministic_detail_preset())
        session.fx_toggle = int(self._deterministic_fx_toggle())

        dt_tick = float(self._lan_capture_clock.dt_tick)
        def _consume_lan_frames() -> bool:
            while True:
                frame = runtime.pop_tick_frame()
                if frame is None:
                    return False

                packed_inputs = list(frame.frame_inputs)
                player_inputs = [unpack_player_input(packed) for packed in packed_inputs]
                recorder = self._replay_recorder
                if recorder is not None:
                    tick_index = recorder.record_tick(player_inputs)
                else:
                    tick_index = None
                tick = session.step_tick(
                    dt_frame=float(dt_tick),
                    inputs=player_inputs,
                )

                remote_command_hash = str(frame.command_hash or "")
                remote_state_hash = str(frame.state_hash or "")
                local_command_hash = str(tick.step.command_hash)
                local_state_hash = ""
                if role == "join":
                    if remote_command_hash and remote_command_hash != local_command_hash:
                        runtime.note_desync(
                            kind="command_hash",
                            tick_index=int(frame.tick_index),
                            expected=str(remote_command_hash),
                            actual=str(local_command_hash),
                        )
                    if remote_state_hash:
                        local_state_hash = str(
                            build_checkpoint(
                                tick_index=int(frame.tick_index),
                                world=self.world.world_state,
                                elapsed_ms=float(tick.elapsed_ms),
                                creature_count_override=int(tick.creature_count_world_step),
                            ).state_hash,
                        )
                        if local_state_hash != remote_state_hash:
                            runtime.note_desync(
                                kind="state_hash",
                                tick_index=int(frame.tick_index),
                                expected=str(remote_state_hash),
                                actual=str(local_state_hash),
                            )

                state_hash = ""
                if role == "host":
                    tick_i = int(frame.tick_index)
                    if int(tick_i) < 5 or (int(tick_i) % int(STATE_HASH_PERIOD_TICKS)) == 0:
                        state_hash = str(
                            build_checkpoint(
                                tick_index=int(frame.tick_index),
                                world=self.world.world_state,
                                elapsed_ms=float(tick.elapsed_ms),
                                creature_count_override=int(tick.creature_count_world_step),
                            ).state_hash,
                        )
                self.world.apply_step_result(
                    tick.step,
                    game_tune_started=bool(session.game_tune_started),
                    apply_audio=True,
                    update_camera=True,
                )
                self._rush.elapsed_ms = float(tick.elapsed_ms)
                self._rush.spawn_cooldown_ms = float(session.spawn_cooldown_ms)
                self._store_net_runtime_snapshot(
                    mode_name="rush",
                    tick_index=int(frame.tick_index),
                    session_state={
                        "elapsed_ms": float(tick.elapsed_ms),
                        "spawn_cooldown_ms": float(session.spawn_cooldown_ms),
                    },
                    mode_state={
                        "rush_elapsed_ms": float(self._rush.elapsed_ms),
                        "rush_spawn_cooldown_ms": float(self._rush.spawn_cooldown_ms),
                        "kill_count": int(self.creatures.kill_count),
                    },
                )
                world_events = tick.step.events

                if tick_index is not None:
                    self._record_replay_checkpoint(
                        int(tick_index),
                        rng_marks=tick.rng_marks,
                        deaths=world_events.deaths,
                        events=world_events,
                        command_hash=str(tick.step.command_hash),
                    )

                if role == "host":
                    runtime.broadcast_tick_frame(
                        TickFrame(
                            tick_index=int(frame.tick_index),
                            frame_inputs=list(frame.frame_inputs),
                            command_hash=str(local_command_hash),
                            state_hash=str(state_hash),
                        ),
                    )

                if not any(player.health > 0.0 for player in self.world.players):
                    self._enter_game_over()
                    return True

        if role == "join":
            if _consume_lan_frames():
                return

        ticks_to_capture = self._lan_capture_clock.advance(dt_frame)
        if ticks_to_capture > 0:
            input_frame = self._build_local_inputs(dt_frame=dt_frame)
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
        # Pump networking again after queuing local inputs so the host can emit frames
        # in the same render frame (reduces perceived host-side input latency).
        runtime.update()

        _consume_lan_frames()

    def _draw_game_cursor(self) -> None:
        mouse_pos = self._ui_mouse
        cursor_tex = self._ui_assets.cursor if self._ui_assets is not None else None
        draw_menu_cursor(
            self.world.particles_texture,
            cursor_tex,
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )

    def draw(self) -> None:
        self.world.draw(
            draw_aim_indicators=(not self._game_over_active),
            entity_alpha=self._world_entity_alpha(),
        )
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not self._game_over_active) and self._hud_assets is not None:
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    assets=self._hud_assets,
                    state=self._hud_state,
                    font=self._small,
                    show_health=hud_flags.show_health,
                    show_weapon=hud_flags.show_weapon,
                    show_xp=hud_flags.show_xp,
                    show_time=hud_flags.show_time,
                    show_quest_hud=hud_flags.show_quest_hud,
                    small_indicators=self._hud_small_indicators(),
                ),
                player=self.player,
                players=self.world.players,
                bonus_hud=self.state.bonus_hud,
                elapsed_ms=self._rush.elapsed_ms,
                frame_dt_ms=self._last_dt_ms,
            )

        if debug_enabled() and (not self._game_over_active):
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            self._draw_ui_text(f"rush: t={self._rush.elapsed_ms / 1000.0:6.1f}s", Vec2(x, y), UI_TEXT_COLOR)
            self._draw_ui_text(f"kills={self.creatures.kill_count}", Vec2(x, y + line), UI_HINT_COLOR)
            y_extra = y + line * 2.0
            if self._paused:
                self._draw_ui_text("paused (TAB)", Vec2(x, y_extra), UI_HINT_COLOR)
                y_extra += line
            if self.player.health <= 0.0:
                self._draw_ui_text("game over", Vec2(x, y_extra), UI_ERROR_COLOR)
                y_extra += line
            self._draw_lan_debug_info(x=x, y=y_extra, line_h=line)

        if self._game_over_active:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    hud_assets=self._hud_assets,
                    mouse=self._ui_mouse_pos(),
                )
        self._draw_lan_wait_overlay()
