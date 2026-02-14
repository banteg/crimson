from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import datetime as dt
import hashlib
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.console import ConsoleState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.view import ViewContext

from ..game_modes import GameMode
from ..weapon_runtime import weapon_assign_player
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import load_perk_menu_assets
from ..replay import ReplayHeader, ReplayRecorder, ReplayStatusSnapshot, dump_replay
from ..replay.types import WEAPON_USAGE_COUNT
from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINTS_FORMAT_VERSION,
    ReplayCheckpoint,
    ReplayCheckpoints,
    build_checkpoint,
    default_checkpoints_path,
    dump_checkpoints_file,
    resolve_checkpoint_sample_rate,
)
from ..sim.clock import FixedStepClock
from ..sim.input import PlayerInput
from ..sim.sessions import RushDeterministicSession
from ..net.protocol import TickFrame
from ..weapons import WeaponId
from .base_gameplay_mode import BaseGameplayMode
from .components.highscore_record_builder import build_highscore_record_for_game_over

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
            )
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
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)
        self._rush = _RushState()
        self._sim_clock.reset()
        self._lan_capture_clock.reset()
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
        status = self.state.status
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
                0, WEAPON_USAGE_COUNT - len(weapon_usage_counts)
            )
            weapon_usage_counts = weapon_usage_counts[:WEAPON_USAGE_COUNT]
        status_snapshot = ReplayStatusSnapshot(
            quest_unlock_index=int(getattr(status, "quest_unlock_index", 0) or 0) if status is not None else 0,
            quest_unlock_index_full=int(getattr(status, "quest_unlock_index_full", 0) or 0)
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
                    tick_rate=int(self._sim_clock.tick_rate),
                    difficulty_level=int(self.world.difficulty_level),
                    hardcore=bool(self.world.hardcore),
                    preserve_bugs=bool(self.world.preserve_bugs),
                    world_size=float(self.world.world_size),
                    player_count=len(self.world.players),
                    status=status_snapshot,
                )
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
        data = dump_replay(replay)
        digest = hashlib.sha256(data).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        replay_dir = self._base_dir / "replays"
        replay_dir.mkdir(parents=True, exist_ok=True)
        kills = int(self.creatures.kill_count)
        base_name = f"rush_{stamp}_kills{kills}"
        path = replay_dir / f"{base_name}.crdemo.gz"
        counter = 1
        while path.exists():
            path = replay_dir / f"{base_name}_{counter}.crdemo.gz"
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
        if self.world.audio_router is not None:
            self.world.audio_router.audio = self.world.audio
            self.world.audio_router.audio_rng = self.world.audio_rng
            self.world.audio_router.demo_mode_active = self.world.demo_mode_active
        if self.world.ground is not None:
            self.world._sync_ground_settings()
            self.world.ground.process_pending()
        session.detail_preset = self.config.detail_preset
        session.fx_toggle = self.config.fx_toggle

        for tick_offset in range(int(ticks_to_run)):
            inputs = input_frame if tick_offset == 0 else self._clear_local_input_edges(input_frame)
            recorder = self._replay_recorder
            if recorder is not None:
                tick_index = recorder.record_tick(inputs)
            else:
                tick_index = None
            tick = session.step_tick(
                dt_frame=dt_tick,
                inputs=inputs,
            )
            self.world.apply_step_result(
                tick.step,
                game_tune_started=bool(session.game_tune_started),
                apply_audio=True,
                update_camera=True,
            )
            self._rush.elapsed_ms = float(session.elapsed_ms)
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
                break

    def _update_lan_match(self, *, dt_frame: float) -> None:
        runtime = self._lan_runtime
        if runtime is None:
            return
        session = self._sim_session
        if session is None:
            return

        ticks_to_capture = self._lan_capture_clock.advance(dt_frame)
        if ticks_to_capture > 0:
            input_frame = self._build_local_inputs(dt_frame=dt_frame)
            local_slot = int(self._lan_local_slot_index)
            for tick_offset in range(int(ticks_to_capture)):
                inputs = input_frame if tick_offset == 0 else self._clear_local_input_edges(input_frame)
                local_input = PlayerInput()
                if 0 <= local_slot < len(inputs):
                    local_input = inputs[local_slot]
                runtime.queue_local_input(self._pack_player_input_for_net(local_input))

        any_alive = any(player.health > 0.0 for player in self.world.players)
        if (not any_alive) or bool(self._paused):
            self._sim_clock.reset()
            if not any_alive:
                self._enter_game_over()
            return

        if self.world.audio_router is not None:
            self.world.audio_router.audio = self.world.audio
            self.world.audio_router.audio_rng = self.world.audio_rng
            self.world.audio_router.demo_mode_active = self.world.demo_mode_active
        if self.world.ground is not None:
            self.world._sync_ground_settings()
            self.world.ground.process_pending()
        session.detail_preset = self.config.detail_preset
        session.fx_toggle = self.config.fx_toggle

        dt_tick = float(self._lan_capture_clock.dt_tick)
        while True:
            frame = runtime.pop_tick_frame()
            if frame is None:
                break

            packed_inputs = list(getattr(frame, "frame_inputs", []) or [])
            player_inputs = [self._unpack_player_input_from_net(packed) for packed in packed_inputs]
            recorder = self._replay_recorder
            if recorder is not None:
                tick_index = recorder.record_tick(player_inputs)
            else:
                tick_index = None
            tick = session.step_tick(
                dt_frame=float(dt_tick),
                inputs=player_inputs,
            )
            self.world.apply_step_result(
                tick.step,
                game_tune_started=bool(session.game_tune_started),
                apply_audio=True,
                update_camera=True,
            )
            self._rush.elapsed_ms = float(session.elapsed_ms)
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

            if str(self._lan_role) == "host":
                runtime.broadcast_tick_frame(
                    TickFrame(
                        tick_index=int(frame.tick_index),
                        frame_inputs=list(frame.frame_inputs),
                        command_hash=str(tick.step.command_hash),
                        state_hash="",
                    )
                )

            if not any(player.health > 0.0 for player in self.world.players):
                self._enter_game_over()
                break

    def _draw_game_cursor(self) -> None:
        mouse_pos = self._ui_mouse
        cursor_tex = self._ui_assets.cursor if self._ui_assets is not None else None
        draw_menu_cursor(
            self.world.particles_texture,
            cursor_tex,
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_aim_cursor(self) -> None:
        mouse_pos = self._ui_mouse
        aim_tex = self._ui_assets.aim if self._ui_assets is not None else None
        draw_aim_cursor(self.world.particles_texture, aim_tex, pos=mouse_pos)

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
                self._hud_assets,
                state=self._hud_state,
                player=self.player,
                players=self.world.players,
                bonus_hud=self.state.bonus_hud,
                elapsed_ms=self._rush.elapsed_ms,
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                small_indicators=self._hud_small_indicators(),
                preserve_bugs=bool(self.world.preserve_bugs),
            )

        if not self._game_over_active:
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

        warn_y = float(rl.get_screen_height()) - 28.0
        if self.world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self.world.missing_assets)
            self._draw_ui_text(warn, Vec2(24.0, warn_y), UI_ERROR_COLOR, scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, Vec2(24.0, warn_y), UI_ERROR_COLOR, scale=0.8)

        if not self._game_over_active:
            self._draw_aim_cursor()
        else:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    hud_assets=self._hud_assets,
                    mouse=self._ui_mouse_pos(),
                )
        self._draw_lan_wait_overlay()
