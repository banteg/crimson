from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.console import ConsoleState
from grim.config import CrimsonConfig
from grim.view import ViewContext

from ..creatures.spawn import tick_rush_mode_spawns
from ..game_modes import GameMode
from ..gameplay import PlayerInput, weapon_assign_player
from ..input_codes import config_keybinds, input_code_is_down, input_code_is_pressed, player_move_fire_binds
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
)
from ..sim.clock import FixedStepClock
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
        self._replay_recorder: ReplayRecorder | None = None
        self._replay_checkpoints: list[ReplayCheckpoint] = []
        self._replay_checkpoints_sample_rate: int = 60
        self._replay_checkpoints_last_tick: int | None = None

    def _record_replay_checkpoint(self, tick_index: int, *, force: bool = False) -> None:
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
                world=self._world.world_state,
                elapsed_ms=float(self._rush.elapsed_ms),
            )
        )
        self._replay_checkpoints_last_tick = int(tick_index)

    def _enforce_rush_loadout(self) -> None:
        for player in self._world.players:
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
        self._enforce_rush_loadout()
        status = self._state.status
        weapon_usage_counts: tuple[int, ...] = ()
        if status is not None:
            try:
                raw_counts = status.data.get("weapon_usage_counts")
                if isinstance(raw_counts, list):
                    weapon_usage_counts = tuple(int(value) & 0xFFFFFFFF for value in raw_counts[:WEAPON_USAGE_COUNT])
            except Exception:
                weapon_usage_counts = ()
        if len(weapon_usage_counts) != WEAPON_USAGE_COUNT:
            weapon_usage_counts = tuple(weapon_usage_counts) + (0,) * max(0, WEAPON_USAGE_COUNT - len(weapon_usage_counts))
            weapon_usage_counts = weapon_usage_counts[:WEAPON_USAGE_COUNT]
        status_snapshot = ReplayStatusSnapshot(
            quest_unlock_index=int(getattr(status, "quest_unlock_index", 0) or 0) if status is not None else 0,
            quest_unlock_index_full=int(getattr(status, "quest_unlock_index_full", 0) or 0) if status is not None else 0,
            weapon_usage_counts=weapon_usage_counts,
        )
        self._replay_recorder = ReplayRecorder(
            ReplayHeader(
                game_mode_id=int(GameMode.RUSH),
                seed=int(self._state.rng.state),
                tick_rate=int(self._sim_clock.tick_rate),
                difficulty_level=int(self._world.difficulty_level),
                hardcore=bool(self._world.hardcore),
                preserve_bugs=bool(self._world.preserve_bugs),
                world_size=float(self._world.world_size),
                player_count=len(self._world.players),
                status=status_snapshot,
            )
        )
        tick_rate = int(self._replay_recorder.header.tick_rate)
        self._replay_checkpoints_sample_rate = max(1, tick_rate)
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

    def close(self) -> None:
        if self._ui_assets is not None:
            self._ui_assets = None
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = "back_to_menu"
                self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

    def _build_input(self) -> PlayerInput:
        keybinds = config_keybinds(self._config)
        if not keybinds:
            keybinds = (0x11, 0x1F, 0x1E, 0x20, 0x100)
        up_key, down_key, left_key, right_key, fire_key = player_move_fire_binds(keybinds, 0)

        move_x = 0.0
        move_y = 0.0
        if input_code_is_down(left_key):
            move_x -= 1.0
        if input_code_is_down(right_key):
            move_x += 1.0
        if input_code_is_down(up_key):
            move_y -= 1.0
        if input_code_is_down(down_key):
            move_y += 1.0

        mouse = self._ui_mouse_pos()
        aim_x, aim_y = self._world.screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = input_code_is_down(fire_key)
        fire_pressed = input_code_is_pressed(fire_key)

        return PlayerInput(
            move_x=move_x,
            move_y=move_y,
            aim_x=float(aim_x),
            aim_y=float(aim_y),
            fire_down=bool(fire_down),
            fire_pressed=bool(fire_pressed),
            reload_pressed=False,
        )

    def _player_name_default(self) -> str:
        config = self._config
        if config is None:
            return ""
        raw = config.data.get("player_name")
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
        if isinstance(raw, str):
            return raw
        return ""

    def _enter_game_over(self) -> None:
        if self._game_over_active:
            return

        game_mode_id = int(self._config.data.get("game_mode", int(GameMode.RUSH))) if self._config is not None else int(GameMode.RUSH)
        record = build_highscore_record_for_game_over(
            state=self._state,
            player=self._player,
            survival_elapsed_ms=int(self._rush.elapsed_ms),
            creature_kill_count=int(self._creatures.kill_count),
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
        path = replay_dir / f"{stamp}_{digest}.crdemo.gz"
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

        any_alive = any(player.health > 0.0 for player in self._world.players)
        sim_active = (not self._paused) and any_alive

        if not sim_active:
            self._sim_clock.reset()
            if not any_alive:
                self._enter_game_over()
            return

        ticks_to_run = self._sim_clock.advance(dt_frame)
        if ticks_to_run <= 0:
            return

        dt_tick = float(self._sim_clock.dt_tick)
        input_frame = self._build_input()
        input_tick = input_frame

        for tick_offset in range(int(ticks_to_run)):
            if tick_offset:
                input_tick = PlayerInput(
                    move_x=float(input_frame.move_x),
                    move_y=float(input_frame.move_y),
                    aim_x=float(input_frame.aim_x),
                    aim_y=float(input_frame.aim_y),
                    fire_down=bool(input_frame.fire_down),
                    fire_pressed=False,
                    reload_pressed=False,
                )

            self._rush.elapsed_ms += dt_tick * 1000.0
            self._enforce_rush_loadout()
            inputs = [input_tick for _ in self._world.players]
            recorder = self._replay_recorder
            if recorder is not None:
                tick_index = recorder.record_tick(inputs)
            else:
                tick_index = None
            self._world.update(
                dt_tick,
                inputs=inputs,
                auto_pick_perks=False,
                game_mode=int(GameMode.RUSH),
                perk_progression_enabled=False,
            )

            cooldown, spawns = tick_rush_mode_spawns(
                self._rush.spawn_cooldown_ms,
                dt_tick * 1000.0,
                self._state.rng,
                player_count=len(self._world.players),
                survival_elapsed_ms=int(self._rush.elapsed_ms),
                terrain_width=float(self._world.world_size),
                terrain_height=float(self._world.world_size),
            )
            self._rush.spawn_cooldown_ms = cooldown
            self._creatures.spawn_inits(spawns)

            if tick_index is not None:
                self._record_replay_checkpoint(int(tick_index))

            if not any(player.health > 0.0 for player in self._world.players):
                self._enter_game_over()
                break

    def _draw_game_cursor(self) -> None:
        mouse_x = float(self._ui_mouse_x)
        mouse_y = float(self._ui_mouse_y)
        cursor_tex = self._ui_assets.cursor if self._ui_assets is not None else None
        draw_menu_cursor(
            self._world.particles_texture,
            cursor_tex,
            x=mouse_x,
            y=mouse_y,
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_aim_cursor(self) -> None:
        mouse_x = float(self._ui_mouse_x)
        mouse_y = float(self._ui_mouse_y)
        aim_tex = self._ui_assets.aim if self._ui_assets is not None else None
        draw_aim_cursor(self._world.particles_texture, aim_tex, x=mouse_x, y=mouse_y)

    def draw(self) -> None:
        self._world.draw(draw_aim_indicators=(not self._game_over_active))
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not self._game_over_active) and self._hud_assets is not None:
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                state=self._hud_state,
                player=self._player,
                players=self._world.players,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=self._rush.elapsed_ms,
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                small_indicators=self._hud_small_indicators(),
            )

        if not self._game_over_active:
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            self._draw_ui_text(f"rush: t={self._rush.elapsed_ms/1000.0:6.1f}s", x, y, UI_TEXT_COLOR)
            self._draw_ui_text(f"kills={self._creatures.kill_count}", x, y + line, UI_HINT_COLOR)
            if self._paused:
                self._draw_ui_text("paused (TAB)", x, y + line * 2.0, UI_HINT_COLOR)
            if self._player.health <= 0.0:
                self._draw_ui_text("game over", x, y + line * 2.0, UI_ERROR_COLOR)

        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)

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
