from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random
from typing import Protocol

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState, update_audio
from grim.config import CrimsonConfig
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.view import ViewContext

from ..creatures.spawn import tick_rush_mode_spawns
from ..game_modes import GameMode
from ..game_world import GameWorld
from ..gameplay import PlayerInput, weapon_assign_player
from ..persistence.highscores import HighScoreRecord
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.game_over import GameOverUi
from ..ui.hud import HudAssets, draw_hud_overlay, load_hud_assets
from ..ui.perk_menu import load_perk_menu_assets

WORLD_SIZE = 1024.0
RUSH_WEAPON_ID = 2

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


@dataclass(slots=True)
class _RushState:
    elapsed_ms: float = 0.0
    spawn_cooldown_ms: float = 0.0


class _ScreenFade(Protocol):
    screen_fade_alpha: float


class RushMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
    ) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._hud_missing: list[str] = []
        self._small: SmallFontData | None = None
        self._config = config
        self._base_dir = config.path.parent if config is not None else Path.cwd()

        self.close_requested = False
        self._paused = False

        self._world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=WORLD_SIZE,
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._state = self._world.state
        self._creatures = self._world.creatures
        self._player = self._world.players[0]
        self._rush = _RushState()

        self._hud_assets: HudAssets | None = None
        self._ui_assets = None

        self._game_over_active = False
        self._game_over_record: HighScoreRecord | None = None
        self._game_over_ui = GameOverUi(
            assets_root=self._assets_root,
            base_dir=self._base_dir,
            config=config or CrimsonConfig(path=self._base_dir / "crimson.cfg", data={"game_mode": int(GameMode.RUSH)}),
        )
        self._game_over_banner = "reaper"

        self._ui_mouse_x = 0.0
        self._ui_mouse_y = 0.0
        self._cursor_pulse_time = 0.0
        self._screen_fade: _ScreenFade | None = None

    def _enforce_rush_loadout(self) -> None:
        if int(self._player.weapon_id) != RUSH_WEAPON_ID:
            weapon_assign_player(self._player, RUSH_WEAPON_ID)
        # `rush_mode_update` forces weapon+ammo every frame; keep ammo topped up.
        self._player.ammo = max(0, int(self._player.clip_size))

    def bind_screen_fade(self, fade: _ScreenFade | None) -> None:
        self._screen_fade = fade

    def bind_audio(self, audio: AudioState | None, audio_rng: random.Random | None) -> None:
        self._world.audio = audio
        self._world.audio_rng = audio_rng

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _ui_text_width(self, text: str, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(measure_small_text_width(self._small, text, scale))
        return int(rl.measure_text(text, int(20 * scale)))

    def _draw_ui_text(self, text: str, x: float, y: float, color: rl.Color, scale: float = UI_TEXT_SCALE) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _ui_mouse_pos(self) -> rl.Vector2:
        return rl.Vector2(float(self._ui_mouse_x), float(self._ui_mouse_y))

    def _update_ui_mouse(self) -> None:
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        self._ui_mouse_x = _clamp(float(mouse.x), 0.0, max(0.0, screen_w - 1.0))
        self._ui_mouse_y = _clamp(float(mouse.y), 0.0, max(0.0, screen_h - 1.0))

    def open(self) -> None:
        self._missing_assets.clear()
        self._hud_missing.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        self._hud_assets = load_hud_assets(self._assets_root)
        if self._hud_assets.missing:
            self._hud_missing = list(self._hud_assets.missing)

        self._ui_assets = load_perk_menu_assets(self._assets_root)
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)

        self._game_over_active = False
        self._game_over_record = None
        self._game_over_banner = "reaper"
        self._game_over_ui.close()

        self._paused = False
        self.close_requested = False

        rl.hide_cursor()
        self._world.reset(seed=0xBEEF, player_count=1)
        self._world.open()
        self._state = self._world.state
        self._creatures = self._world.creatures
        self._player = self._world.players[0]
        self._rush = _RushState()
        self._enforce_rush_loadout()
        self._ui_mouse_x = float(rl.get_screen_width()) * 0.5
        self._ui_mouse_y = float(rl.get_screen_height()) * 0.5
        self._cursor_pulse_time = 0.0

    def close(self) -> None:
        rl.show_cursor()
        self._game_over_ui.close()
        if self._ui_assets is not None:
            self._ui_assets = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._hud_assets is not None:
            self._hud_assets = None
        self._world.close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

    def _build_input(self) -> PlayerInput:
        move_x = 0.0
        move_y = 0.0
        if rl.is_key_down(rl.KeyboardKey.KEY_A):
            move_x -= 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_D):
            move_x += 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_W):
            move_y -= 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_S):
            move_y += 1.0

        mouse = self._ui_mouse_pos()
        aim_x, aim_y = self._world.screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        fire_pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

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

        record = HighScoreRecord.blank()
        record.score_xp = int(self._player.experience)
        record.survival_elapsed_ms = int(self._rush.elapsed_ms)
        record.creature_kill_count = int(self._creatures.kill_count)
        record.most_used_weapon_id = int(self._player.weapon_id)
        record.shots_fired = 0
        record.shots_hit = 0
        record.game_mode_id = int(self._config.data.get("game_mode", int(GameMode.RUSH))) if self._config is not None else int(GameMode.RUSH)

        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True

    def update(self, dt: float) -> None:
        if self._world.audio is not None:
            update_audio(self._world.audio, dt)

        dt_frame = float(dt)
        dt_ui_ms = float(min(dt_frame, 0.1) * 1000.0)
        self._update_ui_mouse()
        self._cursor_pulse_time += dt_frame * 1.1
        self._handle_input()

        if self._game_over_active:
            record = self._game_over_record
            if record is None:
                self._enter_game_over()
                record = self._game_over_record
            if record is not None:
                action = self._game_over_ui.update(
                    dt,
                    record=record,
                    player_name_default=self._player_name_default(),
                    mouse=self._ui_mouse_pos(),
                )
                if action == "play_again":
                    self.open()
                    return
                if action in {"main_menu", "high_scores"}:
                    self.close_requested = True
            return

        dt_world = 0.0 if self._paused or self._player.health <= 0.0 else dt_frame

        self._rush.elapsed_ms += dt_world * 1000.0
        if dt_world <= 0.0:
            if self._player.health <= 0.0:
                self._enter_game_over()
            return

        self._enforce_rush_loadout()
        input_state = self._build_input()
        self._world.update(
            dt_world,
            inputs=[input_state],
            auto_pick_perks=False,
            game_mode=int(GameMode.RUSH),
            perk_progression_enabled=False,
        )

        cooldown, spawns = tick_rush_mode_spawns(
            self._rush.spawn_cooldown_ms,
            dt_world * 1000.0,
            self._state.rng,
            player_count=1,
            survival_elapsed_ms=int(self._rush.elapsed_ms),
            terrain_width=float(self._world.world_size),
            terrain_height=float(self._world.world_size),
        )
        self._rush.spawn_cooldown_ms = cooldown
        self._creatures.spawn_inits(spawns)

        if self._player.health <= 0.0:
            self._enter_game_over()

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

        fade_alpha = 0.0
        if self._screen_fade is not None:
            fade_alpha = float(self._screen_fade.screen_fade_alpha)
        if fade_alpha > 0.0:
            alpha = int(255 * max(0.0, min(1.0, fade_alpha)))
            rl.draw_rectangle(0, 0, int(rl.get_screen_width()), int(rl.get_screen_height()), rl.Color(0, 0, 0, alpha))

        hud_bottom = 0.0
        if (not self._game_over_active) and self._hud_assets is not None:
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=self._rush.elapsed_ms,
                font=self._small,
                show_xp=False,
                show_time=True,
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
