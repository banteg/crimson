from __future__ import annotations

from dataclasses import dataclass
import math
import random
from pathlib import Path

import pyray as rl

from grim.audio import AudioState, init_audio_state, shutdown_audio
from grim.config import ensure_crimson_cfg
from grim.console import ConsoleLog, ConsoleState
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext

from ..game_world import GameWorld
from ..gameplay import PlayerInput, player_update, weapon_assign_player
from ..ui.cursor import draw_aim_cursor
from ..weapons import WEAPON_TABLE
from .registry import register_view


WORLD_SIZE = 1024.0

BG = rl.Color(10, 10, 12, 255)
GRID_COLOR = rl.Color(255, 255, 255, 14)

UI_TEXT = rl.Color(235, 235, 235, 255)
UI_HINT = rl.Color(180, 180, 180, 255)
UI_ERROR = rl.Color(240, 80, 80, 255)

TARGET_FILL = rl.Color(220, 80, 80, 220)
TARGET_OUTLINE = rl.Color(140, 40, 40, 255)


@dataclass(slots=True)
class TargetDummy:
    x: float
    y: float
    hp: float
    size: float = 56.0


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


class ProjectileRenderDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self._world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=WORLD_SIZE,
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
        )
        self._player = self._world.players[0] if self._world.players else None
        self._aim_texture: rl.Texture | None = None
        self._audio: AudioState | None = None
        self._audio_rng: random.Random | None = None
        self._console: ConsoleState | None = None

        self._weapon_ids = [entry.weapon_id for entry in WEAPON_TABLE if entry.name is not None]
        self._weapon_index = 0

        self._targets: list[TargetDummy] = []

        self.close_requested = False
        self._paused = False
        self._screenshot_requested = False

    def _ui_line_height(self, scale: float = 1.0) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _draw_ui_text(self, text: str, x: float, y: float, color: rl.Color, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _selected_weapon_id(self) -> int:
        if not self._weapon_ids:
            return 0
        return int(self._weapon_ids[self._weapon_index % len(self._weapon_ids)])

    def _apply_weapon(self) -> None:
        if self._player is None:
            return
        weapon_assign_player(self._player, self._selected_weapon_id())

    def _reset_targets(self) -> None:
        self._targets.clear()
        base_x = WORLD_SIZE * 0.5
        base_y = WORLD_SIZE * 0.5
        ring = 260.0
        for idx in range(10):
            angle = float(idx) / 10.0 * math.tau
            x = _clamp(base_x + math.cos(angle) * ring, 40.0, WORLD_SIZE - 40.0)
            y = _clamp(base_y + math.sin(angle) * ring, 40.0, WORLD_SIZE - 40.0)
            self._targets.append(TargetDummy(x=x, y=y, hp=260.0, size=64.0))

    def _reset_scene(self) -> None:
        self._world.reset(seed=0xBEEF, player_count=1, spawn_x=WORLD_SIZE * 0.5, spawn_y=WORLD_SIZE * 0.5)
        self._player = self._world.players[0] if self._world.players else None
        self._weapon_index = 0
        self._apply_weapon()
        self._reset_targets()
        self._world.update_camera(0.0)

    def _world_scale(self) -> float:
        _cam_x, _cam_y, scale_x, scale_y = self._world._world_params()
        return (scale_x + scale_y) * 0.5

    def _draw_grid(self) -> None:
        step = 64.0
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w, screen_h = self._world._camera_screen_size()
        cam_x, cam_y, scale_x, scale_y = self._world._world_params()

        start_x = math.floor((-cam_x) / step) * step
        end_x = (-cam_x) + screen_w
        x = start_x
        while x <= end_x:
            sx = int((x + cam_x) * scale_x)
            rl.draw_line(sx, 0, sx, int(out_h), GRID_COLOR)
            x += step

        start_y = math.floor((-cam_y) / step) * step
        end_y = (-cam_y) + screen_h
        y = start_y
        while y <= end_y:
            sy = int((y + cam_y) * scale_y)
            rl.draw_line(0, sy, int(out_w), sy, GRID_COLOR)
            y += step

    def _handle_debug_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._weapon_index = (self._weapon_index - 1) % max(1, len(self._weapon_ids))
            self._apply_weapon()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._weapon_index = (self._weapon_index + 1) % max(1, len(self._weapon_ids))
            self._apply_weapon()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self._reset_targets()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._reset_scene()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True

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

        mouse = rl.get_mouse_position()
        aim_x, aim_y = self._world.screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        fire_pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        reload_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_R)

        return PlayerInput(
            move_x=move_x,
            move_y=move_y,
            aim_x=float(aim_x),
            aim_y=float(aim_y),
            fire_down=fire_down,
            fire_pressed=fire_pressed,
            reload_pressed=reload_pressed,
        )

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        runtime_dir = Path("artifacts") / "runtime"
        if runtime_dir.is_dir():
            try:
                self._world.config = ensure_crimson_cfg(runtime_dir)
            except Exception:
                self._world.config = None
        else:
            self._world.config = None

        if self._world.config is not None:
            try:
                self._console = ConsoleState(base_dir=runtime_dir, log=ConsoleLog(base_dir=runtime_dir), assets_dir=self._assets_root)
                self._audio = init_audio_state(self._world.config, self._assets_root, self._console)
                self._audio_rng = random.Random(0xBEEF)
                self._world.audio = self._audio
                self._world.audio_rng = self._audio_rng
            except Exception:
                self._audio = None
                self._audio_rng = None
                self._console = None
                self._world.audio = None
                self._world.audio_rng = None

        self._world.open()
        self._aim_texture = self._world._load_texture(
            "ui_aim",
            cache_path="ui/ui_aim.jaz",
            file_path="ui/ui_aim.png",
        )
        self._reset_scene()
        rl.hide_cursor()

    def close(self) -> None:
        rl.show_cursor()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None
            self._audio_rng = None
            self._console = None
        self._world.audio = None
        self._world.audio_rng = None
        self._world.close()
        self._aim_texture = None

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def update(self, dt: float) -> None:
        self._handle_debug_input()

        if self._paused:
            dt = 0.0

        if self._world.ground is not None:
            self._world._sync_ground_settings()
            self._world.ground.process_pending()

        if self._player is None:
            return

        prev_audio = None
        if self._world.audio is not None:
            prev_audio = (int(self._player.ammo), bool(self._player.reload_active), float(self._player.reload_timer))

        # Keep the scene stable: targets are static, only projectiles + player advance.
        hits = self._world.state.projectiles.update(
            float(dt),
            self._targets,
            world_size=WORLD_SIZE,
            damage_scale_by_type=self._world._damage_scale_by_type,
            rng=self._world.state.rng.rand,
            runtime_state=self._world.state,
        )
        self._world.state.secondary_projectiles.update_pulse_gun(float(dt), self._targets)
        if hits:
            self._world._queue_projectile_decals(hits)
            self._world._play_hit_sfx(hits, game_mode=1)
        self._targets = [target for target in self._targets if target.hp > 0.0]

        input_state = self._build_input()
        player_update(self._player, input_state, float(dt), self._world.state, world_size=WORLD_SIZE)

        if prev_audio is not None:
            prev_ammo, prev_reload_active, prev_reload_timer = prev_audio
            self._world._handle_player_audio(
                self._player,
                prev_ammo=prev_ammo,
                prev_reload_active=prev_reload_active,
                prev_reload_timer=prev_reload_timer,
            )

        self._world._bake_fx_queues()
        self._world.update_camera(float(dt))

    def draw(self) -> None:
        rl.clear_background(BG)

        cam_x, cam_y, scale_x, scale_y = self._world._world_params()
        screen_w, screen_h = self._world._camera_screen_size()

        if self._world.ground is not None:
            self._world.ground.draw(cam_x, cam_y, screen_w=screen_w, screen_h=screen_h)

        warn_x = 24.0
        warn_y = 24.0
        warn_line = float(self._ui_line_height())
        if self._missing_assets:
            self._draw_ui_text("Missing assets (ui): " + ", ".join(self._missing_assets), warn_x, warn_y, UI_ERROR)
            warn_y += warn_line
        if self._world.missing_assets:
            self._draw_ui_text(
                "Missing assets (world): " + ", ".join(self._world.missing_assets),
                warn_x,
                warn_y,
                UI_ERROR,
            )
            warn_y += warn_line

        scale = self._world_scale()

        self._draw_grid()

        # Targets.
        for target in self._targets:
            sx, sy = self._world.world_to_screen(float(target.x), float(target.y))
            radius = max(2.0, float(target.size) * 0.5 * scale)
            rl.draw_circle(int(sx), int(sy), radius, TARGET_FILL)
            rl.draw_circle_lines(int(sx), int(sy), int(max(1.0, radius)), TARGET_OUTLINE)

        # Projectiles.
        for proj in self._world.state.projectiles.iter_active():
            self._world._draw_projectile(proj, scale=scale)
        for proj in self._world.state.secondary_projectiles.iter_active():
            self._world._draw_secondary_projectile(proj, scale=scale)

        # Player.
        player = self._player
        if player is not None:
            texture = self._world.creature_textures.get("trooper")
            if texture is not None:
                self._world._draw_player_trooper_sprite(
                    texture,
                    player,
                    cam_x=cam_x,
                    cam_y=cam_y,
                    scale_x=scale_x,
                    scale_y=scale_y,
                    scale=scale,
                )
            else:
                px, py = self._world.world_to_screen(float(player.pos_x), float(player.pos_y))
                rl.draw_circle(int(px), int(py), max(1.0, 14.0 * scale), rl.Color(90, 190, 120, 255))

        if player is not None and player.health > 0.0:
            aim_x = float(getattr(player, "aim_x", player.pos_x))
            aim_y = float(getattr(player, "aim_y", player.pos_y))
            dist = math.hypot(aim_x - float(player.pos_x), aim_y - float(player.pos_y))
            radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
            screen_radius = max(1.0, radius * scale)
            aim_screen_x, aim_screen_y = self._world.world_to_screen(aim_x, aim_y)
            self._world._draw_aim_circle(x=aim_screen_x, y=aim_screen_y, radius=screen_radius)

        # UI.
        x = 16.0
        y = 12.0
        line = float(self._ui_line_height())

        weapon_id = int(player.weapon_id) if player is not None else 0
        weapon_name = next((w.name for w in WEAPON_TABLE if w.weapon_id == weapon_id), None) or f"weapon_{weapon_id}"
        self._draw_ui_text("Projectile render debug", x, y, UI_TEXT)
        y += line
        self._draw_ui_text(f"{weapon_name} (weapon_id={weapon_id})", x, y, UI_TEXT)
        y += line
        if player is not None:
            self._draw_ui_text(
                f"ammo {player.ammo}/{player.clip_size}  reload {player.reload_timer:.2f}/{player.reload_timer_max:.2f}",
                x,
                y,
                UI_TEXT,
            )
            y += line
        y += 6.0
        self._draw_ui_text("WASD move  LMB fire  R reload  [/] cycle weapons  Space pause  P screenshot", x, y, UI_HINT)
        y += line
        self._draw_ui_text("T reset targets  Backspace reset scene  Esc quit", x, y, UI_HINT)

        mouse = rl.get_mouse_position()
        draw_aim_cursor(self._world.particles_texture, self._aim_texture, x=float(mouse.x), y=float(mouse.y))


@register_view("projectile-render-debug", "Projectile render debug")
def build_projectile_render_debug_view(ctx: ViewContext) -> View:
    return ProjectileRenderDebugView(ctx)
