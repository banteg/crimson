from __future__ import annotations

from dataclasses import dataclass
import math
import random

import pyray as rl

from grim.audio import AudioState, shutdown_audio
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.math import clamp
from grim.view import View, ViewContext

from ..game_world import GameWorld
from ..gameplay import PlayerInput, player_update, weapon_assign_player
from ..ui.cursor import draw_aim_cursor
from ..weapons import WEAPON_TABLE
from ._ui_helpers import draw_ui_text, ui_line_height
from .audio_bootstrap import init_view_audio
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
            preserve_bugs=bool(ctx.preserve_bugs),
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
            x = clamp(base_x + math.cos(angle) * ring, 40.0, WORLD_SIZE - 40.0)
            y = clamp(base_y + math.sin(angle) * ring, 40.0, WORLD_SIZE - 40.0)
            self._targets.append(TargetDummy(x=x, y=y, hp=260.0, size=64.0))

    def _reset_scene(self) -> None:
        self._world.reset(seed=0xBEEF, player_count=1, spawn_pos=Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5))
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
        move = Vec2(
            float(rl.is_key_down(rl.KeyboardKey.KEY_D)) - float(rl.is_key_down(rl.KeyboardKey.KEY_A)),
            float(rl.is_key_down(rl.KeyboardKey.KEY_S)) - float(rl.is_key_down(rl.KeyboardKey.KEY_W)),
        )

        mouse = rl.get_mouse_position()
        aim = self._world.screen_to_world(Vec2(mouse.x, mouse.y))

        fire_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        fire_pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        reload_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_R)

        return PlayerInput(
            move=move,
            aim=aim,
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

        bootstrap = init_view_audio(self._assets_root)
        self._world.config = bootstrap.config
        self._console = bootstrap.console
        self._audio = bootstrap.audio
        self._audio_rng = bootstrap.audio_rng
        self._world.audio = self._audio
        self._world.audio_rng = self._audio_rng

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
            prev_audio = (int(self._player.shot_seq), bool(self._player.reload_active), float(self._player.reload_timer))

        detail_preset = 5
        if self._world.config is not None:
            detail_preset = int(self._world.config.data.get("detail_preset", 5) or 5)

        # Keep the scene stable: targets are static, only projectiles + player advance.
        hits = self._world.state.projectiles.update(
            float(dt),
            self._targets,
            world_size=WORLD_SIZE,
            damage_scale_by_type=self._world._damage_scale_by_type,
            detail_preset=int(detail_preset),
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
            prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio
            self._world._handle_player_audio(
                self._player,
                prev_shot_seq=prev_shot_seq,
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
        warn_line = float(ui_line_height(self._small))
        if self._missing_assets:
            draw_ui_text(self._small, "Missing assets (ui): " + ", ".join(self._missing_assets), warn_x, warn_y, color=UI_ERROR)
            warn_y += warn_line
        if self._world.missing_assets:
            draw_ui_text(
                self._small,
                "Missing assets (world): " + ", ".join(self._world.missing_assets),
                warn_x,
                warn_y,
                color=UI_ERROR,
            )
            warn_y += warn_line

        scale = self._world_scale()

        self._draw_grid()

        # Targets.
        for target in self._targets:
            target_screen = self._world.world_to_screen(target.pos)
            radius = max(2.0, float(target.size) * 0.5 * scale)
            rl.draw_circle(int(target_screen.x), int(target_screen.y), radius, TARGET_FILL)
            rl.draw_circle_lines(int(target_screen.x), int(target_screen.y), int(max(1.0, radius)), TARGET_OUTLINE)

        # Projectiles.
        for proj_index, proj in enumerate(self._world.state.projectiles.entries):
            if not proj.active:
                continue
            self._world._draw_projectile(proj, proj_index=proj_index, scale=scale)
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
                player_screen = self._world.world_to_screen(player.pos)
                rl.draw_circle(int(player_screen.x), int(player_screen.y), max(1.0, 14.0 * scale), rl.Color(90, 190, 120, 255))

        if player is not None and player.health > 0.0:
            aim = player.aim
            dist = (aim - player.pos).length()
            radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
            screen_radius = max(1.0, radius * scale)
            aim_screen = self._world.world_to_screen(aim)
            self._world._draw_aim_circle(x=aim_screen.x, y=aim_screen.y, radius=screen_radius)

        # UI.
        x = 16.0
        y = 12.0
        line = float(ui_line_height(self._small))

        weapon_id = int(player.weapon_id) if player is not None else 0
        weapon_name = next((w.name for w in WEAPON_TABLE if w.weapon_id == weapon_id), None) or f"weapon_{weapon_id}"
        draw_ui_text(self._small, "Projectile render debug", x, y, color=UI_TEXT)
        y += line
        draw_ui_text(self._small, f"{weapon_name} (weapon_id={weapon_id})", x, y, color=UI_TEXT)
        y += line
        if player is not None:
            draw_ui_text(
                self._small,
                f"ammo {player.ammo}/{player.clip_size}  reload {player.reload_timer:.2f}/{player.reload_timer_max:.2f}",
                x,
                y,
                color=UI_TEXT,
            )
            y += line
        y += 6.0
        draw_ui_text(
            self._small,
            "WASD move  LMB fire  R reload  [/] cycle weapons  Space pause  P screenshot",
            x,
            y,
            color=UI_HINT,
        )
        y += line
        draw_ui_text(self._small, "T reset targets  Backspace reset scene  Esc quit", x, y, color=UI_HINT)

        mouse = rl.get_mouse_position()
        draw_aim_cursor(self._world.particles_texture, self._aim_texture, pos=Vec2(mouse.x, mouse.y))


@register_view("projectile-render-debug", "Projectile render debug")
def build_projectile_render_debug_view(ctx: ViewContext) -> View:
    return ProjectileRenderDebugView(ctx)
