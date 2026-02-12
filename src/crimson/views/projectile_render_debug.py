from __future__ import annotations

from dataclasses import dataclass
import math
import random

import pyray as rl

from grim.audio import AudioState, shutdown_audio
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.view import View, ViewContext

from ..creatures.spawn import CreatureFlags
from ..game_world import GameWorld
from ..gameplay import player_update
from ..sim.input import PlayerInput
from ..weapon_runtime import weapon_assign_player
from ..sim.world_defs import BEAM_TYPES
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
    pos: Vec2
    hp: float
    size: float = 56.0
    hitbox_size: float = 56.0
    active: bool = True
    flags: CreatureFlags = CreatureFlags(0)
    plague_infected: bool = False


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
        center = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)
        ring = 260.0
        for idx in range(10):
            angle = float(idx) / 10.0 * math.tau
            target_pos = (center + Vec2.from_angle(angle) * ring).clamp_rect(
                40.0, 40.0, WORLD_SIZE - 40.0, WORLD_SIZE - 40.0
            )
            self._targets.append(TargetDummy(pos=target_pos, hp=260.0, size=64.0, hitbox_size=64.0))

    def _reset_scene(self) -> None:
        self._world.reset(seed=0xBEEF, player_count=1, spawn_pos=Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5))
        self._player = self._world.players[0] if self._world.players else None
        self._weapon_index = 0
        self._apply_weapon()
        self._reset_targets()
        self._world.update_camera(0.0)

    def _world_scale(self) -> float:
        _camera, view_scale = self._world.renderer._world_params()
        return view_scale.avg_component()

    def _draw_grid(self) -> None:
        step = 64.0
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_size = self._world.renderer._camera_screen_size()
        camera, view_scale = self._world.renderer._world_params()

        start_x = math.floor((-camera.x) / step) * step
        end_x = (-camera.x) + screen_size.x
        x = start_x
        while x <= end_x:
            line_start = Vec2(self._world.world_to_screen(Vec2(x, 0.0)).x, 0.0)
            line_end = Vec2(line_start.x, out_h)
            rl.draw_line(int(line_start.x), int(line_start.y), int(line_end.x), int(line_end.y), GRID_COLOR)
            x += step

        start_y = math.floor((-camera.y) / step) * step
        end_y = (-camera.y) + screen_size.y
        y = start_y
        while y <= end_y:
            line_start = Vec2(0.0, self._world.world_to_screen(Vec2(0.0, y)).y)
            line_end = Vec2(out_w, line_start.y)
            rl.draw_line(int(line_start.x), int(line_start.y), int(line_end.x), int(line_end.y), GRID_COLOR)
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
        aim = self._world.screen_to_world(Vec2.from_xy(mouse))

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
            prev_audio = (
                int(self._player.shot_seq),
                bool(self._player.reload_active),
                float(self._player.reload_timer),
            )

        detail_preset = 5
        if self._world.config is not None:
            detail_preset = int(self._world.config.detail_preset)

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
            self._world.audio_router.play_hit_sfx(
                hits,
                game_mode=1,
                rand=self._world.state.rng.rand,
                beam_types=BEAM_TYPES,
            )
        self._targets = [target for target in self._targets if target.hp > 0.0]

        input_state = self._build_input()
        player_update(
            self._player,
            input_state,
            float(dt),
            self._world.state,
            world_size=WORLD_SIZE,
            creatures=self._targets,
        )

        if prev_audio is not None:
            prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio
            self._world.audio_router.handle_player_audio(
                self._player,
                prev_shot_seq=prev_shot_seq,
                prev_reload_active=prev_reload_active,
                prev_reload_timer=prev_reload_timer,
            )

        self._world._bake_fx_queues()
        self._world.update_camera(float(dt))

    def draw(self) -> None:
        rl.clear_background(BG)

        renderer = self._world.renderer
        camera, view_scale = renderer._world_params()
        screen_size = renderer._camera_screen_size()

        if self._world.ground is not None:
            self._world.ground.draw(camera, screen_w=screen_size.x, screen_h=screen_size.y)

        warn_x = 24.0
        warn_y = 24.0
        warn_line = float(ui_line_height(self._small))
        if self._missing_assets:
            draw_ui_text(
                self._small,
                "Missing assets (ui): " + ", ".join(self._missing_assets),
                Vec2(warn_x, warn_y),
                color=UI_ERROR,
            )
            warn_y += warn_line
        if self._world.missing_assets:
            draw_ui_text(
                self._small,
                "Missing assets (world): " + ", ".join(self._world.missing_assets),
                Vec2(warn_x, warn_y),
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
            renderer._draw_projectile(proj, proj_index=proj_index, scale=scale)
        for proj in self._world.state.secondary_projectiles.iter_active():
            renderer._draw_secondary_projectile(proj, scale=scale)

        # Player.
        player = self._player
        if player is not None:
            texture = self._world.creature_textures.get("trooper")
            if texture is not None:
                renderer._draw_player_trooper_sprite(
                    texture,
                    player,
                    camera=camera,
                    view_scale=view_scale,
                    scale=scale,
                )
            else:
                player_screen = self._world.world_to_screen(player.pos)
                rl.draw_circle(
                    int(player_screen.x), int(player_screen.y), max(1.0, 14.0 * scale), rl.Color(90, 190, 120, 255)
                )

        if player is not None and player.health > 0.0:
            aim = player.aim
            dist = (aim - player.pos).length()
            radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
            screen_radius = max(1.0, radius * scale)
            aim_screen = self._world.world_to_screen(aim)
            renderer._draw_aim_circle(center=aim_screen, radius=screen_radius)

        # UI.
        x = 16.0
        y = 12.0
        line = float(ui_line_height(self._small))

        weapon_id = int(player.weapon_id) if player is not None else 0
        weapon_name = next((w.name for w in WEAPON_TABLE if w.weapon_id == weapon_id), None) or f"weapon_{weapon_id}"
        draw_ui_text(self._small, "Projectile render debug", Vec2(x, y), color=UI_TEXT)
        y += line
        draw_ui_text(self._small, f"{weapon_name} (weapon_id={weapon_id})", Vec2(x, y), color=UI_TEXT)
        y += line
        if player is not None:
            draw_ui_text(
                self._small,
                f"ammo {player.ammo}/{player.clip_size}  reload {player.reload_timer:.2f}/{player.reload_timer_max:.2f}",
                Vec2(x, y),
                color=UI_TEXT,
            )
            y += line
        y += 6.0
        draw_ui_text(
            self._small,
            "WASD move  LMB fire  R reload  [/] cycle weapons  Space pause  P screenshot",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(self._small, "T reset targets  Backspace reset scene  Esc quit", Vec2(x, y), color=UI_HINT)

        mouse = rl.get_mouse_position()
        draw_aim_cursor(self._world.particles_texture, self._aim_texture, pos=Vec2.from_xy(mouse))


@register_view("projectile-render-debug", "Projectile render debug")
def build_projectile_render_debug_view(ctx: ViewContext) -> View:
    return ProjectileRenderDebugView(ctx)
