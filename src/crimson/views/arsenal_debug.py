from __future__ import annotations

import math
import random

import pyray as rl

from grim.audio import AudioState, shutdown_audio, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext

from ..creatures.spawn import SpawnId
from ..game_modes import GameMode
from ..game_world import GameWorld
from ..gameplay import PlayerInput, weapon_assign_player
from ..projectiles import ProjectileTypeId
from ..ui.cursor import draw_aim_cursor
from ..weapon_sfx import resolve_weapon_sfx_ref
from ..weapons import (
    WEAPON_BY_ID,
    WEAPON_TABLE,
    Weapon,
    projectile_type_id_from_weapon_id,
)
from .audio_bootstrap import init_view_audio
from .registry import register_view


WORLD_SIZE = 1024.0

BG = rl.Color(10, 10, 12, 255)

UI_TEXT = rl.Color(235, 235, 235, 255)
UI_HINT = rl.Color(180, 180, 180, 255)
UI_ERROR = rl.Color(240, 80, 80, 255)

ARSENAL_PLAYER_MOVE_SPEED_MULTIPLIER = 6.0
ARSENAL_PLAYER_INVULNERABLE_SHIELD_TIMER = 1e-3

DEFAULT_SPAWN_IDS = (
    SpawnId.ZOMBIE_CONST_GREY_42,
    SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43,
    SpawnId.LIZARD_CONST_GREY_2F,
    SpawnId.LIZARD_CONST_YELLOW_BOSS_30,
    SpawnId.ALIEN_CONST_GREEN_24,
    SpawnId.ALIEN_CONST_GREY_BRUTE_29,
    SpawnId.ALIEN_CONST_RED_FAST_2B,
    SpawnId.SPIDER_SP1_CONST_BLUE_40,
    SpawnId.SPIDER_SP1_CONST_WHITE_FAST_3E,
    SpawnId.SPIDER_SP2_RANDOM_35,
)

SPECIAL_PROJECTILES: dict[int, str] = {
    9: "particle style 0 (plasma rifle)",
    13: "secondary type 1 (seeker rockets)",
    14: "secondary type 2 (plasma shotgun)",
    16: "particle style 1 (hr flamer)",
    17: "particle style 2 (mini-rocket swarmers)",
    18: "secondary type 2 (rocket minigun)",
    19: "secondary type 4 (pulse gun)",
    43: "particle style 8 (rainbow gun)",
}


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _fmt_float(value: float | None, *, digits: int = 3) -> str:
    if value is None:
        return "—"
    return f"{float(value):.{digits}f}"


def _fmt_int(value: int | None) -> str:
    if value is None:
        return "—"
    return f"{int(value)}"


def _fmt_hex(value: int | None) -> str:
    if value is None:
        return "—"
    value = int(value)
    return f"0x{value:02x} ({value})"


def _projectile_type_label(type_id: int) -> str:
    try:
        name = ProjectileTypeId(int(type_id)).name.lower().replace("_", " ")
    except ValueError:
        name = "unknown"
    return f"{name} (id {type_id})"


class ArsenalDebugView:
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

        self._weapon_ids = sorted({int(entry.weapon_id) for entry in WEAPON_TABLE})
        self._weapon_index = 0
        self._spawn_ids = [int(spawn_id) for spawn_id in DEFAULT_SPAWN_IDS]
        self._spawn_ring_radius = 280.0

        self.close_requested = False
        self._paused = False
        self._screenshot_requested = False

    def _apply_debug_player_cheats(self) -> None:
        player = self._player
        if player is None:
            return
        player.speed_multiplier = float(ARSENAL_PLAYER_MOVE_SPEED_MULTIPLIER)
        player.shield_timer = float(ARSENAL_PLAYER_INVULNERABLE_SHIELD_TIMER)

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

    def _reset_scene(self) -> None:
        self._world.reset(seed=0xBEEF, player_count=1, spawn_x=WORLD_SIZE * 0.5, spawn_y=WORLD_SIZE * 0.5)
        self._player = self._world.players[0] if self._world.players else None
        self._apply_weapon()
        self._reset_creatures()
        self._world.update_camera(0.0)

    def _reset_creatures(self) -> None:
        self._world.creatures.reset()
        self._world.state.projectiles.reset()
        self._world.state.secondary_projectiles.reset()
        self._world.state.particles.reset()
        self._world.state.sprite_effects.reset()
        self._world.state.effects.reset()
        self._world.state.bonus_pool.reset()
        self._world.fx_queue.clear()
        self._world.fx_queue_rotated.clear()

        player = self._player
        if player is None:
            return

        count = max(1, len(self._spawn_ids))
        base_x = float(player.pos_x)
        base_y = float(player.pos_y)
        for idx in range(count):
            spawn_id = int(self._spawn_ids[idx % len(self._spawn_ids)])
            angle = float(idx) / float(count) * math.tau
            x = _clamp(base_x + math.cos(angle) * self._spawn_ring_radius, 48.0, WORLD_SIZE - 48.0)
            y = _clamp(base_y + math.sin(angle) * self._spawn_ring_radius, 48.0, WORLD_SIZE - 48.0)
            heading = angle + math.pi
            self._world.creatures.spawn_template(
                spawn_id,
                (x, y),
                heading,
                self._world.state.rng,
                rand=self._world.state.rng.rand,
            )

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
            self._reset_creatures()

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

    def _weapon_projectile_desc(self, weapon_id: int) -> str:
        special = SPECIAL_PROJECTILES.get(int(weapon_id))
        if special is not None:
            return special
        type_id = projectile_type_id_from_weapon_id(int(weapon_id))
        if type_id is None:
            return "particle/secondary"
        return _projectile_type_label(type_id)

    def _weapon_debug_lines(self, weapon: Weapon | None) -> list[str]:
        player = self._player
        if player is None:
            return ["Arsenal debug: missing player"]

        weapon_id = int(player.weapon_id)
        name = weapon.name if weapon is not None and weapon.name else f"weapon_{weapon_id}"
        index_label = f"{self._weapon_index + 1}/{max(1, len(self._weapon_ids))}"

        lines = [
            "Arsenal",
            f"{name} (id {weapon_id})  [{index_label}]",
            f"projectile: {self._weapon_projectile_desc(weapon_id)}",
            f"ammo {player.ammo:.1f}/{player.clip_size:.1f}  reload {player.reload_timer:.2f}/{player.reload_timer_max:.2f}",
            f"shot_cd {player.shot_cooldown:.3f}  spread {player.spread_heat:.3f}  muzzle {player.muzzle_flash_alpha:.2f}",
        ]

        if weapon is None:
            return lines

        fire_sfx = resolve_weapon_sfx_ref(weapon.fire_sound)
        reload_sfx = resolve_weapon_sfx_ref(weapon.reload_sound)
        lines.extend(
            [
                f"clip { _fmt_int(weapon.clip_size) }  reload { _fmt_float(weapon.reload_time) }  cooldown { _fmt_float(weapon.shot_cooldown) }",
                f"pellets { _fmt_int(weapon.pellet_count) }  spread_inc { _fmt_float(weapon.spread_heat_inc) }  dmg_scale { _fmt_float(weapon.damage_scale) }  meta { _fmt_int(weapon.projectile_meta) }",
                f"ammo_class { _fmt_int(weapon.ammo_class) }  flags { _fmt_hex(weapon.flags) }  icon { _fmt_int(weapon.icon_index) }",
                f"sfx fire {fire_sfx or '—'}  reload {reload_sfx or '—'}",
            ]
        )
        return lines

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

        player = self._player
        if player is None:
            return

        self._apply_debug_player_cheats()
        input_state = self._build_input()
        self._world.update(dt, inputs=[input_state], game_mode=int(GameMode.SURVIVAL))

        if self._audio is not None:
            update_audio(self._audio, dt)

    def draw(self) -> None:
        rl.clear_background(BG)

        if self._world.ground is not None:
            self._world._sync_ground_settings()
            self._world.ground.process_pending()

        self._world.draw(draw_aim_indicators=True)

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

        x = 16.0
        y = 12.0
        line = float(self._ui_line_height())

        weapon = WEAPON_BY_ID.get(int(self._player.weapon_id)) if self._player is not None else None
        for text in self._weapon_debug_lines(weapon):
            self._draw_ui_text(text, x, y, UI_TEXT)
            y += line

        if self._player is not None:
            alive = sum(1 for c in self._world.creatures.entries if c.active and c.hp > 0.0)
            total = sum(1 for c in self._world.creatures.entries if c.active)
            self._draw_ui_text(f"creatures alive {alive}/{total}", x, y, UI_TEXT)
            y += line

        y += 6.0
        self._draw_ui_text(
            "WASD move  LMB fire  R reload  [/] cycle weapons  Space pause  T respawn  Backspace reset  Esc quit",
            x,
            y,
            UI_HINT,
        )
        y += line
        self._draw_ui_text("P screenshot", x, y, UI_HINT)

        mouse = rl.get_mouse_position()
        draw_aim_cursor(self._world.particles_texture, self._aim_texture, x=float(mouse.x), y=float(mouse.y))


@register_view("arsenal", "Arsenal")
def build_arsenal_debug_view(ctx: ViewContext) -> View:
    return ArsenalDebugView(ctx)
