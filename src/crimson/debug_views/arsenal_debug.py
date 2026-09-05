from __future__ import annotations

import math

from grim.app import RunViewHooks
from grim.assets import TextureId
from grim.audio import AudioState, shutdown_audio, update_audio
from grim.console import ConsoleState
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

from ..bonuses import BONUS_TABLE, BonusId
from ..creatures.spawn import SpawnId
from ..game_modes import GameMode
from ..projectiles.types import ProjectileTemplateId
from ..sim.input import PlayerInput
from ..sim.input_providers import FrameContext, LocalInputRuntime
from ..tooling.audio_bootstrap import init_view_audio
from ..ui.cursor import draw_aim_cursor
from ..weapon_runtime import weapon_assign_player
from ..weapon_runtime.fire_recipes import (
    MultiPlasmaFanMode,
    ParticleStreamMode,
    PrimaryPelletsMode,
    SecondaryShotMode,
    SwarmerDumpMode,
    resolve_fire_recipe,
)
from ..weapons import (
    WEAPON_BY_ID,
    WEAPON_TABLE,
    WeaponId,
    projectile_type_id_for_weapon_id,
)
from ..world import WorldRuntime
from ..world.standalone_tick_harness import StandaloneTickHarness
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import ViewInstance, register_view

WORLD_SIZE = 1024.0

BG = rl.Color(10, 10, 12, 255)

UI_TEXT = rl.Color(235, 235, 235, 255)
UI_HINT = rl.Color(180, 180, 180, 255)
UI_ERROR = rl.Color(240, 80, 80, 255)

ARSENAL_PLAYER_MOVE_SPEED_MULTIPLIER = 6.0
ARSENAL_PLAYER_INVULNERABLE_SHIELD_TIMER = 1e-3
ARSENAL_BONUS_RING_RADIUS = 140.0

DEFAULT_SPAWN_IDS = (
    SpawnId.ZOMBIE_SMALL_WHITE_42,
    SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43,
    SpawnId.LIZARD_CONST_GREY_2F,
    SpawnId.LIZARD_CONST_YELLOW_BOSS_30,
    SpawnId.ALIEN_CONST_GREEN_24,
    SpawnId.ALIEN_BIG_GRAY_29,
    SpawnId.ALIEN_DEADLY_FAST_2B,
    SpawnId.SPIDER_SMALL_BLUE_40,
    SpawnId.SPIDER_SP1_CONST_WHITE_FAST_3E,
    SpawnId.SPIDER_SP2_RANDOM_35,
)


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
        name = ProjectileTemplateId(type_id).name.lower().replace("_", " ")
    except ValueError:
        name = "unknown"
    return f"{name} (id {type_id})"


class _ArsenalLocalInputRuntime(LocalInputRuntime):
    view: ArsenalDebugView

    def capture_frame_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        return self.view._build_runner_inputs(frame_ctx)


class ArsenalDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._audio_rng = Crand(0xBEEF)

        self._runtime = WorldRuntime(
            assets_dir=ctx.assets_dir,
            world_size=float(WORLD_SIZE),
            preserve_bugs=bool(ctx.preserve_bugs),
            audio_rng=self._audio_rng,
        )
        self._runtime.reset(player_count=1)

        self._player = self._runtime.sim_world.players[0] if self._runtime.sim_world.players else None
        self._aim_texture: rl.Texture | None = None
        self._audio: AudioState | None = None
        self._console: ConsoleState | None = None

        self._weapon_ids = sorted({int(entry.weapon_id) for entry in WEAPON_TABLE})
        self._weapon_index = 0
        self._spawn_ids = list(DEFAULT_SPAWN_IDS)
        self._spawn_ring_radius = 280.0

        self.close_requested = False
        self._paused = False
        self._screenshot_requested = False
        self._tick_harness = StandaloneTickHarness(
            game_mode=GameMode.SURVIVAL,
            input_runtime=_ArsenalLocalInputRuntime(view=self),
        )

    def _load_texture(self, texture_id: TextureId) -> rl.Texture:
        return self._runtime.render_resources.resources.texture(texture_id)

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._runtime.draw(draw_aim_indicators=draw_aim_indicators, entity_alpha=entity_alpha)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._runtime.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._runtime.screen_to_world(pos)

    def _apply_debug_player_cheats(self) -> None:
        player = self._player
        if player is None:
            return
        player.speed_multiplier = float(ARSENAL_PLAYER_MOVE_SPEED_MULTIPLIER)
        player.shield_timer = float(ARSENAL_PLAYER_INVULNERABLE_SHIELD_TIMER)

    def _selected_weapon_id(self) -> WeaponId:
        if not self._weapon_ids:
            return WeaponId.NONE
        return WeaponId(self._weapon_ids[self._weapon_index % len(self._weapon_ids)])

    def _apply_weapon(self) -> None:
        if self._player is None:
            return
        weapon_assign_player(self._player, self._selected_weapon_id(), state=self._runtime.sim_world.state)

    def _reset_scene(self) -> None:
        self._runtime.reset(seed=0xBEEF, player_count=1, spawn_pos=Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5))
        self._reset_tick_runner()
        self._player = self._runtime.sim_world.players[0] if self._runtime.sim_world.players else None
        self._apply_weapon()
        self._reset_creatures()
        self._runtime.update_camera()

    def _reset_creatures(self) -> None:
        self._runtime.sim_world.creatures.reset()
        self._runtime.sim_world.state.projectiles.reset()
        self._runtime.sim_world.state.secondary_projectiles.reset()
        self._runtime.sim_world.state.particles.reset()
        self._runtime.sim_world.state.sprite_effects.reset()
        self._runtime.sim_world.state.effects.reset()
        self._runtime.sim_world.state.bonus_pool.reset()
        self._runtime.render_resources.clear_pending_terrain_fx()

        player = self._player
        if player is None:
            return

        count = max(1, len(self._spawn_ids))
        player_pos = player.pos
        for idx in range(count):
            spawn_id = self._spawn_ids[idx % len(self._spawn_ids)]
            angle = float(idx) / float(count) * math.tau
            spawn_pos = (player_pos + Vec2.from_angle(angle) * self._spawn_ring_radius).clamp_rect(
                48.0,
                48.0,
                WORLD_SIZE - 48.0,
                WORLD_SIZE - 48.0,
            )
            heading = angle + math.pi
            self._runtime.sim_world.creatures.spawn_template(
                spawn_id,
                spawn_pos,
                heading,
                self._runtime.sim_world.state.rng,
            )

    def _spawn_all_bonuses(self) -> None:
        player = self._player
        if player is None:
            return

        bonus_pool = self._runtime.sim_world.state.bonus_pool
        bonus_pool.reset()

        bonus_ids = [entry.bonus_id for entry in BONUS_TABLE if entry.bonus_id != BonusId.UNUSED]
        count = max(1, len(bonus_ids))

        player_pos = player.pos
        rng = self._runtime.sim_world.state.rng.rand
        current_weapon_id = player.weapon.weapon_id

        for idx, bonus_id in enumerate(bonus_ids):
            angle = float(idx) / float(count) * math.tau
            pos = player_pos + Vec2.from_angle(angle) * float(ARSENAL_BONUS_RING_RADIUS)

            amount_override = -1
            if bonus_id == BonusId.WEAPON and self._weapon_ids:
                weapon_id = int(current_weapon_id)
                for _ in range(8):
                    weapon_id = int(self._weapon_ids[int(rng()) % len(self._weapon_ids)])
                    if weapon_id != current_weapon_id:
                        break
                amount_override = int(weapon_id)

            bonus_pool.spawn_at(
                pos=pos,
                bonus_id=bonus_id,
                duration_override=int(amount_override),
                state=self._runtime.sim_world.state,
                world_width=float(WORLD_SIZE),
                world_height=float(WORLD_SIZE),
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

        if rl.is_key_pressed(rl.KeyboardKey.KEY_B):
            self._spawn_all_bonuses()

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
        aim = self.screen_to_world(Vec2.from_xy(mouse))

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

    def _build_runner_inputs(self, frame_ctx: FrameContext) -> list[PlayerInput]:
        _ = frame_ctx
        return [self._build_input()]

    def _reset_tick_runner(self) -> None:
        self._tick_harness.reset()

    def _weapon_projectile_desc(self, weapon_id: WeaponId) -> str:
        weapon = WEAPON_BY_ID[weapon_id]
        recipe = resolve_fire_recipe(
            weapon_id,
            pellet_count=int(weapon.pellet_count),
            fire_bullets_active=False,
        )
        if recipe is None:
            return "unsupported/unmapped"
        match recipe.mode:
            case PrimaryPelletsMode(type_id=type_id):
                if type_id is None:
                    return "unsupported/unmapped"
                return _projectile_type_label(int(type_id))
            case SecondaryShotMode(type_id=type_id):
                return f"secondary type {int(type_id)}"
            case ParticleStreamMode(style=style, slow=slow):
                if style is None:
                    return "slow particle stream" if slow else "particle stream"
                return f"particle style {int(style)}"
            case MultiPlasmaFanMode():
                return "plasma fan"
            case SwarmerDumpMode():
                return "secondary swarm dump"
        try:
            type_id = projectile_type_id_for_weapon_id(weapon_id)
        except ValueError:
            return "unsupported/unmapped"
        return _projectile_type_label(int(type_id))

    def _weapon_debug_lines(self) -> list[str]:
        player = self._player
        if player is None:
            return ["Arsenal debug: missing player"]

        weapon = WEAPON_BY_ID[player.weapon.weapon_id]
        weapon_id = player.weapon.weapon_id
        name = weapon.name
        index_label = f"{self._weapon_index + 1}/{max(1, len(self._weapon_ids))}"

        lines = [
            "Arsenal",
            f"{name} (id {weapon_id})  [{index_label}]",
            f"projectile: {self._weapon_projectile_desc(weapon_id)}",
            f"ammo {player.weapon.ammo:.1f}/{player.weapon.clip_size:.1f}  reload {player.weapon.reload_timer:.2f}/{player.weapon.reload_timer_max:.2f}",
            f"shot_cd {player.weapon.shot_cooldown:.3f}  spread {player.spread_heat:.3f}  muzzle {player.muzzle_flash_alpha:.2f}",
        ]

        lines.extend(
            [
                f"clip {_fmt_int(weapon.clip_size)}  reload {_fmt_float(weapon.reload_time)}  cooldown {_fmt_float(weapon.shot_cooldown)}",
                f"pellets {_fmt_int(weapon.pellet_count)}  spread_inc {_fmt_float(weapon.spread_heat_inc)}  dmg_scale {_fmt_float(weapon.damage_scale)}  meta {_fmt_int(weapon.travel_budget)}",
                f"ammo_class {_fmt_int(weapon.ammo_class)}  flags {_fmt_hex(weapon.flags)}  icon {_fmt_int(weapon.icon_index)}",
                f"sfx fire {weapon.fire_sound}  reload {weapon.reload_sound}",
            ],
        )
        return lines

    def open(self) -> None:
        self._missing_assets.clear()
        bootstrap = init_view_audio(self._assets_root)
        self._runtime.config = bootstrap.config
        self._console = bootstrap.console
        self._audio = bootstrap.audio
        self._audio_rng = bootstrap.audio_rng
        self._runtime.audio = self._audio
        self._runtime.audio_rng = self._audio_rng
        self._runtime.sync_audio_bridge_state()

        self._small = load_small_font(self._assets_root)

        self._runtime.open_runtime()
        self._aim_texture = self._load_texture(TextureId.UI_AIM)
        self._reset_scene()
        rl.hide_cursor()

    def close(self) -> None:
        rl.show_cursor()
        self._reset_tick_runner()
        if self._small is not None:
            self._small = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None
            self._console = None
        self._runtime.audio = None
        self._runtime.audio_rng = self._audio_rng
        self._runtime.sync_audio_bridge_state()
        self._runtime.close_runtime()
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
        self._tick_harness.advance_frame(self._runtime, float(dt))

        if self._audio is not None:
            update_audio(self._audio, dt)

    def draw(self) -> None:
        rl.clear_background(BG)

        if self._runtime.render_resources.ground is not None:
            self._runtime.render_resources.ground.process_pending()

        self._draw_world(draw_aim_indicators=True)

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

        x = 16.0
        y = 12.0
        line = float(ui_line_height(self._small))

        for text in self._weapon_debug_lines():
            draw_ui_text(self._small, text, Vec2(x, y), color=UI_TEXT)
            y += line

        if self._player is not None:
            alive = sum(1 for c in self._runtime.sim_world.creatures.entries if c.active and c.hp > 0.0)
            total = sum(1 for c in self._runtime.sim_world.creatures.entries if c.active)
            draw_ui_text(self._small, f"creatures alive {alive}/{total}", Vec2(x, y), color=UI_TEXT)
            y += line

        y += 6.0
        draw_ui_text(
            self._small,
            "WASD move  LMB fire  R reload  [/] cycle weapons  Space pause  T respawn  B spawn all bonuses  Backspace reset  Esc quit",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(self._small, "P screenshot", Vec2(x, y), color=UI_HINT)

        resources = self._runtime.render_resources.resources
        mouse = rl.get_mouse_position()
        draw_aim_cursor(resources.texture(TextureId.PARTICLES), self._aim_texture, pos=Vec2.from_xy(mouse))


@register_view("arsenal", "Arsenal")
def build_arsenal_debug_view(ctx: ViewContext) -> ViewInstance:
    view = ArsenalDebugView(ctx)
    return ViewInstance(
        view,
        RunViewHooks(
            should_close=lambda: view.close_requested,
            consume_screenshot_request=view.consume_screenshot_request,
        ),
    )
