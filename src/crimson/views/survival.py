from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import ViewContext

from ..creatures.runtime import CreaturePool
from ..creatures.spawn import SpawnEnv, advance_survival_spawn_stage, tick_survival_wave_spawns
from ..gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_hud_update,
    player_update,
    survival_progression_update,
    weapon_assign_player,
)
from ..ui.hud import HudAssets, draw_hud_overlay, load_hud_assets
from .registry import register_view

WORLD_SIZE = 1024.0
GAME_MODE_SURVIVAL = 3

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


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


@dataclass(slots=True)
class _SurvivalState:
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown: float = 0.0


class SurvivalView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self.close_requested = False
        self._paused = False

        self._spawn_env = SpawnEnv(
            terrain_width=WORLD_SIZE,
            terrain_height=WORLD_SIZE,
            demo_mode_active=False,
            hardcore=False,
            difficulty_level=0,
        )

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos_x=WORLD_SIZE * 0.5, pos_y=WORLD_SIZE * 0.5)
        self._creatures = CreaturePool(env=self._spawn_env)
        self._survival = _SurvivalState()

        self._hud_assets: HudAssets | None = None
        self._hud_missing: list[str] = []

        self._camera_x = -1.0
        self._camera_y = -1.0

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _draw_ui_text(
        self,
        text: str,
        x: float,
        y: float,
        color: rl.Color,
        scale: float = UI_TEXT_SCALE,
    ) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _camera_world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        return self._camera_x + x, self._camera_y + y

    def _camera_screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        return x - self._camera_x, y - self._camera_y

    def _update_camera(self, dt: float) -> None:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        focus_x = self._player.pos_x
        focus_y = self._player.pos_y
        desired_x = (screen_w * 0.5) - focus_x
        desired_y = (screen_h * 0.5) - focus_y

        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        desired_x = _clamp(desired_x, min_x, -1.0)
        desired_y = _clamp(desired_y, min_y, -1.0)

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self._camera_x = _lerp(self._camera_x, desired_x, t)
        self._camera_y = _lerp(self._camera_y, desired_y, t)

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

        self._paused = False
        self.close_requested = False

        self._state = GameplayState()
        self._state.rng.srand(0xBEEF)

        self._player = PlayerState(index=0, pos_x=WORLD_SIZE * 0.5, pos_y=WORLD_SIZE * 0.5)
        weapon_assign_player(self._player, 0)  # pistol

        self._creatures = CreaturePool(env=self._spawn_env)
        self._survival = _SurvivalState()

        self._camera_x = -1.0
        self._camera_y = -1.0

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._hud_assets is not None:
            self._hud_assets.unload()
            self._hud_assets = None

    def _decay_global_timers(self, dt: float) -> None:
        bonuses = self._state.bonuses
        bonuses.weapon_power_up = max(0.0, bonuses.weapon_power_up - dt)
        bonuses.reflex_boost = max(0.0, bonuses.reflex_boost - dt)
        bonuses.energizer = max(0.0, bonuses.energizer - dt)
        bonuses.double_experience = max(0.0, bonuses.double_experience - dt)
        bonuses.freeze = max(0.0, bonuses.freeze - dt)

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if self._player.health <= 0.0 and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self.open()

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
        aim_x, aim_y = self._camera_screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        fire_pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        reload_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_R)

        return PlayerInput(
            move_x=move_x,
            move_y=move_y,
            aim_x=aim_x,
            aim_y=aim_y,
            fire_down=fire_down,
            fire_pressed=fire_pressed,
            reload_pressed=reload_pressed,
        )

    def update(self, dt: float) -> None:
        self._handle_input()

        if self._paused or self._player.health <= 0.0:
            dt = 0.0

        self._survival.elapsed_ms += dt * 1000.0

        # Existing projectiles update first; new spawns (from player_update) take effect next tick.
        self._state.projectiles.update(
            dt,
            self._creatures.entries,
            world_size=WORLD_SIZE,
            rng=self._state.rng.rand,
        )
        self._state.secondary_projectiles.update_pulse_gun(dt, self._creatures.entries)

        self._decay_global_timers(dt)

        input_state = self._build_input()
        player_update(self._player, input_state, dt, self._state, world_size=WORLD_SIZE)

        self._creatures.update(
            dt,
            state=self._state,
            players=[self._player],
            world_width=WORLD_SIZE,
            world_height=WORLD_SIZE,
        )

        self._state.bonus_pool.update(dt, state=self._state, players=[self._player])
        survival_progression_update(self._state, [self._player], game_mode=GAME_MODE_SURVIVAL, auto_pick=True)

        # Scripted milestone spawns based on level.
        stage, milestone_calls = advance_survival_spawn_stage(self._survival.stage, player_level=self._player.level)
        self._survival.stage = stage
        for call in milestone_calls:
            self._creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                self._state.rng,
                rand=self._state.rng.rand,
                env=self._spawn_env,
            )

        # Regular wave spawns based on elapsed time.
        cooldown, wave_spawns = tick_survival_wave_spawns(
            self._survival.spawn_cooldown,
            dt * 1000.0,
            self._state.rng,
            player_count=1,
            survival_elapsed_ms=self._survival.elapsed_ms,
            player_experience=self._player.experience,
            terrain_width=int(WORLD_SIZE),
            terrain_height=int(WORLD_SIZE),
        )
        self._survival.spawn_cooldown = cooldown
        self._creatures.spawn_inits(wave_spawns)

        bonus_hud_update(self._state, [self._player])
        self._update_camera(dt)

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))

        # World bounds.
        x0, y0 = self._camera_world_to_screen(0.0, 0.0)
        x1, y1 = self._camera_world_to_screen(WORLD_SIZE, WORLD_SIZE)
        rl.draw_rectangle_lines(int(x0), int(y0), int(x1 - x0), int(y1 - y0), rl.Color(40, 40, 55, 255))

        # Creatures (debug shapes).
        for creature in self._creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            sx, sy = self._camera_world_to_screen(creature.x, creature.y)
            color = rl.Color(220, 90, 90, 255)
            if creature.type_id == 0:
                color = rl.Color(140, 220, 140, 255)  # zombie
            elif creature.type_id == 1:
                color = rl.Color(120, 200, 240, 255)  # lizard
            elif creature.type_id == 2:
                color = rl.Color(220, 160, 80, 255)  # alien
            elif creature.type_id in (3, 4):
                color = rl.Color(220, 90, 200, 255)  # spiders
            rl.draw_circle(int(sx), int(sy), float(creature.size * 0.5), color)

        # Bonuses.
        for bonus in self._state.bonus_pool.entries:
            if bonus.bonus_id == 0:
                continue
            sx, sy = self._camera_world_to_screen(bonus.pos_x, bonus.pos_y)
            rl.draw_circle(int(sx), int(sy), 10.0, rl.Color(220, 220, 90, 255))

        # Projectiles.
        for proj in self._state.projectiles.iter_active():
            sx, sy = self._camera_world_to_screen(proj.pos_x, proj.pos_y)
            rl.draw_circle(int(sx), int(sy), 2.0, rl.Color(240, 220, 160, 255))

        for proj in self._state.secondary_projectiles.iter_active():
            sx, sy = self._camera_world_to_screen(proj.pos_x, proj.pos_y)
            color = rl.Color(120, 200, 240, 255) if proj.type_id != 3 else rl.Color(200, 240, 160, 255)
            rl.draw_circle(int(sx), int(sy), 3.0, color)

        # Player.
        px, py = self._camera_world_to_screen(self._player.pos_x, self._player.pos_y)
        rl.draw_circle(int(px), int(py), 14.0, rl.Color(90, 190, 120, 255))
        rl.draw_circle_lines(int(px), int(py), 14.0, rl.Color(40, 80, 50, 255))

        aim_len = 42.0
        ax = px + self._player.aim_dir_x * aim_len
        ay = py + self._player.aim_dir_y * aim_len
        rl.draw_line(int(px), int(py), int(ax), int(ay), rl.Color(240, 240, 240, 255))

        hud_bottom = 0.0
        if self._hud_assets is not None:
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=self._survival.elapsed_ms,
                score=self._player.experience,
                font=self._small,
            )

        # Minimal debug text.
        x = 18.0
        y = max(18.0, hud_bottom + 10.0)
        line = float(self._ui_line_height())
        self._draw_ui_text(f"survival: t={self._survival.elapsed_ms/1000.0:6.1f}s  stage={self._survival.stage}", x, y, UI_TEXT_COLOR)
        self._draw_ui_text(f"xp={self._player.experience}  level={self._player.level}  kills={self._creatures.kill_count}", x, y + line, UI_HINT_COLOR)
        if self._paused:
            self._draw_ui_text("paused (TAB)", x, y + line * 2.0, UI_HINT_COLOR)
        if self._player.health <= 0.0:
            self._draw_ui_text("game over (ENTER to restart)", x, y + line * 2.0, UI_ERROR_COLOR)
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, float(rl.get_screen_height()) - 28.0, UI_ERROR_COLOR, scale=0.8)


@register_view("survival", "Survival (debug)")
def _create_survival_view(*, ctx: ViewContext) -> SurvivalView:
    return SurvivalView(ctx)

