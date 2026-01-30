from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from .registry import register_view
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext

from ..bonuses import BonusId
from ..gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_apply,
    bonus_hud_update,
    player_update,
    weapon_assign_player,
)
from ..perks import PerkId
from ..ui.hud import HudAssets, draw_hud_overlay, hud_ui_scale, load_hud_assets
from ..weapons import WEAPON_TABLE, projectile_type_id_from_weapon_id

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(slots=True)
class DummyCreature:
    x: float
    y: float
    hp: float
    size: float = 32.0


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _rand_float01(state: GameplayState) -> float:
    return float(state.rng.rand()) / 32767.0


class PlayerSandboxView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos_x=WORLD_SIZE * 0.5, pos_y=WORLD_SIZE * 0.5)
        self._creatures: list[DummyCreature] = []

        self._hud_assets: HudAssets | None = None
        self._hud_missing: list[str] = []
        self._elapsed_ms = 0.0
        self._last_dt_ms = 0.0

        self._camera_x = -1.0
        self._camera_y = -1.0
        self._paused = False

        self._weapon_ids = [entry.weapon_id for entry in WEAPON_TABLE if entry.name is not None]
        self._weapon_index = 0
        self._damage_scale_by_type = {}
        for entry in WEAPON_TABLE:
            if entry.weapon_id <= 0:
                continue
            type_id = projectile_type_id_from_weapon_id(entry.weapon_id)
            if type_id is None:
                continue
            self._damage_scale_by_type[int(type_id)] = float(entry.damage_scale or 1.0)

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

    def _ensure_creatures(self, target_count: int) -> None:
        while len(self._creatures) < target_count:
            margin = 40.0
            x = margin + _rand_float01(self._state) * (WORLD_SIZE - margin * 2)
            y = margin + _rand_float01(self._state) * (WORLD_SIZE - margin * 2)
            self._creatures.append(DummyCreature(x=x, y=y, hp=80.0, size=28.0))

    def _weapon_id(self) -> int:
        if not self._weapon_ids:
            return 0
        return int(self._weapon_ids[self._weapon_index % len(self._weapon_ids)])

    def _set_weapon(self, weapon_id: int) -> None:
        weapon_assign_player(self._player, weapon_id)

    def _toggle_perk(self, perk_id: PerkId, *, count: int = 1) -> None:
        idx = int(perk_id)
        current = self._player.perk_counts[idx] if 0 <= idx < len(self._player.perk_counts) else 0
        next_value = 0 if current else int(count)
        if 0 <= idx < len(self._player.perk_counts):
            self._player.perk_counts[idx] = next_value
        if perk_id == PerkId.ALTERNATE_WEAPON and next_value:
            if self._player.alt_weapon_id is None:
                alt_idx = (self._weapon_index + 1) % max(1, len(self._weapon_ids))
                alt_id = int(self._weapon_ids[alt_idx])
                weapon = next((w for w in WEAPON_TABLE if w.weapon_id == alt_id), None)
                clip = int(weapon.clip_size) if weapon is not None and weapon.clip_size is not None else 0
                self._player.alt_weapon_id = alt_id
                self._player.alt_clip_size = max(0, clip)
                self._player.alt_ammo = self._player.alt_clip_size
        if perk_id == PerkId.ALTERNATE_WEAPON and not next_value:
            self._player.alt_weapon_id = None

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

        self._state.rng.srand(0xBEEF)
        self._creatures.clear()
        self._ensure_creatures(14)

        self._weapon_index = 0
        self._set_weapon(self._weapon_id())

        self._player.pos_x = WORLD_SIZE * 0.5
        self._player.pos_y = WORLD_SIZE * 0.5
        self._player.health = 100.0
        self._elapsed_ms = 0.0

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._hud_assets is not None:
            self._hud_assets = None

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_Q):
            self._weapon_index = (self._weapon_index - 1) % max(1, len(self._weapon_ids))
            self._set_weapon(self._weapon_id())
        if rl.is_key_pressed(rl.KeyboardKey.KEY_E):
            self._weapon_index = (self._weapon_index + 1) % max(1, len(self._weapon_ids))
            self._set_weapon(self._weapon_id())

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._toggle_perk(PerkId.SHARPSHOOTER)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._toggle_perk(PerkId.ANXIOUS_LOADER)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_THREE):
            self._toggle_perk(PerkId.STATIONARY_RELOADER)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._toggle_perk(PerkId.ANGRY_RELOADER)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FIVE):
            self._toggle_perk(PerkId.MAN_BOMB)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SIX):
            self._toggle_perk(PerkId.HOT_TEMPERED)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SEVEN):
            self._toggle_perk(PerkId.FIRE_CAUGH)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self._toggle_perk(PerkId.ALTERNATE_WEAPON)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_Z):
            bonus_apply(self._state, self._player, BonusId.WEAPON_POWER_UP)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_X):
            bonus_apply(self._state, self._player, BonusId.SHIELD)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_C):
            bonus_apply(self._state, self._player, BonusId.SPEED)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_V):
            bonus_apply(self._state, self._player, BonusId.FIRE_BULLETS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_B):
            bonus_apply(self._state, self._player, BonusId.FIREBLAST, origin=self._player)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._state.bonuses.weapon_power_up = 0.0
            self._player.shield_timer = 0.0
            self._player.speed_bonus_timer = 0.0
            self._player.fire_bullets_timer = 0.0
            bonus_hud_update(self._state, [self._player])

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
        if desired_x > -1.0:
            desired_x = -1.0
        if desired_x < min_x:
            desired_x = min_x
        if desired_y > -1.0:
            desired_y = -1.0
        if desired_y < min_y:
            desired_y = min_y

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self._camera_x = _lerp(self._camera_x, desired_x, t)
        self._camera_y = _lerp(self._camera_y, desired_y, t)

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

    def _decay_global_timers(self, dt: float) -> None:
        self._state.bonuses.weapon_power_up = max(0.0, self._state.bonuses.weapon_power_up - dt)
        self._state.bonuses.reflex_boost = max(0.0, self._state.bonuses.reflex_boost - dt)
        self._state.bonuses.energizer = max(0.0, self._state.bonuses.energizer - dt)
        self._state.bonuses.double_experience = max(0.0, self._state.bonuses.double_experience - dt)
        self._state.bonuses.freeze = max(0.0, self._state.bonuses.freeze - dt)

    def update(self, dt: float) -> None:
        self._handle_input()

        if self._paused:
            dt = 0.0

        self._last_dt_ms = float(min(dt, 0.1) * 1000.0)

        self._elapsed_ms += dt * 1000.0

        # Frame loop: projectiles update first; player spawns are visible next tick.
        self._state.projectiles.update(
            dt,
            self._creatures,
            world_size=WORLD_SIZE,
            damage_scale_by_type=self._damage_scale_by_type,
            rng=self._state.rng.rand,
            runtime_state=self._state,
        )
        self._state.secondary_projectiles.update_pulse_gun(dt, self._creatures)
        self._creatures = [c for c in self._creatures if c.hp > 0.0]
        self._ensure_creatures(10)

        self._decay_global_timers(dt)

        input_state = self._build_input()
        player_update(self._player, input_state, dt, self._state, world_size=WORLD_SIZE)

        bonus_hud_update(self._state, [self._player])
        self._update_camera(dt)

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return

        # World bounds.
        x0, y0 = self._camera_world_to_screen(0.0, 0.0)
        x1, y1 = self._camera_world_to_screen(WORLD_SIZE, WORLD_SIZE)
        rl.draw_rectangle_lines(int(x0), int(y0), int(x1 - x0), int(y1 - y0), rl.Color(40, 40, 55, 255))

        # Creatures.
        for creature in self._creatures:
            sx, sy = self._camera_world_to_screen(creature.x, creature.y)
            color = rl.Color(220, 90, 90, 255)
            rl.draw_circle(int(sx), int(sy), float(creature.size * 0.5), color)

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
                elapsed_ms=self._elapsed_ms,
                score=self._player.experience,
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
            )

        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24, rl.get_screen_height() - 28, UI_ERROR_COLOR, scale=0.8)

        # UI.
        scale = hud_ui_scale(float(rl.get_screen_width()), float(rl.get_screen_height()))
        margin = 18
        x = float(margin)
        y = max(float(margin) + 110.0 * scale, hud_bottom + 12.0 * scale)
        line = self._ui_line_height()

        weapon_id = self._player.weapon_id
        weapon_name = next((w.name for w in WEAPON_TABLE if w.weapon_id == weapon_id), None) or f"weapon_{weapon_id}"
        self._draw_ui_text(f"{weapon_name} (id {weapon_id})", x, y, UI_TEXT_COLOR)
        y += line + 4
        self._draw_ui_text(
            f"ammo {self._player.ammo}/{self._player.clip_size}  reload {self._player.reload_timer:.2f}/{self._player.reload_timer_max:.2f}",
            x,
            y,
            UI_TEXT_COLOR,
        )
        y += line + 4
        self._draw_ui_text(
            f"cooldown {self._player.shot_cooldown:.3f}  spread {self._player.spread_heat:.3f}",
            x,
            y,
            UI_TEXT_COLOR,
        )
        y += line + 8

        self._draw_ui_text("WASD move  Mouse aim  LMB fire  R reload/swap  Q/E weapon  Tab pause", x, y, UI_HINT_COLOR)
        y += line + 4
        self._draw_ui_text(
            "1 Sharpshooter 2 Anxious 3 Stationary 4 Angry 5 Man Bomb 6 Hot Tempered 7 Fire Cough  T Alt Weapon",
            x,
            y,
            UI_HINT_COLOR,
        )
        y += line + 4
        self._draw_ui_text("Z PowerUp  X Shield  C Speed  V FireBullets  B Fireblast  Backspace clear bonuses", x, y, UI_HINT_COLOR)
        y += line + 10

        active_perks = []
        for perk in (
            PerkId.SHARPSHOOTER,
            PerkId.ANXIOUS_LOADER,
            PerkId.STATIONARY_RELOADER,
            PerkId.ANGRY_RELOADER,
            PerkId.MAN_BOMB,
            PerkId.HOT_TEMPERED,
            PerkId.FIRE_CAUGH,
            PerkId.ALTERNATE_WEAPON,
        ):
            if self._player.perk_counts[int(perk)]:
                active_perks.append(perk.name.lower())
        self._draw_ui_text("perks: " + (", ".join(active_perks) if active_perks else "none"), x, y, UI_TEXT_COLOR)
        y += line + 8

        # Bonus HUD slots (text-only).
        slots = [slot for slot in self._state.bonus_hud.slots if slot.active]
        if slots:
            self._draw_ui_text("bonuses:", x, y, UI_TEXT_COLOR)
            y += line + 4
            for slot in slots:
                self._draw_ui_text(f"- {slot.label}", x, y, UI_HINT_COLOR)
                y += line + 2


@register_view("player", "Player sandbox")
def build_player_view(ctx: ViewContext) -> View:
    return PlayerSandboxView(ctx)
