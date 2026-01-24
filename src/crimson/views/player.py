from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path

import pyray as rl

from .registry import register_view
from grim.audio import init_audio_state, play_sfx, shutdown_audio
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.console import create_console
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext

from ..bonuses import BONUS_BY_ID, BonusId
from ..effects import ParticlePool, SpriteEffectPool
from ..gameplay import (
    BonusPickupEvent,
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_apply,
    bonus_update,
    bonus_hud_update,
    player_update,
    weapon_assign_player,
)
from ..perks import PerkId
from ..weapons import WEAPON_BY_ID, WEAPON_TABLE

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
        self._bonus_texture: rl.Texture | None = None
        self._wicon_texture: rl.Texture | None = None

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos_x=WORLD_SIZE * 0.5, pos_y=WORLD_SIZE * 0.5)
        self._creatures: list[DummyCreature] = []
        self._particles = ParticlePool(rand=self._state.rng.rand)
        self._sprite_fx = SpriteEffectPool(rand=self._state.rng.rand)
        self._audio = None

        self._camera_x = -1.0
        self._camera_y = -1.0
        self._paused = False

        self._weapon_ids = [entry.weapon_id for entry in WEAPON_TABLE if entry.name is not None]
        self._weapon_index = 0

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
                clip = int(getattr(weapon, "clip_size", 0) or 0) if weapon is not None else 0
                self._player.alt_weapon_id = alt_id
                self._player.alt_clip_size = max(0, clip)
                self._player.alt_ammo = self._player.alt_clip_size
        if perk_id == PerkId.ALTERNATE_WEAPON and not next_value:
            self._player.alt_weapon_id = None

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None
        self._bonus_texture = self._load_texture("game/bonuses.png")
        self._wicon_texture = self._load_texture("ui/ui_wicons.png")
        self._audio = self._init_audio()

        self._state.rng.srand(0xBEEF)
        self._creatures.clear()
        self._ensure_creatures(14)

        self._weapon_index = 0
        self._set_weapon(self._weapon_id())

        self._player.pos_x = WORLD_SIZE * 0.5
        self._player.pos_y = WORLD_SIZE * 0.5
        self._player.health = 100.0

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._bonus_texture is not None:
            rl.unload_texture(self._bonus_texture)
            self._bonus_texture = None
        if self._wicon_texture is not None:
            rl.unload_texture(self._wicon_texture)
            self._wicon_texture = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None

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

    def _load_texture(self, rel_path: str) -> rl.Texture | None:
        path = self._assets_root / "crimson" / rel_path
        if not path.is_file():
            self._missing_assets.append(rel_path)
            return None
        return rl.load_texture(str(path))

    def _init_audio(self):
        try:
            base_dir = Path("artifacts") / "runtime"
            console = create_console(base_dir)
            cfg = CrimsonConfig(path=base_dir / "crimson.cfg", data=default_crimson_cfg_data())
            return init_audio_state(cfg, self._assets_root, console)
        except Exception:
            return None

    def _spawn_bonus_pickup_fx(self, events: list[BonusPickupEvent]) -> None:
        if not events:
            return
        rng = self._state.rng
        for event in events:
            if self._audio is not None:
                play_sfx(self._audio, "sfx_ui_bonus")
            for _ in range(12):
                angle = float(rng.rand() % 628) * 0.01
                self._particles.spawn_particle(
                    pos_x=event.pos_x,
                    pos_y=event.pos_y,
                    angle=angle,
                    intensity=1.0,
                )
            for _ in range(8):
                vel_x = float((rng.rand() & 0x7F) - 0x40)
                vel_y = float((rng.rand() & 0x7F) - 0x40)
                self._sprite_fx.spawn(
                    pos_x=event.pos_x,
                    pos_y=event.pos_y,
                    vel_x=vel_x,
                    vel_y=vel_y,
                    scale=0.35,
                )

    def _bonus_icon_src(self, icon_id: int) -> rl.Rectangle | None:
        texture = self._bonus_texture
        if texture is None:
            return None
        if icon_id < 0:
            return None
        grid = 4
        cell_w = float(texture.width) / grid
        cell_h = float(texture.height) / grid
        col = int(icon_id) % grid
        row = int(icon_id) // grid
        return rl.Rectangle(cell_w * col, cell_h * row, cell_w, cell_h)

    def _weapon_icon_src(self, weapon_id: int) -> rl.Rectangle | None:
        texture = self._wicon_texture
        if texture is None:
            return None
        weapon = WEAPON_BY_ID.get(int(weapon_id))
        icon_index = weapon.icon_index if weapon is not None else None
        if icon_index is None or icon_index < 0:
            return None
        cols = 8
        rows = 8
        cell_w = float(texture.width) / cols
        cell_h = float(texture.height) / rows
        frame = int(icon_index) * 2
        col = frame % cols
        row = frame // cols
        return rl.Rectangle(cell_w * col, cell_h * row, cell_w * 2.0, cell_h)

    def _draw_bonus_icon(
        self,
        *,
        texture: rl.Texture,
        src: rl.Rectangle,
        world_x: float,
        world_y: float,
        scale: float,
        tint: rl.Color,
    ) -> None:
        screen_x, screen_y = self._camera_world_to_screen(world_x, world_y)
        width = src.width * scale
        height = src.height * scale
        dst = rl.Rectangle(float(screen_x), float(screen_y), float(width), float(height))
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, 0.0, tint)

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

        # Frame loop: projectiles update first; player spawns are visible next tick.
        self._state.projectiles.update(
            dt,
            self._creatures,
            world_size=WORLD_SIZE,
            damage_scale_by_type={},
            rng=self._state.rng.rand,
        )
        self._state.secondary_projectiles.update_pulse_gun(dt, self._creatures)
        self._creatures = [c for c in self._creatures if c.hp > 0.0]
        self._ensure_creatures(10)

        input_state = self._build_input()
        player_update(self._player, input_state, dt, self._state, world_size=WORLD_SIZE)

        pickup_events = bonus_update(self._state, [self._player], dt, update_hud=True)
        self._spawn_bonus_pickup_fx(pickup_events)

        self._particles.update(dt)
        self._sprite_fx.update(dt)

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

        # Bonuses.
        for entry in self._state.bonus_pool.iter_active():
            meta = BONUS_BY_ID.get(int(entry.bonus_id))
            icon_id = meta.icon_id if meta is not None and meta.icon_id is not None else -1
            if entry.bonus_id == int(BonusId.WEAPON):
                src = self._weapon_icon_src(entry.amount)
                texture = self._wicon_texture
            else:
                src = self._bonus_icon_src(int(icon_id))
                texture = self._bonus_texture
            if src is None or texture is None:
                sx, sy = self._camera_world_to_screen(entry.pos_x, entry.pos_y)
                rl.draw_circle(int(sx), int(sy), 10.0, rl.Color(220, 200, 80, 220))
                continue

            t = entry.time_left / entry.time_max if entry.time_max > 0.0 else 0.0
            t = _clamp(t, 0.0, 1.0)
            pulse = 0.85 + 0.15 * math.sin(entry.time_left * 6.0)
            scale = (0.7 + 0.3 * t) * pulse
            alpha = int((0.6 + 0.4 * t) * 255)
            if entry.picked:
                alpha = int(alpha * 0.5)
            tint = rl.Color(255, 255, 255, alpha)
            self._draw_bonus_icon(
                texture=texture,
                src=src,
                world_x=entry.pos_x,
                world_y=entry.pos_y,
                scale=scale,
                tint=tint,
            )

        # Bonus pickup FX.
        for particle in self._particles.iter_active():
            sx, sy = self._camera_world_to_screen(particle.pos_x, particle.pos_y)
            alpha = int(_clamp(particle.age, 0.0, 1.0) * 255)
            radius = max(1.0, 2.0 + particle.scale_x * 6.0)
            rl.draw_circle(int(sx), int(sy), radius, rl.Color(255, 210, 120, alpha))

        for fx in self._sprite_fx.iter_active():
            sx, sy = self._camera_world_to_screen(fx.pos_x, fx.pos_y)
            alpha = int(_clamp(fx.color_a, 0.0, 1.0) * 255)
            radius = max(1.0, fx.scale * 0.25)
            rl.draw_circle(int(sx), int(sy), radius, rl.Color(255, 180, 120, alpha))

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

        # UI.
        margin = 18
        x = float(margin)
        y = float(margin)
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
