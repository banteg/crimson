from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import random
from typing import Protocol

import pyray as rl

from .audio import AudioState, update_audio
from .assets import PaqTextureCache, load_paq_entries
from .config import CrimsonConfig
from .spawn_templates import CreatureFlags, CreatureTypeId, SPAWN_ID_TO_TEMPLATE
from .terrain_render import GroundRenderer
from .weapons import WEAPON_TABLE


WORLD_SIZE = 1024.0
DEMO_VARIANT_COUNT = 5


class DemoState(Protocol):
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    texture_cache: PaqTextureCache | None
    audio: AudioState | None


@dataclass(frozen=True, slots=True)
class _AnimInfo:
    base: int
    anim_rate: float
    mirror: bool


_TYPE_ANIM: dict[CreatureTypeId, _AnimInfo] = {
    CreatureTypeId.ZOMBIE: _AnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: _AnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: _AnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: _AnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: _AnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: _AnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}


@dataclass(slots=True)
class DemoCreature:
    spawn_id: int
    x: float
    y: float
    vx: float = 0.0
    vy: float = 0.0
    hp: float = 10.0
    phase: float = 0.0
    target_player: int | None = None


@dataclass(slots=True)
class DemoPlayer:
    index: int
    x: float
    y: float
    weapon_id: int
    vx: float = 0.0
    vy: float = 0.0
    aim_x: float = 1.0
    aim_y: float = 0.0
    fire_cooldown: float = 0.0
    reload_timer: float = 0.0
    clip_remaining: int | None = None
    target_creature: int | None = None
    phase: float = 0.0


def _weapon_name(weapon_id: int) -> str:
    for weapon in WEAPON_TABLE:
        if weapon.weapon_id == weapon_id:
            return weapon.name or f"weapon_{weapon_id}"
    return f"weapon_{weapon_id}"


@dataclass(slots=True)
class DemoProjectile:
    kind: str
    x: float
    y: float
    vx: float
    vy: float
    life: float
    radius: float
    damage: float


@dataclass(slots=True)
class DemoBeam:
    x0: float
    y0: float
    x1: float
    y1: float
    life: float


@dataclass(slots=True)
class DemoExplosion:
    kind: str
    x: float
    y: float
    elapsed: float
    duration: float
    max_radius: float
    damage_per_tick: float
    tick_interval: float
    tick_accum: float = 0.0


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _distance_sq(x0: float, y0: float, x1: float, y1: float) -> float:
    dx = x1 - x0
    dy = y1 - y0
    return dx * dx + dy * dy


def _normalize(dx: float, dy: float) -> tuple[float, float, float]:
    d = math.hypot(dx, dy)
    if d <= 1e-6:
        return 0.0, 0.0, 0.0
    inv = 1.0 / d
    return dx * inv, dy * inv, d


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


class DemoView:
    """Attract-mode demo scaffold.

    Modeled after the classic demo helpers in crimsonland.exe:
      - demo_setup_variant_0 @ 0x00402ED0
      - demo_setup_variant_1 @ 0x004030F0
      - demo_setup_variant_2 @ 0x00402FE0
      - demo_setup_variant_3 @ 0x00403250
      - demo_mode_start       @ 0x00403390
    """

    def __init__(self, state: DemoState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._creatures: list[DemoCreature] = []
        self._players: list[DemoPlayer] = []
        self._projectiles: list[DemoProjectile] = []
        self._beams: list[DemoBeam] = []
        self._explosions: list[DemoExplosion] = []
        self._variant_index = 0
        self._variant_elapsed = 0.0
        self._variant_duration = 0.0
        self._finished = False
        self._camera_x = 0.0
        self._camera_y = 0.0

    def open(self) -> None:
        self._finished = False
        self._variant_index = 0
        self._start_variant(0)

    def close(self) -> None:
        if self._ground is not None and self._ground.render_target is not None:
            rl.unload_render_texture(self._ground.render_target)
        self._ground = None
        self._creatures.clear()
        self._players.clear()
        self._projectiles.clear()
        self._beams.clear()
        self._explosions.clear()

    def is_finished(self) -> bool:
        return self._finished

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio)
        if self._finished:
            return
        if self._skip_triggered():
            self._finished = True
            return
        frame_dt = min(dt, 0.1)
        self._variant_elapsed += frame_dt
        self._update_sim(frame_dt)
        self._advance_anim_phase(frame_dt)
        if self._variant_elapsed < self._variant_duration:
            return
        next_variant = self._variant_index + 1
        if next_variant >= DEMO_VARIANT_COUNT:
            self._finished = True
            return
        self._start_variant(next_variant)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(self._camera_x, self._camera_y)
        self._draw_fx()
        self._draw_entities()
        self._draw_overlay()

    def _skip_triggered(self) -> bool:
        if rl.get_key_pressed() != 0:
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT):
            return True
        return False

    def _advance_anim_phase(self, dt: float) -> None:
        for creature in self._creatures:
            template = SPAWN_ID_TO_TEMPLATE.get(creature.spawn_id)
            if template is None or template.type_id is None:
                continue
            info = _TYPE_ANIM.get(template.type_id)
            if info is None:
                continue
            creature.phase += info.anim_rate * dt * 60.0
        for player in self._players:
            info = _TYPE_ANIM.get(CreatureTypeId.TROOPER)
            if info is None:
                continue
            player.phase += info.anim_rate * dt * 60.0

    def _ensure_cache(self) -> PaqTextureCache:
        cache = self._state.texture_cache
        if cache is not None:
            return cache
        entries = load_paq_entries(self._state.assets_dir)
        cache = PaqTextureCache(entries=entries, textures={})
        self._state.texture_cache = cache
        return cache

    def _start_variant(self, index: int) -> None:
        self._variant_index = index
        self._variant_elapsed = 0.0
        self._creatures.clear()
        self._players.clear()
        self._projectiles.clear()
        self._beams.clear()
        self._explosions.clear()
        self._apply_variant_ground(index)
        if index == 0:
            self._setup_variant_0()
        elif index == 1:
            self._setup_variant_1()
        elif index == 2:
            self._setup_variant_2()
        elif index == 3:
            self._setup_variant_3()
        else:
            self._setup_variant_0()

    def _apply_variant_ground(self, index: int) -> None:
        cache = self._ensure_cache()
        terrain = {
            0: ("ter_q1_base", "ter_q1_tex1", "ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"),
            1: ("ter_q2_base", "ter_q2_tex1", "ter/ter_q2_base.jaz", "ter/ter_q2_tex1.jaz"),
            2: ("ter_q3_base", "ter_q3_tex1", "ter/ter_q3_base.jaz", "ter/ter_q3_tex1.jaz"),
            3: ("ter_q4_base", "ter_q4_tex1", "ter/ter_q4_base.jaz", "ter/ter_q4_tex1.jaz"),
            4: ("ter_q1_base", "ter_q1_tex1", "ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"),
        }.get(index, ("ter_q1_base", "ter_q1_tex1", "ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"))
        base_key, overlay_key, base_path, overlay_path = terrain
        base = cache.get_or_load(base_key, base_path).texture
        if base is None:
            return
        overlay = cache.get_or_load(overlay_key, overlay_path).texture
        detail = overlay or base
        if self._ground is None:
            self._ground = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=int(WORLD_SIZE),
                height=int(WORLD_SIZE),
                texture_scale=self._state.config.texture_scale,
                screen_width=float(self._state.config.screen_width),
                screen_height=float(self._state.config.screen_height),
            )
        else:
            self._ground.texture = base
            self._ground.overlay = overlay
            self._ground.overlay_detail = detail
            self._ground.texture_scale = self._state.config.texture_scale
            self._ground.screen_width = float(self._state.config.screen_width)
            self._ground.screen_height = float(self._state.config.screen_height)
        self._ground.generate(seed=self._state.rng.randrange(0, 10_000))

    def _wrap_pos(self, x: float, y: float) -> tuple[float, float]:
        return (x % WORLD_SIZE, y % WORLD_SIZE)

    def _spawn(self, spawn_id: int, x: float, y: float) -> None:
        x, y = self._wrap_pos(x, y)
        template = SPAWN_ID_TO_TEMPLATE.get(spawn_id)
        hp = self._creature_hp(template.type_id if template is not None else None)
        self._creatures.append(DemoCreature(spawn_id=spawn_id, x=x, y=y, hp=hp))

    def _setup_variant_0(self) -> None:
        self._variant_duration = 4.0
        weapon_id = 11
        self._players = [
            DemoPlayer(index=0, x=448.0, y=384.0, weapon_id=weapon_id),
            DemoPlayer(index=1, x=546.0, y=654.0, weapon_id=weapon_id),
        ]
        y = 256
        i = 0
        while y < 1696:
            col = i % 2
            self._spawn(0x38, float((col + 2) * 64), float(y))
            self._spawn(0x38, float(col * 64 + 798), float(y))
            y += 80
            i += 1

    def _setup_variant_1(self) -> None:
        self._variant_duration = 5.0
        weapon_id = 5
        self._players = [
            DemoPlayer(index=0, x=490.0, y=448.0, weapon_id=weapon_id),
            DemoPlayer(index=1, x=480.0, y=576.0, weapon_id=weapon_id),
        ]
        for idx in range(20):
            x = float(self._state.rng.randrange(200) + 32)
            y = float(self._state.rng.randrange(899) + 64)
            self._spawn(0x34, x, y)
            if idx % 3 != 0:
                x2 = float(self._state.rng.randrange(30) + 32)
                y2 = float(self._state.rng.randrange(899) + 64)
                self._spawn(0x35, x2, y2)

    def _setup_variant_2(self) -> None:
        self._variant_duration = 5.0
        weapon_id = 21
        self._players = [DemoPlayer(index=0, x=512.0, y=512.0, weapon_id=weapon_id)]
        y = 128
        i = 0
        while y < 848:
            col = i % 2
            self._spawn(0x41, float(col * 64 + 32), float(y))
            self._spawn(0x41, float((col + 2) * 64), float(y))
            self._spawn(0x41, float(col * 64 - 64), float(y))
            self._spawn(0x41, float((col + 12) * 64), float(y))
            y += 60
            i += 1

    def _setup_variant_3(self) -> None:
        self._variant_duration = 4.0
        weapon_id = 18
        self._players = [DemoPlayer(index=0, x=512.0, y=512.0, weapon_id=weapon_id)]
        for idx in range(20):
            x = float(self._state.rng.randrange(200) + 32)
            y = float(self._state.rng.randrange(899) + 64)
            self._spawn(0x24, x, y)
            if idx % 3 != 0:
                x2 = float(self._state.rng.randrange(30) + 32)
                y2 = float(self._state.rng.randrange(899) + 64)
                self._spawn(0x25, x2, y2)

    def _world_params(self) -> tuple[float, float, float, float]:
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w = float(self._state.config.screen_width)
        screen_h = float(self._state.config.screen_height)
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        cam_x = self._camera_x
        cam_y = self._camera_y
        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        if cam_x < min_x:
            cam_x = min_x
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_y < min_y:
            cam_y = min_y
        if cam_y > -1.0:
            cam_y = -1.0

        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        return cam_x, cam_y, scale_x, scale_y

    def _world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        return (x + cam_x) * scale_x, (y + cam_y) * scale_y

    def _select_frame(self, spawn_id: int, phase: float) -> tuple[int, bool]:
        template = SPAWN_ID_TO_TEMPLATE.get(spawn_id)
        if template is None or template.type_id is None:
            return 0, False
        info = _TYPE_ANIM.get(template.type_id)
        if info is None:
            return 0, False
        flags = template.flags or CreatureFlags(0)
        long_strip = not (flags & CreatureFlags.ANIM_PING_PONG) or (
            flags & CreatureFlags.ANIM_LONG_STRIP
        )
        if long_strip:
            base_frame = int(phase) % 32
            frame = base_frame
            if flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                frame += 0x20
            mirror = info.mirror and base_frame >= 16
            return frame, mirror
        ping = int(phase) % 16
        if ping >= 8:
            ping = 15 - ping
        frame = info.base + 0x10 + ping
        return frame, False

    def _draw_fx(self) -> None:
        if not (self._projectiles or self._beams or self._explosions):
            return
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        del cam_x, cam_y
        scale = (scale_x + scale_y) * 0.5

        for proj in self._projectiles:
            sx, sy = self._world_to_screen(proj.x, proj.y)
            radius = max(1.0, proj.radius * scale)
            color = {
                "gauss": rl.Color(235, 235, 235, 255),
                "rocket": rl.Color(255, 120, 80, 255),
                "pulse": rl.Color(200, 120, 255, 255),
            }.get(proj.kind, rl.Color(235, 235, 235, 255))
            rl.draw_circle(int(sx), int(sy), radius, color)

        for beam in self._beams:
            x0, y0 = self._world_to_screen(beam.x0, beam.y0)
            x1, y1 = self._world_to_screen(beam.x1, beam.y1)
            alpha = int(_clamp(beam.life / 0.08, 0.0, 1.0) * 255.0)
            color = rl.Color(120, 220, 255, alpha)
            rl.draw_line_ex(rl.Vector2(x0, y0), rl.Vector2(x1, y1), 2.0 * scale, color)

        for fx in self._explosions:
            t = fx.elapsed / fx.duration if fx.duration > 0 else 1.0
            radius = fx.max_radius * _clamp(t, 0.0, 1.0)
            sx, sy = self._world_to_screen(fx.x, fx.y)
            alpha = int((1.0 - _clamp(t, 0.0, 1.0)) * 180.0)
            color = (
                rl.Color(255, 180, 100, alpha)
                if fx.kind == "rocket"
                else rl.Color(200, 120, 255, alpha)
            )
            rl.draw_circle_lines(int(sx), int(sy), max(1.0, radius * scale), color)

    def _draw_entities(self) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        del cam_x, cam_y

        player_tex = cache.get_or_load("trooper", "game/trooper.jaz").texture
        if player_tex is not None:
            for player in self._players:
                self._draw_sprite(
                    player_tex,
                    CreatureTypeId.TROOPER,
                    CreatureFlags(0),
                    player.phase,
                    player.x,
                    player.y,
                    scale_x,
                    scale_y,
                    tint=rl.Color(240, 240, 255, 255),
                )

        for creature in self._creatures:
            template = SPAWN_ID_TO_TEMPLATE.get(creature.spawn_id)
            if template is None or template.creature is None or template.type_id is None:
                continue
            texture = cache.texture(template.creature)
            if texture is None:
                rel_path = f"game/{template.creature}.jaz"
                texture = cache.get_or_load(template.creature, rel_path).texture
            if texture is None:
                continue
            self._draw_sprite(
                texture,
                template.type_id,
                template.flags or CreatureFlags(0),
                creature.phase,
                creature.x,
                creature.y,
                scale_x,
                scale_y,
                tint=rl.WHITE,
            )

    def _draw_sprite(
        self,
        texture: rl.Texture2D,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        world_x: float,
        world_y: float,
        scale_x: float,
        scale_y: float,
        *,
        tint: rl.Color,
    ) -> None:
        info = _TYPE_ANIM.get(type_id)
        if info is None:
            return
        long_strip = not (flags & CreatureFlags.ANIM_PING_PONG) or (
            flags & CreatureFlags.ANIM_LONG_STRIP
        )
        if long_strip:
            base_frame = int(phase) % 32
            frame = base_frame
            if flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                frame += 0x20
            mirror = info.mirror and base_frame >= 16
        else:
            ping = int(phase) % 16
            if ping >= 8:
                ping = 15 - ping
            frame = info.base + 0x10 + ping
            mirror = False

        grid = 8
        cell = float(texture.width) / grid if grid > 0 else float(texture.width)
        row = frame // grid
        col = frame % grid
        src = rl.Rectangle(float(col * cell), float(row * cell), float(cell), float(cell))
        if mirror:
            src.x += src.width
            src.width = -src.width
        screen_x, screen_y = self._world_to_screen(world_x, world_y)
        width = cell * scale_x
        height = cell * scale_y
        dst = rl.Rectangle(screen_x, screen_y, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, 0.0, tint)

    def _draw_overlay(self) -> None:
        title = f"DEMO MODE  ({self._variant_index + 1}/{DEMO_VARIANT_COUNT})"
        hint = "Press any key / click to skip"
        remaining = max(0.0, self._variant_duration - self._variant_elapsed)
        weapons = ", ".join(
            f"P{p.index + 1}:{_weapon_name(p.weapon_id)}" for p in self._players
        )
        detail = f"{weapons}  —  next in {remaining:0.1f}s"
        rl.draw_text(title, 16, 12, 20, rl.Color(240, 240, 240, 255))
        rl.draw_text(detail, 16, 36, 16, rl.Color(180, 180, 190, 255))
        rl.draw_text(hint, 16, 56, 16, rl.Color(140, 140, 150, 255))

    def _creature_hp(self, type_id: CreatureTypeId | None) -> float:
        if type_id == CreatureTypeId.ZOMBIE:
            return 22.0
        if type_id in (CreatureTypeId.SPIDER_SP1, CreatureTypeId.SPIDER_SP2):
            return 12.0
        if type_id == CreatureTypeId.ALIEN:
            return 16.0
        return 14.0

    def _creature_speed(self, type_id: CreatureTypeId | None) -> float:
        if type_id == CreatureTypeId.ZOMBIE:
            return 70.0
        if type_id in (CreatureTypeId.SPIDER_SP1, CreatureTypeId.SPIDER_SP2):
            return 105.0
        if type_id == CreatureTypeId.ALIEN:
            return 85.0
        return 80.0

    def _weapon_spec(self, weapon_id: int) -> tuple[float, float, float, float]:
        """Return (fire_interval, spread_rad, speed, damage) for demo weapons."""
        fire_interval = 0.2
        spread = 0.0
        speed = 650.0
        damage = 10.0
        for weapon in WEAPON_TABLE:
            if weapon.weapon_id != weapon_id:
                continue
            if weapon.fire_rate is not None:
                fire_interval = max(0.02, float(weapon.fire_rate))
            if weapon.spread is not None:
                spread = float(weapon.spread)
            break
        if weapon_id == 5:  # Gauss Gun
            speed = 920.0
            damage = 18.0
        elif weapon_id == 11:  # Rocket Launcher
            speed = 520.0
            damage = 32.0
        elif weapon_id == 18:  # Pulse Gun
            speed = 280.0
            damage = 14.0
        elif weapon_id == 21:  # Ion Minigun (beam)
            speed = 0.0
            damage = 5.0
        return fire_interval, spread, speed, damage

    def _update_sim(self, dt: float) -> None:
        self._update_creatures(dt)
        self._update_players(dt)
        self._update_projectiles(dt)
        self._update_fx(dt)
        self._update_camera(dt)

    def _nearest_player_index(self, x: float, y: float) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, player in enumerate(self._players):
            d = _distance_sq(x, y, player.x, player.y)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _nearest_creature_index(self, x: float, y: float) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, creature in enumerate(self._creatures):
            if creature.hp <= 0.0:
                continue
            d = _distance_sq(x, y, creature.x, creature.y)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _update_creatures(self, dt: float) -> None:
        if not self._creatures or not self._players:
            return
        for creature in self._creatures:
            if creature.hp <= 0.0:
                continue
            target_idx = self._nearest_player_index(creature.x, creature.y)
            creature.target_player = target_idx
            if target_idx is None:
                creature.vx = 0.0
                creature.vy = 0.0
                continue
            target = self._players[target_idx]
            dx = target.x - creature.x
            dy = target.y - creature.y
            nx, ny, _ = _normalize(dx, dy)
            template = SPAWN_ID_TO_TEMPLATE.get(creature.spawn_id)
            speed = self._creature_speed(
                template.type_id if template is not None else None
            )
            creature.vx = nx * speed
            creature.vy = ny * speed
            creature.x = _clamp(creature.x + creature.vx * dt, 0.0, WORLD_SIZE)
            creature.y = _clamp(creature.y + creature.vy * dt, 0.0, WORLD_SIZE)

    def _select_player_target(self, player: DemoPlayer) -> int | None:
        candidate = self._nearest_creature_index(player.x, player.y)
        current = player.target_creature
        if current is None:
            return candidate
        if not (0 <= current < len(self._creatures)):
            return candidate
        current_creature = self._creatures[current]
        if current_creature.hp <= 0.0:
            return candidate
        if candidate is None or candidate == current:
            return current
        cand_creature = self._creatures[candidate]
        if cand_creature.hp <= 0.0:
            return current
        cur_d = math.hypot(current_creature.x - player.x, current_creature.y - player.y)
        cand_d = math.hypot(cand_creature.x - player.x, cand_creature.y - player.y)
        if cand_d + 64.0 < cur_d:
            return candidate
        return current

    def _update_players(self, dt: float) -> None:
        if not self._players:
            return
        center_x = WORLD_SIZE * 0.5
        center_y = WORLD_SIZE * 0.5
        for player in self._players:
            player.fire_cooldown = max(0.0, player.fire_cooldown - dt)
            player.reload_timer = max(0.0, player.reload_timer - dt)

            player.target_creature = self._select_player_target(player)
            target = (
                self._creatures[player.target_creature]
                if player.target_creature is not None
                else None
            )
            if target is not None and target.hp > 0.0:
                dx = target.x - player.x
                dy = target.y - player.y
                nx, ny, _ = _normalize(dx, dy)
                player.aim_x, player.aim_y = nx, ny
            else:
                dx = center_x - player.x
                dy = center_y - player.y
                nx, ny, _ = _normalize(dx, dy)
                player.aim_x, player.aim_y = nx, ny

            move_x, move_y = 0.0, 0.0
            to_cx = center_x - player.x
            to_cy = center_y - player.y
            nx, ny, d = _normalize(to_cx, to_cy)
            if d > 120.0:
                move_x += nx
                move_y += ny

            if target is not None and target.hp > 0.0:
                rx = player.x - target.x
                ry = player.y - target.y
                rnx, rny, rd = _normalize(rx, ry)
                if 0.0 < rd < 160.0:
                    strength = (160.0 - rd) / 160.0
                    move_x += rnx * (1.5 * strength)
                    move_y += rny * (1.5 * strength)

            orbit_dir = -1.0 if (player.index % 2) else 1.0
            ox, oy, _ = _normalize(-(player.y - center_y), player.x - center_x)
            move_x += ox * 0.55 * orbit_dir
            move_y += oy * 0.55 * orbit_dir

            mnx, mny, _ = _normalize(move_x, move_y)
            speed = 150.0
            player.vx = mnx * speed
            player.vy = mny * speed
            player.x = _clamp(player.x + player.vx * dt, 0.0, WORLD_SIZE)
            player.y = _clamp(player.y + player.vy * dt, 0.0, WORLD_SIZE)

            self._player_fire(player, target)

    def _player_fire(self, player: DemoPlayer, target: DemoCreature | None) -> None:
        if player.reload_timer > 0.0:
            return
        if player.fire_cooldown > 0.0:
            return
        if target is None or target.hp <= 0.0:
            return

        fire_interval, spread, speed, damage = self._weapon_spec(player.weapon_id)
        player.fire_cooldown = fire_interval
        ax, ay = player.aim_x, player.aim_y
        if spread > 0.0:
            jitter = (self._state.rng.random() * 2.0 - 1.0) * spread
            ca = math.cos(jitter)
            sa = math.sin(jitter)
            ax, ay = ax * ca - ay * sa, ax * sa + ay * ca

        if player.weapon_id == 21:
            self._fire_ion_beam(player, damage)
            return

        if speed <= 0.0:
            return

        if player.weapon_id == 11:
            radius = 10.0
            life = 1.6
            kind = "rocket"
        elif player.weapon_id == 18:
            radius = 12.0
            life = 0.7
            kind = "pulse"
        else:
            radius = 6.0
            life = 1.2
            kind = "gauss"
        self._projectiles.append(
            DemoProjectile(
                kind=kind,
                x=player.x,
                y=player.y,
                vx=ax * speed,
                vy=ay * speed,
                life=life,
                radius=radius,
                damage=damage,
            )
        )

    def _fire_ion_beam(self, player: DemoPlayer, damage: float) -> None:
        max_range = 420.0
        hit_idx = self._nearest_creature_index(player.x, player.y)
        if hit_idx is None:
            return
        creature = self._creatures[hit_idx]
        if creature.hp <= 0.0:
            return
        dist = math.hypot(creature.x - player.x, creature.y - player.y)
        if dist > max_range:
            return
        creature.hp -= damage
        self._beams.append(
            DemoBeam(
                x0=player.x,
                y0=player.y,
                x1=creature.x,
                y1=creature.y,
                life=0.08,
            )
        )

    def _update_projectiles(self, dt: float) -> None:
        if not self._projectiles:
            return
        survivors: list[DemoProjectile] = []
        for proj in self._projectiles:
            proj.life -= dt
            proj.x += proj.vx * dt
            proj.y += proj.vy * dt
            if proj.x < -64.0 or proj.x > WORLD_SIZE + 64.0:
                continue
            if proj.y < -64.0 or proj.y > WORLD_SIZE + 64.0:
                continue

            if proj.kind in {"gauss", "rocket"}:
                if self._projectile_hit_creature(proj):
                    continue
            if proj.kind == "pulse" and proj.life <= 0.0:
                self._explosions.append(
                    DemoExplosion(
                        kind="pulse",
                        x=proj.x,
                        y=proj.y,
                        elapsed=0.0,
                        duration=0.9,
                        max_radius=120.0,
                        damage_per_tick=4.0,
                        tick_interval=0.12,
                        tick_accum=0.12,
                    )
                )
                continue

            if proj.life > 0.0:
                survivors.append(proj)
        self._projectiles = survivors
        self._creatures = [c for c in self._creatures if c.hp > 0.0]

    def _projectile_hit_creature(self, proj: DemoProjectile) -> bool:
        hit_idx = None
        hit_dist = 0.0
        for idx, creature in enumerate(self._creatures):
            if creature.hp <= 0.0:
                continue
            d = _distance_sq(proj.x, proj.y, creature.x, creature.y)
            if hit_idx is None or d < hit_dist:
                hit_idx = idx
                hit_dist = d
        if hit_idx is None:
            return False
        creature = self._creatures[hit_idx]
        hit_radius = proj.radius + 18.0
        if hit_dist > hit_radius * hit_radius:
            return False

        if proj.kind == "rocket":
            radius = 90.0
            self._apply_radial_damage(proj.x, proj.y, radius, proj.damage)
            self._explosions.append(
                DemoExplosion(
                    kind="rocket",
                    x=proj.x,
                    y=proj.y,
                    elapsed=0.0,
                    duration=0.35,
                    max_radius=radius,
                    damage_per_tick=0.0,
                    tick_interval=1.0,
                )
            )
        else:
            creature.hp -= proj.damage
        return True

    def _apply_radial_damage(self, x: float, y: float, radius: float, damage: float) -> None:
        rsq = radius * radius
        for creature in self._creatures:
            if creature.hp <= 0.0:
                continue
            if _distance_sq(x, y, creature.x, creature.y) <= rsq:
                creature.hp -= damage

    def _update_fx(self, dt: float) -> None:
        if self._beams:
            beams: list[DemoBeam] = []
            for beam in self._beams:
                beam.life -= dt
                if beam.life > 0.0:
                    beams.append(beam)
            self._beams = beams

        if not self._explosions:
            return
        survivors: list[DemoExplosion] = []
        for fx in self._explosions:
            fx.elapsed += dt
            if fx.damage_per_tick > 0.0 and fx.tick_interval > 0.0:
                fx.tick_accum += dt
                while fx.tick_accum >= fx.tick_interval:
                    fx.tick_accum -= fx.tick_interval
                    self._apply_explosion_damage(fx)
            if fx.elapsed < fx.duration:
                survivors.append(fx)
        self._explosions = survivors
        self._creatures = [c for c in self._creatures if c.hp > 0.0]

    def _apply_explosion_damage(self, fx: DemoExplosion) -> None:
        t = fx.elapsed / fx.duration if fx.duration > 0 else 1.0
        radius = fx.max_radius * _clamp(t, 0.0, 1.0)
        rsq = radius * radius
        for creature in self._creatures:
            if creature.hp <= 0.0:
                continue
            if _distance_sq(fx.x, fx.y, creature.x, creature.y) <= rsq:
                creature.hp -= fx.damage_per_tick

    def _update_camera(self, dt: float) -> None:
        if not self._players:
            return
        screen_w = float(self._state.config.screen_width)
        screen_h = float(self._state.config.screen_height)
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        if len(self._players) == 1:
            focus_x = self._players[0].x
            focus_y = self._players[0].y
        else:
            focus_x = sum(p.x for p in self._players) / len(self._players)
            focus_y = sum(p.y for p in self._players) / len(self._players)

        desired_x = (screen_w * 0.5) - focus_x
        desired_y = (screen_h * 0.5) - focus_y

        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        if desired_x < min_x:
            desired_x = min_x
        if desired_x > -1.0:
            desired_x = -1.0
        if desired_y < min_y:
            desired_y = min_y
        if desired_y > -1.0:
            desired_y = -1.0

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self._camera_x = _lerp(self._camera_x, desired_x, t)
        self._camera_y = _lerp(self._camera_y, desired_y, t)
