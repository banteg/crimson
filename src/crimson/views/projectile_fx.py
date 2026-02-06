from __future__ import annotations

from grim.geom import Vec2

from dataclasses import dataclass
import math

import pyray as rl

from grim.fonts.small import SmallFontData, load_small_font
from grim.math import clamp
from grim.view import View, ViewContext

from ..bonuses import BonusId
from ..effects_atlas import EffectId, effect_src_rect
from ..gameplay import GameplayState, PlayerState, bonus_apply
from ..projectiles import ProjectileTypeId
from ..weapons import (
    WEAPON_BY_ID,
    WEAPON_TABLE,
    weapon_entry_for_projectile_type_id,
)
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_ACCENT_COLOR = rl.Color(240, 200, 80, 255)


@dataclass(slots=True)
class DummyCreature:
    pos: Vec2
    hp: float
    size: float = 42.0
    active: bool = True
    hitbox_size: float = 16.0
    plague_infected: bool = False


@dataclass(slots=True)
class BeamFx:
    start: Vec2
    end: Vec2
    life: float


@dataclass(slots=True)
class EffectFx:
    effect_id: int
    pos: Vec2
    life: float
    rotation: float
    scale: float


_KNOWN_PROJ_FRAMES: dict[int, tuple[int, int]] = {
    # Based on docs/atlas.md (projectile `type_id` values index the weapon table).
    ProjectileTypeId.PULSE_GUN: (2, 0),
    ProjectileTypeId.SPLITTER_GUN: (4, 3),
    ProjectileTypeId.BLADE_GUN: (4, 6),
    ProjectileTypeId.ION_MINIGUN: (4, 2),
    ProjectileTypeId.ION_CANNON: (4, 2),
    ProjectileTypeId.SHRINKIFIER: (4, 2),
    ProjectileTypeId.FIRE_BULLETS: (4, 2),
    ProjectileTypeId.ION_RIFLE: (4, 2),  # Shock Chain projectile
}

_BEAM_TYPES = frozenset(
    {
        ProjectileTypeId.ION_RIFLE,
        ProjectileTypeId.ION_MINIGUN,
        ProjectileTypeId.ION_CANNON,
        ProjectileTypeId.SHRINKIFIER,
        ProjectileTypeId.FIRE_BULLETS,
        ProjectileTypeId.BLADE_GUN,
        ProjectileTypeId.SPLITTER_GUN,
    }
)


class ProjectileFxView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []

        self._small: SmallFontData | None = None
        self._projs: rl.Texture | None = None
        self._particles: rl.Texture | None = None

        self.close_requested = False
        self._paused = False
        self._show_help = True
        self._show_debug = True

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos=Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5))
        self._creatures: list[DummyCreature] = []

        self._camera = Vec2(-1.0, -1.0)

        max_type_id = max((int(entry.weapon_id) for entry in WEAPON_TABLE), default=0)
        self._type_ids = list(range(int(max_type_id) + 1))
        self._type_index = 0

        self._damage_scale_by_type = {}
        for entry in WEAPON_TABLE:
            if entry.weapon_id <= 0:
                continue
            self._damage_scale_by_type[int(entry.weapon_id)] = float(entry.damage_scale or 1.0)

        self._origin = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)

        self._beams: list[BeamFx] = []
        self._effects: list[EffectFx] = []

    def _camera_world_to_screen(self, pos: Vec2) -> Vec2:
        return self._camera + pos

    def _camera_screen_to_world(self, pos: Vec2) -> Vec2:
        return pos - self._camera

    def _update_camera(self, dt: float) -> None:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        desired = Vec2(
            (screen_w * 0.5) - self._origin.x,
            (screen_h * 0.5) - self._origin.y,
        ).clamp_rect(min_x, min_y, -1.0, -1.0)

        t = clamp(dt * 6.0, 0.0, 1.0)
        self._camera = Vec2.lerp(self._camera, desired, t)

    def _reset_scene(self) -> None:
        self._state.projectiles.reset()
        self._state.secondary_projectiles.reset()
        self._state.shock_chain_links_left = 0
        self._state.shock_chain_projectile_id = -1
        self._beams.clear()
        self._effects.clear()
        self._creatures = [
            DummyCreature(pos=self._origin.offset(dx=180.0), hp=140.0, size=38.0),
            DummyCreature(pos=self._origin + Vec2(260.0, 40.0), hp=140.0, size=42.0),
            DummyCreature(pos=self._origin + Vec2(-220.0, 140.0), hp=140.0, size=52.0),
            DummyCreature(pos=self._origin + Vec2(-300.0, -120.0), hp=140.0, size=58.0),
        ]

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        projs_path = self._assets_root / "crimson" / "game" / "projs.png"
        if not projs_path.is_file():
            self._missing_assets.append("game/projs.png")
            raise FileNotFoundError(f"Missing asset: {projs_path}")
        self._projs = rl.load_texture(str(projs_path))

        particles_path = self._assets_root / "crimson" / "game" / "particles.png"
        if particles_path.is_file():
            self._particles = rl.load_texture(str(particles_path))
        else:
            self._particles = None
            self._missing_assets.append("game/particles.png")

        self.close_requested = False
        self._paused = False
        self._state.rng.srand(0xBEEF)
        self._reset_scene()

        self._camera = Vec2(-1.0, -1.0)

    def close(self) -> None:
        if self._projs is not None:
            rl.unload_texture(self._projs)
            self._projs = None
        if self._particles is not None:
            rl.unload_texture(self._particles)
            self._particles = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _selected_type_id(self) -> int:
        if not self._type_ids:
            return 0
        return int(self._type_ids[self._type_index % len(self._type_ids)])

    def _projectile_meta_for(self, type_id: int) -> float:
        entry = weapon_entry_for_projectile_type_id(int(type_id))
        meta = entry.projectile_meta if entry is not None else None
        return float(meta if meta is not None else 45.0)

    def _spawn_effect(self, *, effect_id: int, pos: Vec2, scale: float, duration: float) -> None:
        if self._particles is None:
            return
        self._effects.append(
            EffectFx(
                effect_id=int(effect_id),
                pos=pos,
                life=float(duration),
                rotation=float(int(self._state.rng.rand()) % 0x274) * 0.01,
                scale=float(scale),
            )
        )

    def _spawn_projectile(self, *, type_id: int, angle: float, owner_id: int = -100) -> None:
        meta = self._projectile_meta_for(type_id)
        self._spawn_effect(effect_id=int(EffectId.CASING), pos=self._origin, scale=0.55, duration=0.18)
        self._state.projectiles.spawn(
            pos=self._origin,
            angle=float(angle),
            type_id=int(type_id),
            owner_id=int(owner_id),
            base_damage=meta,
        )

    def _spawn_fire_bullets_volley(self, *, angle: float) -> None:
        base = weapon_entry_for_projectile_type_id(self._selected_type_id())
        pellet_count = int(getattr(base, "pellet_count", 1) or 1)
        pellet_count = max(1, pellet_count)
        meta = self._projectile_meta_for(ProjectileTypeId.FIRE_BULLETS)
        self._spawn_effect(effect_id=int(EffectId.CASING), pos=self._origin, scale=0.6, duration=0.2)
        for _ in range(pellet_count):
            jitter = (float(self._state.rng.rand() % 200) - 100.0) * 0.0015
            self._state.projectiles.spawn(
                pos=self._origin,
                angle=float(angle + jitter),
                type_id=ProjectileTypeId.FIRE_BULLETS,
                owner_id=-1,
                base_damage=meta,
            )

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._show_help = not self._show_help
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
            self._show_debug = not self._show_debug

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._reset_scene()

        wheel = int(rl.get_mouse_wheel_move())
        if wheel:
            self._type_index = (self._type_index - wheel) % max(1, len(self._type_ids))

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._type_index = (self._type_index - 1) % max(1, len(self._type_ids))
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._type_index = (self._type_index + 1) % max(1, len(self._type_ids))

        mouse = rl.get_mouse_position()
        aim = self._camera_screen_to_world(Vec2.from_xy(mouse))
        aim_delta = aim - self._origin
        angle = aim_delta.to_heading() if aim_delta.length_sq() > 1e-12 else math.pi / 2.0

        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT):
            self._origin = aim.clamp_rect(0.0, 0.0, WORLD_SIZE, WORLD_SIZE)

        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._spawn_projectile(type_id=self._selected_type_id(), angle=angle, owner_id=-1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            count = 12
            step = math.tau / float(count)
            for idx in range(count):
                self._spawn_projectile(
                    type_id=self._selected_type_id(),
                    angle=float(idx) * step,
                    owner_id=-1,
                )

        if rl.is_key_pressed(rl.KeyboardKey.KEY_F):
            self._spawn_fire_bullets_volley(angle=angle)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_S):
            self._player.pos = self._origin
            bonus_apply(self._state, self._player, BonusId.SHOCK_CHAIN, origin=self._player, creatures=self._creatures)

    def update(self, dt: float) -> None:
        self._handle_input()
        if self._paused:
            dt = 0.0

        if dt <= 0.0:
            return

        self._update_camera(dt)

        self._beams = [beam for beam in self._beams if beam.life > 0.0]
        for beam in self._beams:
            beam.life -= dt

        self._effects = [fx for fx in self._effects if fx.life > 0.0]
        for fx in self._effects:
            fx.life -= dt

        hits = self._state.projectiles.update(
            dt,
            self._creatures,
            world_size=WORLD_SIZE,
            damage_scale_by_type=self._damage_scale_by_type,
            detail_preset=5,
            rng=self._state.rng.rand,
            runtime_state=self._state,
        )
        for hit in hits:
            if int(hit.type_id) in _BEAM_TYPES:
                self._beams.append(BeamFx(start=hit.origin, end=hit.hit, life=0.08))
                self._spawn_effect(effect_id=int(EffectId.RING), pos=hit.hit, scale=0.9, duration=0.25)
            else:
                effect_id = (
                    int(EffectId.EXPLOSION_PUFF)
                    if int(hit.type_id) in (ProjectileTypeId.GAUSS_GUN, ProjectileTypeId.FIRE_BULLETS)
                    else int(EffectId.BURST)
                )
                self._spawn_effect(effect_id=effect_id, pos=hit.hit, scale=1.2, duration=0.35)

        self._creatures = [c for c in self._creatures if c.hp > 0.0]

    def _draw_atlas_sprite(
        self,
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        pos: Vec2,
        scale: float,
        rotation_rad: float = 0.0,
        tint: rl.Color = rl.WHITE,
    ) -> None:
        grid = max(1, int(grid))
        frame = max(0, int(frame))

        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        col = frame % grid
        row = frame // grid
        src = rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)

        w = cell_w * float(scale)
        h = cell_h * float(scale)
        dst = rl.Rectangle(float(pos.x), float(pos.y), w, h)
        origin = rl.Vector2(w * 0.5, h * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, float(rotation_rad * 57.29577951308232), tint)

    def _draw_projectile(self, proj: object) -> None:
        texture = self._projs
        if texture is None:
            return

        type_id = int(getattr(proj, "type_id", 0))
        mapping = _KNOWN_PROJ_FRAMES.get(type_id)
        proj_pos = getattr(proj, "pos", None)
        if not isinstance(proj_pos, Vec2):
            return
        screen_pos = self._camera_world_to_screen(proj_pos)

        if mapping is None:
            rl.draw_circle(int(screen_pos.x), int(screen_pos.y), 3.0, rl.Color(240, 220, 160, 255))
            if self._show_debug:
                rl.draw_text(f"{type_id:02x}", int(screen_pos.x) + 6, int(screen_pos.y) - 8, 10, UI_HINT_COLOR)
            return

        grid, frame = mapping
        life = float(getattr(proj, "life_timer", 0.0))
        angle = float(getattr(proj, "angle", 0.0))

        color = rl.Color(240, 220, 160, 255)
        if type_id in (ProjectileTypeId.ION_RIFLE, ProjectileTypeId.ION_MINIGUN, ProjectileTypeId.ION_CANNON):
            color = rl.Color(120, 200, 255, 255)
        elif type_id == ProjectileTypeId.FIRE_BULLETS:
            color = rl.Color(255, 170, 90, 255)
        elif type_id == ProjectileTypeId.SHRINKIFIER:
            color = rl.Color(160, 255, 170, 255)
        elif type_id == ProjectileTypeId.BLADE_GUN:
            color = rl.Color(240, 120, 255, 255)

        # Beam-style projectiles get a trail from origin to current position in the flight phase.
        if type_id in _BEAM_TYPES and life >= 0.4:
            proj_origin = getattr(proj, "origin", None)
            if not isinstance(proj_origin, Vec2):
                proj_origin = proj_pos
            beam = proj_pos - proj_origin
            direction, dist = beam.normalized_with_length()
            if dist > 1e-6:
                step = 14.0
                seg_count = max(1, int(dist // step) + 1)
                for idx in range(seg_count):
                    t = float(idx) / float(max(1, seg_count - 1))
                    trail_pos = proj_origin + direction * (dist * t)
                    px = trail_pos.x
                    py = trail_pos.y
                    alpha = int(220 * (1.0 - t * 0.75))
                    tint = rl.Color(color.r, color.g, color.b, alpha)
                    trail_screen = self._camera_world_to_screen(Vec2(px, py))
                    self._draw_atlas_sprite(
                        texture,
                        grid=grid,
                        frame=frame,
                        pos=trail_screen,
                        scale=0.55,
                        rotation_rad=angle,
                        tint=tint,
                    )
                return

        alpha = int(clamp(life / 0.4, 0.0, 1.0) * 255)
        tint = rl.Color(color.r, color.g, color.b, alpha)
        self._draw_atlas_sprite(
            texture, grid=grid, frame=frame, pos=screen_pos, scale=0.6, rotation_rad=angle, tint=tint
        )

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))
        if self._missing_assets and self._projs is None:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            draw_ui_text(self._small, message, Vec2(24, 24), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return

        # World bounds.
        world_min = self._camera_world_to_screen(Vec2())
        world_max = self._camera_world_to_screen(Vec2(WORLD_SIZE, WORLD_SIZE))
        rl.draw_rectangle_lines(
            int(world_min.x),
            int(world_min.y),
            int(world_max.x - world_min.x),
            int(world_max.y - world_min.y),
            rl.Color(40, 40, 55, 255),
        )

        # Spawn origin marker.
        origin_screen = self._camera_world_to_screen(self._origin)
        rl.draw_circle(int(origin_screen.x), int(origin_screen.y), 5.0, rl.Color(240, 200, 80, 255))
        rl.draw_circle_lines(int(origin_screen.x), int(origin_screen.y), 9.0, rl.Color(70, 70, 90, 255))

        # Creatures.
        for creature in self._creatures:
            screen_pos = self._camera_world_to_screen(creature.pos)
            color = rl.Color(220, 90, 90, 255) if not creature.plague_infected else rl.Color(240, 180, 90, 255)
            rl.draw_circle(int(screen_pos.x), int(screen_pos.y), float(creature.size * 0.5), color)
            rl.draw_circle_lines(
                int(screen_pos.x), int(screen_pos.y), float(creature.size * 0.5), rl.Color(40, 40, 55, 255)
            )

        # AOE rings for ion linger types.
        for proj in self._state.projectiles.iter_active():
            life = float(proj.life_timer)
            if life >= 0.4:
                continue
            if proj.type_id == ProjectileTypeId.ION_RIFLE:
                radius = 88.0
                color = rl.Color(120, 200, 255, 50)
            elif proj.type_id == ProjectileTypeId.ION_MINIGUN:
                radius = 60.0
                color = rl.Color(120, 200, 255, 40)
            elif proj.type_id == ProjectileTypeId.ION_CANNON:
                radius = 128.0
                color = rl.Color(120, 200, 255, 40)
            else:
                continue
            proj_screen = self._camera_world_to_screen(proj.pos)
            rl.draw_circle(int(proj_screen.x), int(proj_screen.y), radius, color)
            rl.draw_circle_lines(int(proj_screen.x), int(proj_screen.y), radius, rl.Color(120, 200, 255, 120))

        # Beam flashes from hit events.
        for beam in self._beams:
            t = clamp(beam.life / 0.08, 0.0, 1.0)
            alpha = int(200 * t)
            beam_start = self._camera_world_to_screen(beam.start)
            beam_end = self._camera_world_to_screen(beam.end)
            rl.draw_line_ex(
                beam_start.to_vector2(rl.Vector2),
                beam_end.to_vector2(rl.Vector2),
                2.0,
                rl.Color(150, 220, 255, alpha),
            )

        # Particle sprite effects.
        if self._particles is not None:
            for fx in self._effects:
                src = effect_src_rect(
                    fx.effect_id,
                    texture_width=float(self._particles.width),
                    texture_height=float(self._particles.height),
                )
                if src is None:
                    continue
                life = max(0.0, fx.life)
                alpha = int(clamp(life / 0.35, 0.0, 1.0) * 220)
                tint = rl.Color(255, 255, 255, alpha)
                screen_pos = self._camera_world_to_screen(fx.pos)
                dst_scale = fx.scale * (1.0 + (0.7 - clamp(life, 0.0, 0.7)) * 0.6)
                dst = rl.Rectangle(float(screen_pos.x), float(screen_pos.y), src[2] * dst_scale, src[3] * dst_scale)
                origin = rl.Vector2(dst.width * 0.5, dst.height * 0.5)
                rl.draw_texture_pro(
                    self._particles,
                    rl.Rectangle(float(src[0]), float(src[1]), float(src[2]), float(src[3])),
                    dst,
                    origin,
                    float(fx.rotation * 57.29577951308232),
                    tint,
                )

        # Projectiles.
        for proj in self._state.projectiles.iter_active():
            self._draw_projectile(proj)

        # UI.
        margin = 18
        x = float(margin)
        y = float(margin)
        line = ui_line_height(self._small, scale=UI_TEXT_SCALE)

        type_id = self._selected_type_id()
        weapon = WEAPON_BY_ID.get(int(type_id))
        label = weapon.name if weapon is not None and weapon.name else f"type_{type_id}"
        draw_ui_text(
            self._small,
            f"{label} (type_id {type_id} / 0x{type_id:02x})",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        y += line + 4

        if self._show_debug:
            meta = self._projectile_meta_for(type_id)
            dmg = self._damage_scale_by_type.get(type_id, 1.0)
            pellets = int(weapon.pellet_count) if weapon is not None and weapon.pellet_count is not None else 1
            draw_ui_text(
                self._small,
                f"meta {meta:.1f}  dmg_scale {dmg:.2f}  pellet_count {pellets}",
                Vec2(x, y),
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            y += line + 4
            draw_ui_text(
                self._small,
                f"shock_chain links {self._state.shock_chain_links_left}  proj {self._state.shock_chain_projectile_id}",
                Vec2(x, y),
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            y += line + 8

        if self._show_help:
            draw_ui_text(self._small, "controls:", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_ACCENT_COLOR)
            y += line + 2
            draw_ui_text(
                self._small,
                "- left/right: select projectile type",
                Vec2(x, y),
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            y += line + 2
            draw_ui_text(
                self._small, "- mouse wheel: select type", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR
            )
            y += line + 2
            draw_ui_text(
                self._small,
                "- LMB: spawn projectile toward mouse",
                Vec2(x, y),
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            y += line + 2
            draw_ui_text(self._small, "- RMB: move spawn origin", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR)
            y += line + 2
            draw_ui_text(self._small, "- space: spawn ring", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR)
            y += line + 2
            draw_ui_text(
                self._small,
                "- F: fire-bullets volley (uses pellet_count)",
                Vec2(x, y),
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            y += line + 2
            draw_ui_text(
                self._small, "- S: apply Shock Chain bonus", Vec2(x, y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR
            )
            y += line + 2
            draw_ui_text(
                self._small,
                "- R: reset  Tab: pause  H: hide help  F3: toggle debug",
                Vec2(x, y),
                scale=0.9,
                color=UI_HINT_COLOR,
            )


@register_view("projectile_fx", "Projectile FX lab")
def build_projectile_fx_view(ctx: ViewContext) -> View:
    return ProjectileFxView(ctx)
