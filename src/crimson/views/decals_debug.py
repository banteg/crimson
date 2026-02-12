from __future__ import annotations

from grim.color import RGBA
from grim.geom import Vec2

from dataclasses import dataclass
import json
import math
from pathlib import Path
import time

import pyray as rl

from crimson.creatures.anim import (
    creature_anim_advance_phase,
    creature_anim_select_frame,
    creature_corpse_frame_for_type,
)
from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureFlags, CreatureInit, CreatureTypeId, SpawnEnv
from crimson.effects import FxQueue, FxQueueRotated
from crimson.effects_atlas import EffectId
from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.render.terrain_fx import FxQueueTextures, bake_fx_queues
from grim.assets import resolve_asset_path
from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.terrain_render import GroundRenderer
from grim.view import View, ViewContext

from ..paths import default_runtime_dir
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view


UI_TEXT_SCALE = 1.0
UI_TEXT_DARK = rl.Color(30, 30, 30, 255)
UI_HINT_DARK = rl.Color(70, 70, 70, 255)
UI_TEXT_LIGHT = rl.Color(220, 220, 220, 255)
UI_HINT_LIGHT = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

BG_DARK = rl.Color(12, 12, 14, 255)
BG_LIGHT = rl.Color(235, 235, 235, 255)
GRID_COLOR = rl.Color(0, 0, 0, 20)

WORLD_SIZE = 1024.0


@dataclass(frozen=True, slots=True)
class _CreatureAnimInfo:
    base: int
    anim_rate: float
    mirror: bool


_CREATURE_ANIM: dict[CreatureTypeId, _CreatureAnimInfo] = {
    CreatureTypeId.ZOMBIE: _CreatureAnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: _CreatureAnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: _CreatureAnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: _CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: _CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: _CreatureAnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}

_CREATURE_ASSET: dict[CreatureTypeId, str] = {
    CreatureTypeId.ZOMBIE: "zombie",
    CreatureTypeId.LIZARD: "lizard",
    CreatureTypeId.ALIEN: "alien",
    CreatureTypeId.SPIDER_SP1: "spider_sp1",
    CreatureTypeId.SPIDER_SP2: "spider_sp2",
    CreatureTypeId.TROOPER: "trooper",
}


TERRAIN_TEXTURES: list[tuple[int, str]] = [
    (0, "ter/ter_q1_base.png"),
    (1, "ter/ter_q1_tex1.png"),
    (2, "ter/ter_q2_base.png"),
    (3, "ter/ter_q2_tex1.png"),
    (4, "ter/ter_q3_base.png"),
    (5, "ter/ter_q3_tex1.png"),
    (6, "ter/ter_q4_base.png"),
    (7, "ter/ter_q4_tex1.png"),
]


class DecalsDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self._terrain_textures: dict[int, rl.Texture] = {}
        self._creature_textures: dict[str, rl.Texture] = {}
        self._owned_textures: list[rl.Texture] = []

        self._fx_textures: FxQueueTextures | None = None
        self._ground: GroundRenderer | None = None
        self._camera = Vec2()
        self._light_mode = False

        self._terrain_seed = 0xBEEF
        self._terrain_pair = 0  # 0..3, maps to (0,1),(2,3),(4,5),(6,7)
        self._show_stamp_log = True
        self._frame = 0
        self._stamp_log_path: Path | None = None
        self._stamp_log_file = None

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos=Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5))
        self._creatures = CreaturePool()
        self._env = SpawnEnv(
            terrain_width=WORLD_SIZE,
            terrain_height=WORLD_SIZE,
            demo_mode_active=True,
            hardcore=False,
            difficulty_level=0,
        )

        self._fx_queue = FxQueue()
        self._fx_queue_rotated = FxQueueRotated()

    def _write_stamp_log(self, payload: dict) -> None:
        if self._stamp_log_file is None:
            return
        try:
            self._stamp_log_file.write(json.dumps(payload, sort_keys=True) + "\n")
            self._stamp_log_file.flush()
        except Exception:
            self._stamp_log_file = None

    def _load_runtime_config(self) -> tuple[float, float | None, float | None]:
        runtime_dir = default_runtime_dir()
        if runtime_dir.is_dir():
            try:
                cfg = ensure_crimson_cfg(runtime_dir)
                return (
                    float(cfg.texture_scale),
                    float(cfg.screen_width),
                    float(cfg.screen_height),
                )
            except Exception:
                return 1.0, None, None
        return 1.0, None, None

    def _apply_terrain_pair(self) -> None:
        if self._ground is None:
            return
        base_id = int(self._terrain_pair) * 2
        overlay_id = base_id + 1
        base = self._terrain_textures.get(base_id)
        overlay = self._terrain_textures.get(overlay_id)
        if base is None:
            return
        self._ground.texture = base
        self._ground.overlay = overlay
        self._ground.overlay_detail = overlay or base
        self._ground.schedule_generate(seed=int(self._terrain_seed), layers=3)

    def _clear_ground_light(self) -> None:
        ground = self._ground
        if ground is None:
            return
        ground.create_render_target()
        if ground.render_target is None:
            return
        rl.begin_texture_mode(ground.render_target)
        rl.clear_background(BG_LIGHT)
        rl.end_texture_mode()
        # GroundRenderer treats this as an internal invariant; set it for debug fills.
        ground._render_target_ready = True

    def _reset_ground(self) -> None:
        if self._ground is None:
            return
        if self._light_mode:
            self._clear_ground_light()
        else:
            self._apply_terrain_pair()

    def _view_params(self) -> tuple[Vec2, Vec2, Vec2]:
        ground = self._ground
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        if ground is None:
            return self._camera, Vec2(1.0, 1.0), out_size

        # Mirror GameWorld camera behavior (ground.draw uses the same clamp rules).
        cfg_w = ground.screen_width or out_size.x
        cfg_h = ground.screen_height or out_size.y
        if cfg_w > WORLD_SIZE:
            cfg_w = WORLD_SIZE
        if cfg_h > WORLD_SIZE:
            cfg_h = WORLD_SIZE

        camera = self._camera.clamp_rect(cfg_w - WORLD_SIZE, cfg_h - WORLD_SIZE, -1.0, -1.0)
        scale_x = out_size.x / cfg_w if cfg_w > 0 else 1.0
        scale_y = out_size.y / cfg_h if cfg_h > 0 else 1.0
        return camera, Vec2(scale_x, scale_y), Vec2(cfg_w, cfg_h)

    def _world_to_screen(self, pos: Vec2) -> Vec2:
        camera, view_scale, _ = self._view_params()
        return (pos + camera).mul_components(view_scale)

    def _screen_to_world(self, pos: Vec2) -> Vec2:
        camera, view_scale, _ = self._view_params()
        safe_scale = Vec2(
            view_scale.x if view_scale.x > 0.0 else 1.0,
            view_scale.y if view_scale.y > 0.0 else 1.0,
        )
        return pos.div_components(safe_scale) - camera

    def _world_scale(self) -> float:
        _camera, view_scale, _screen_size = self._view_params()
        return view_scale.avg_component()

    def _draw_grid(self) -> None:
        ground = self._ground
        if ground is None:
            return
        step = 64.0
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        camera, view_scale, screen_size = self._view_params()

        start_x = math.floor((-camera.x) / step) * step
        end_x = (-camera.x) + screen_size.x
        x = start_x
        while x <= end_x:
            line_start = Vec2(self._world_to_screen(Vec2(x, 0.0)).x, 0.0)
            line_end = Vec2(line_start.x, out_h)
            rl.draw_line(int(line_start.x), int(line_start.y), int(line_end.x), int(line_end.y), GRID_COLOR)
            x += step

        start_y = math.floor((-camera.y) / step) * step
        end_y = (-camera.y) + screen_size.y
        y = start_y
        while y <= end_y:
            line_start = Vec2(0.0, self._world_to_screen(Vec2(0.0, y)).y)
            line_end = Vec2(out_w, line_start.y)
            rl.draw_line(int(line_start.x), int(line_start.y), int(line_end.x), int(line_end.y), GRID_COLOR)
            y += step

    def _draw_creature_sprite(
        self,
        texture: rl.Texture,
        *,
        info: _CreatureAnimInfo,
        flags: CreatureFlags,
        phase: float,
        mirror_long: bool,
        world_pos: Vec2,
        rotation_rad: float,
        scale: float,
        size_scale: float,
        tint: rl.Color,
    ) -> None:
        frame, _, _ = creature_anim_select_frame(
            phase,
            base_frame=info.base,
            mirror_long=mirror_long,
            flags=flags,
        )
        grid = 8
        cell = float(texture.width) / grid if grid > 0 else float(texture.width)
        row = frame // grid
        col = frame % grid
        src = rl.Rectangle(float(col * cell), float(row * cell), float(cell), float(cell))
        screen_pos = self._world_to_screen(world_pos)
        width = cell * float(scale) * float(size_scale)
        height = cell * float(scale) * float(size_scale)
        dst = rl.Rectangle(screen_pos.x, screen_pos.y, float(width), float(height))
        origin = rl.Vector2(float(width) * 0.5, float(height) * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, math.degrees(float(rotation_rad)), tint)

    def _spawn_enemy(self, pos: Vec2) -> None:
        type_id = CreatureTypeId(int(self._state.rng.rand()) % 5)
        size = float(int(self._state.rng.rand()) % 30 + 40)
        move_speed = float(int(self._state.rng.rand()) % 30) * 0.05 + 1.0
        hp = float(int(self._state.rng.rand()) % 4 + 2)
        heading = float(int(self._state.rng.rand()) % 628) * 0.01
        init = CreatureInit(
            origin_template_id=-1,
            pos=pos,
            heading=heading,
            phase_seed=float(int(self._state.rng.rand()) & 0xFF),
            type_id=type_id,
            flags=CreatureFlags(0),
            ai_mode=0,
            health=hp,
            max_health=hp,
            move_speed=move_speed,
            reward_value=0.0,
            size=size,
            contact_damage=0.0,
            tint=(1.0, 1.0, 1.0, 1.0),
        )
        self._creatures.spawn_init(init, rand=self._state.rng.rand)

    def open(self) -> None:
        self._missing_assets.clear()
        self._owned_textures.clear()
        self._terrain_textures.clear()
        self._creature_textures.clear()
        self._fx_textures = None
        self._fx_queue.clear()
        self._fx_queue_rotated.clear()
        self._creatures.reset()

        self._small = load_small_font(self._assets_root, self._missing_assets)

        for terrain_id, rel_path in TERRAIN_TEXTURES:
            path = resolve_asset_path(self._assets_root, rel_path)
            if path is None:
                self._missing_assets.append(rel_path)
                continue
            texture = rl.load_texture(str(path))
            self._owned_textures.append(texture)
            self._terrain_textures[int(terrain_id)] = texture

        for asset in sorted(set(_CREATURE_ASSET.values())):
            rel_path = f"game/{asset}.png"
            path = resolve_asset_path(self._assets_root, rel_path)
            if path is None:
                self._missing_assets.append(rel_path)
                continue
            texture = rl.load_texture(str(path))
            self._owned_textures.append(texture)
            self._creature_textures[asset] = texture

        particles_path = resolve_asset_path(self._assets_root, "game/particles.png")
        if particles_path is None:
            self._missing_assets.append("game/particles.png")
        bodyset_path = resolve_asset_path(self._assets_root, "game/bodyset.png")
        if bodyset_path is None:
            self._missing_assets.append("game/bodyset.png")

        if self._missing_assets:
            raise FileNotFoundError(f"Missing assets: {', '.join(self._missing_assets)}")

        particles_tex = rl.load_texture(str(particles_path))
        bodyset_tex = rl.load_texture(str(bodyset_path))
        self._owned_textures.append(particles_tex)
        self._owned_textures.append(bodyset_tex)
        self._fx_textures = FxQueueTextures(particles=particles_tex, bodyset=bodyset_tex)

        texture_scale, screen_w, screen_h = self._load_runtime_config()
        base_id = self._terrain_pair * 2
        base = self._terrain_textures.get(base_id)
        overlay = self._terrain_textures.get(base_id + 1)
        if base is None:
            raise FileNotFoundError("Missing base terrain texture")

        self._ground = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=overlay or base,
            width=int(WORLD_SIZE),
            height=int(WORLD_SIZE),
            texture_scale=texture_scale,
            screen_width=screen_w,
            screen_height=screen_h,
        )
        self._reset_ground()
        self._camera = Vec2()
        self._frame = 0

        log_dir = Path("artifacts") / "debug"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_dir = Path("artifacts")
        self._stamp_log_path = log_dir / "decals_stamp_trace.jsonl"
        try:
            self._stamp_log_file = self._stamp_log_path.open("w", encoding="utf-8")
        except Exception:
            self._stamp_log_file = None

        # Spawn a few enemies near the center for immediate testing.
        for _ in range(6):
            ox = float(int(self._state.rng.rand()) % 200 - 100)
            oy = float(int(self._state.rng.rand()) % 200 - 100)
            self._spawn_enemy(Vec2(WORLD_SIZE * 0.5 + ox, WORLD_SIZE * 0.5 + oy))

    def close(self) -> None:
        if self._ground is not None and self._ground.render_target is not None:
            rl.unload_render_texture(self._ground.render_target)
            self._ground.render_target = None
        self._ground = None

        for texture in self._owned_textures:
            rl.unload_texture(texture)
        self._owned_textures.clear()
        self._terrain_textures.clear()
        self._creature_textures.clear()
        self._fx_textures = None

        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

        self._fx_queue.clear()
        self._fx_queue_rotated.clear()
        self._creatures.reset()
        if self._stamp_log_file is not None:
            try:
                self._stamp_log_file.close()
            except Exception:
                pass
            self._stamp_log_file = None

    def update(self, dt: float) -> None:
        self._frame += 1

        speed = 240.0
        movement = Vec2(
            float(rl.is_key_down(rl.KeyboardKey.KEY_A)) - float(rl.is_key_down(rl.KeyboardKey.KEY_D)),
            float(rl.is_key_down(rl.KeyboardKey.KEY_W)) - float(rl.is_key_down(rl.KeyboardKey.KEY_S)),
        )
        self._camera = self._camera + movement * (speed * dt)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_G):
            self._light_mode = not self._light_mode
            self._reset_ground()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_C):
            self._reset_ground()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._terrain_seed = int(rl.get_random_value(0, 0x7FFFFFFF))
            if not self._light_mode:
                self._apply_terrain_pair()
            else:
                self._clear_ground_light()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self._terrain_pair = int(rl.get_random_value(0, 3))
            if not self._light_mode:
                self._apply_terrain_pair()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_L):
            self._show_stamp_log = not self._show_stamp_log

        if self._ground is not None:
            texture_scale, screen_w, screen_h = self._load_runtime_config()
            self._ground.texture_scale = texture_scale
            self._ground.screen_width = screen_w
            self._ground.screen_height = screen_h
            self._ground.process_pending()
            self._ground.debug_log_stamps = self._show_stamp_log
            if self._show_stamp_log:
                self._ground.debug_clear_stamp_log()

        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT):
            mouse = rl.get_mouse_position()
            self._spawn_enemy(self._screen_to_world(Vec2.from_xy(mouse)))

        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            mouse = rl.get_mouse_position()
            click_pos = self._screen_to_world(Vec2.from_xy(mouse))
            hit = None
            for creature in self._creatures.entries:
                if not (creature.active and creature.hp > 0.0):
                    continue
                r = float(creature.size) * 0.35 + 12.0
                if Vec2.distance_sq(creature.pos, click_pos) <= r * r:
                    hit = creature
                    break
            if hit is not None:
                hit.hp -= 1.0
                self._fx_queue.add_random(pos=hit.pos, rand=self._state.rng.rand)
            else:
                # Paint blood directly for ground decal checks.
                self._fx_queue.add(
                    effect_id=int(EffectId.BLOOD_SPLATTER),
                    pos=click_pos,
                    width=30.0,
                    height=30.0,
                    rotation=0.0,
                    rgba=RGBA(1.0, 1.0, 1.0, 1.0),
                )

        # Keep the player fixed; creatures use it as a target for heading/movement.
        self._player.pos = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)
        self._player.health = 1e9

        creature_result = self._creatures.update(
            dt,
            state=self._state,
            players=[self._player],
            env=self._env,
            world_width=WORLD_SIZE,
            world_height=WORLD_SIZE,
            fx_queue=self._fx_queue,
            fx_queue_rotated=self._fx_queue_rotated,
        )
        del creature_result

        # Advance alive animation phase (CreaturePool intentionally does not).
        for creature in self._creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                continue
            info = _CREATURE_ANIM.get(type_id)
            if info is None:
                continue
            creature.anim_phase, _ = creature_anim_advance_phase(
                float(creature.anim_phase),
                anim_rate=info.anim_rate,
                move_speed=float(creature.move_speed),
                dt=dt,
                size=float(creature.size),
                local_scale=float(getattr(creature, "move_scale", 1.0)),
                flags=creature.flags,
                ai_mode=int(creature.ai_mode),
            )

        if self._ground is not None and self._fx_textures is not None:
            if self._fx_queue.count or self._fx_queue_rotated.count:
                fx_count = int(self._fx_queue.count)
                corpse_count = int(self._fx_queue_rotated.count)
                bake_fx_queues(
                    self._ground,
                    fx_queue=self._fx_queue,
                    fx_queue_rotated=self._fx_queue_rotated,
                    textures=self._fx_textures,
                    corpse_frame_for_type=creature_corpse_frame_for_type,
                    corpse_shadow=not self._light_mode,
                )
                if self._show_stamp_log:
                    stamp_log = self._ground.debug_stamp_log()
                    if stamp_log:
                        ts = time.time()
                        for idx, event in enumerate(stamp_log):
                            self._write_stamp_log(
                                {
                                    "ts": ts,
                                    "dt": dt,
                                    "frame": self._frame,
                                    "event_idx": idx,
                                    "queue": {"fx": fx_count, "corpse": corpse_count},
                                    **event,
                                }
                            )

    def draw(self) -> None:
        rl.clear_background(BG_LIGHT if self._light_mode else BG_DARK)

        if self._missing_assets:
            draw_ui_text(
                self._small,
                "Missing assets: " + ", ".join(self._missing_assets),
                Vec2(24, 24),
                scale=UI_TEXT_SCALE,
                color=UI_ERROR_COLOR,
            )
            return

        if self._ground is None:
            draw_ui_text(
                self._small, "Ground renderer not initialized.", Vec2(24, 24), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR
            )
            return

        self._ground.draw(self._camera)
        if self._light_mode:
            self._draw_grid()

        # Creatures (including death slide/fade stage).
        scale = self._world_scale()
        for creature in self._creatures.entries:
            if not creature.active:
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                continue
            asset = _CREATURE_ASSET.get(type_id)
            texture = self._creature_textures.get(asset) if asset is not None else None
            info = _CREATURE_ANIM.get(type_id)
            if texture is None or info is None:
                continue

            tint_rgba = creature.tint
            if float(creature.hitbox_size) < 0.0:
                tint_rgba = tint_rgba.with_alpha(max(0.0, tint_rgba.a + float(creature.hitbox_size) * 0.1))
            tint = tint_rgba.clamped().to_rl()

            flags = creature.flags
            long_strip = (flags & CreatureFlags.ANIM_PING_PONG) == 0 or (flags & CreatureFlags.ANIM_LONG_STRIP) != 0
            phase = float(creature.anim_phase)
            hitbox_size = float(creature.hitbox_size)
            if long_strip:
                if hitbox_size < 0.0:
                    phase = -1.0
                elif hitbox_size < 16.0:
                    phase = float(info.base + 0x0F) - hitbox_size - 0.5
            mirror_long = bool(info.mirror) and hitbox_size >= 16.0

            size_scale = max(0.25, min(float(creature.size) / 64.0, 2.0))
            self._draw_creature_sprite(
                texture,
                info=info,
                flags=flags,
                phase=phase,
                mirror_long=mirror_long,
                world_pos=creature.pos,
                rotation_rad=float(creature.heading) - math.pi / 2.0,
                scale=scale,
                size_scale=size_scale,
                tint=tint,
            )

        # UI overlay.
        text_color = UI_TEXT_DARK if self._light_mode else UI_TEXT_LIGHT
        hint_color = UI_HINT_DARK if self._light_mode else UI_HINT_LIGHT
        x = 16
        y = 12
        line = ui_line_height(self._small, scale=UI_TEXT_SCALE)
        draw_ui_text(self._small, "Decals debug", Vec2(x, y), scale=UI_TEXT_SCALE, color=text_color)
        y += line
        draw_ui_text(
            self._small,
            "LMB: blood / damage enemy   RMB: spawn enemy",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=hint_color,
        )
        y += line
        draw_ui_text(
            self._small,
            "WASD: pan   R: random seed   T: random terrain   G: toggle light grid   C: clear   L: stamp log",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=hint_color,
        )
        y += line
        draw_ui_text(
            self._small,
            f"enemies={len([c for c in self._creatures.entries if c.active])}",
            Vec2(x, y),
            scale=UI_TEXT_SCALE,
            color=hint_color,
        )
        y += line
        if self._stamp_log_path is not None:
            status = "on" if self._show_stamp_log else "off"
            draw_ui_text(
                self._small,
                f"stamp log ({status}): {self._stamp_log_path}",
                Vec2(x, y),
                scale=UI_TEXT_SCALE,
                color=hint_color,
            )
            y += line
        if self._ground is not None and self._show_stamp_log:
            stamp_log = self._ground.debug_stamp_log()
            if stamp_log:
                draw_ui_text(self._small, "stamp order:", Vec2(x, y), scale=UI_TEXT_SCALE, color=hint_color)
                y += line
                for event in stamp_log[-6:]:
                    kind = str(event.get("kind", "?"))
                    if kind == "bake_corpse_decals":
                        msg = f"{kind} shadow={event.get('shadow')} count={event.get('count')}"
                    elif kind == "bake_decals":
                        msg = f"{kind} count={event.get('count')}"
                    elif kind.endswith("_pass"):
                        msg = f"{kind} draws={event.get('draws')}"
                    else:
                        msg = kind
                    draw_ui_text(self._small, msg, Vec2(x, y), scale=UI_TEXT_SCALE, color=hint_color)
                    y += line


@register_view("decals", "Decals debug")
def build_decals_debug_view(ctx: ViewContext) -> View:
    return DecalsDebugView(ctx)
