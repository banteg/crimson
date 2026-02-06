from __future__ import annotations

import json
import math
import random
import os
from pathlib import Path
from dataclasses import dataclass

import pyray as rl

from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.math import clamp
from grim.view import ViewContext

from ..creatures.spawn import CreatureInit, CreatureTypeId
from ..game_world import GameWorld
from ..gameplay import PlayerInput
from ..paths import default_runtime_dir
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

_SDF_SHADOW_MAX_CIRCLES = 64
_SDF_SHADOW_MAX_STEPS = 64
_SDF_SHADOW_EPSILON = 0.25
_SDF_SHADOW_MIN_STEP = 0.25

_SDF_SHADOW_VS_330 = r"""
#version 330

in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;

out vec2 fragTexCoord;
out vec4 fragColor;

uniform mat4 mvp;

void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

_SDF_SHADOW_FS_330 = rf"""
#version 330

in vec2 fragTexCoord;
in vec4 fragColor;

out vec4 finalColor;

#define MAX_CIRCLES {_SDF_SHADOW_MAX_CIRCLES}

uniform vec2 u_resolution;
uniform vec4 u_light_color;
uniform vec2 u_light_pos;
uniform float u_light_range;
uniform float u_light_source_radius;
uniform float u_shadow_k;
uniform float u_shadow_floor;
uniform int u_debug_mode;
uniform int u_circle_count;
uniform vec4 u_circles[MAX_CIRCLES];

float map_skip(vec2 p, int skip_idx)
{{
    // Keep finite to avoid overflow in shadow math when there are no occluders
    // or when uniform data is missing.
    float d = 1e6;
    for (int i = 0; i < MAX_CIRCLES; i++)
    {{
        if (i >= u_circle_count) break;
        if (i == skip_idx) continue;
        vec4 c = u_circles[i];
        d = min(d, length(p - c.xy) - c.z);
    }}
    return d;
}}

float map_with_index(vec2 p, out int hit_idx)
{{
    float d = 1e6;
    hit_idx = -1;
    for (int i = 0; i < MAX_CIRCLES; i++)
    {{
        if (i >= u_circle_count) break;
        vec4 c = u_circles[i];
        float di = length(p - c.xy) - c.z;
        if (di < d)
        {{
            d = di;
            hit_idx = i;
        }}
    }}
    return d;
}}

// Raymarched SDF soft shadows (Inigo Quilez + Sebastian Aaltonen improvement).
// `u_shadow_k` behaves like the original `k` hardness parameter.
float softshadow(vec2 ro, vec2 rd, float mint, float maxt, float k, int skip_idx)
{{
    if (u_circle_count <= 0) return 1.0;
    float res = 1.0;
    float t = mint;
    float ph = 1e6;
    for (int i = 0; i < {_SDF_SHADOW_MAX_STEPS} && t < maxt; i++)
    {{
        float h = map_skip(ro + rd * t, skip_idx);
        if (h < {_SDF_SHADOW_EPSILON:.4f}) return 0.0;
        float y = h*h/(2.0*ph);
        float d = sqrt(max(0.0, h*h - y*y));
        res = min(res, k * d / max(0.001, t - y));
        ph = h;
        t += max(h, {_SDF_SHADOW_MIN_STEP:.4f});
    }}
    return clamp(res, 0.0, 1.0);
}}

void main()
{{
    // Match raylib 2D screen coords: origin top-left.
    vec2 p = vec2(gl_FragCoord.x, u_resolution.y - gl_FragCoord.y);

    if (u_debug_mode == 1)
    {{
        finalColor = vec4(1.0, 1.0, 1.0, 1.0);
        return;
    }}

    if (u_debug_mode == 2)
    {{
        vec2 uv = p / max(u_resolution, vec2(1.0));
        finalColor = vec4(uv.x, uv.y, 0.0, 1.0);
        return;
    }}

    vec2 to_light = u_light_pos - p;
    float dist = length(to_light);
    if (dist <= 1e-4 || dist > u_light_range)
    {{
        finalColor = vec4(0.0, 0.0, 0.0, 1.0);
        return;
    }}

    if (u_debug_mode == 3)
    {{
        finalColor = vec4(1.0, 1.0, 1.0, 1.0);
        return;
    }}

    float atten = 1.0 - clamp(dist / u_light_range, 0.0, 1.0);
    atten = atten * atten;

    if (u_debug_mode == 4)
    {{
        finalColor = vec4(vec3(atten), 1.0);
        return;
    }}

    int self_idx = -1;
    float d0 = map_with_index(p, self_idx);

    float k = u_shadow_k;
    // Heuristic: larger disc lights soften shadows.
    if (u_light_source_radius > 0.0)
    {{
        k = u_shadow_k / max(1.0, u_light_source_radius * 0.25);
    }}
    vec2 rd = to_light / max(dist, 1e-4);
    float maxt = max(0.0, dist - max(0.0, u_light_source_radius));
    float shadow = 0.0;
    if (d0 >= 0.0)
    {{
        shadow = softshadow(p, rd, 0.5, maxt, k, -1);
    }}

    float a = 1.0 - clamp(dist / u_light_range, 0.0, 1.0);
    float floor = clamp(u_shadow_floor, 0.0, 1.0);
    float fill = min(floor * a, atten);
    float shade = mix(fill, atten, shadow);

    if (u_debug_mode == 5)
    {{
        finalColor = vec4(vec3(shade), 1.0);
        return;
    }}

    vec3 add = u_light_color.rgb * shade;
    finalColor = vec4(clamp(add, 0.0, 1.0), 1.0);
}}
"""


@dataclass
class _EmissiveProjectile:
    x: float
    y: float
    vx: float
    vy: float
    age: float
    ttl: float


@dataclass
class _FlyingLight:
    x: float
    y: float
    angle: float
    radius: float
    omega: float
    range: float
    source_radius: float
    color: rl.Color


class LightingDebugView:
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

        self.close_requested = False

        self._ui_mouse_x = 0.0
        self._ui_mouse_y = 0.0

        self._simulate = True
        self._draw_debug = True
        self._draw_occluders = False
        self._debug_lightmap_preview = False
        self._debug_dump_next_frame = False
        self._debug_dump_count = 0
        self._debug_auto_dump = os.environ.get("CRIMSON_LIGHTING_DEBUG_AUTODUMP", "0") not in ("", "0", "false", "False")

        self._sdf_shadow_k = 12.0
        self._sdf_shadow_floor = 0.25
        try:
            self._sdf_debug_mode = int(os.environ.get("CRIMSON_LIGHTING_SDF_DEBUG_MODE", "0"))
        except Exception:
            self._sdf_debug_mode = 0

        self._light_radius = 360.0
        self._light_source_radius = 14.0
        self._ambient_base = rl.Color(26, 26, 34, 255)
        self._ambient_mul = 1.0
        self._ambient = rl.Color(26, 26, 34, 255)
        self._light_tint = rl.Color(255, 245, 220, 255)
        self._cursor_light_enabled = True

        self._last_sdf_circles: list[tuple[float, float, float]] = []
        self._occluder_radius_mul = 0.25
        self._occluder_radius_pad_px = 0.0

        self._projectiles: list[_EmissiveProjectile] = []
        self._proj_fire_cd = 0.0
        self._proj_fire_interval = 0.08
        self._proj_speed = 350.0
        self._proj_ttl = 1.25
        self._proj_radius_px = 3.0
        self._proj_light_range = 220.0
        self._proj_light_source_radius = 10.0
        self._proj_light_tint = rl.Color(255, 190, 140, 255)
        self._max_projectiles = 128
        self._max_projectile_lights = 16

        self._fly_lights_enabled = False
        self._fly_lights: list[_FlyingLight] = []
        self._fly_light_count = 6
        self._fly_light_range = 320.0
        self._fly_light_source_radius = 18.0

        self._sdf_shader: rl.Shader | None = None
        self._sdf_shader_tried: bool = False
        self._sdf_shader_locs: dict[str, int] = {}
        self._sdf_shader_missing: list[str] = []
        self._light_rt: rl.RenderTexture | None = None
        self._solid_white: rl.Texture | None = None

        self._update_ambient()

    def _update_ambient(self) -> None:
        base = self._ambient_base
        m = max(0.0, float(self._ambient_mul))
        self._ambient = rl.Color(
            int(clamp(float(base.r) * m, 0.0, 255.0)),
            int(clamp(float(base.g) * m, 0.0, 255.0)),
            int(clamp(float(base.b) * m, 0.0, 255.0)),
            255,
        )

    def _spawn_fly_lights(self, *, seed: int) -> None:
        if self._player is None:
            return
        rng = random.Random(int(seed))
        palette = [
            rl.Color(120, 220, 255, 255),
            rl.Color(255, 110, 200, 255),
            rl.Color(140, 255, 160, 255),
            rl.Color(255, 220, 120, 255),
            rl.Color(180, 140, 255, 255),
            rl.Color(255, 160, 90, 255),
        ]
        px = float(self._player.pos.x)
        py = float(self._player.pos.y)
        self._fly_lights.clear()
        for i in range(int(self._fly_light_count)):
            angle = rng.random() * math.tau
            radius = 160.0 + rng.random() * 260.0
            omega = (0.8 + rng.random() * 1.6) * (-1.0 if (i % 2) else 1.0)
            c = palette[i % len(palette)]
            if rng.random() < 0.5:
                c = palette[int(rng.random() * len(palette)) % len(palette)]
            x = clamp(px + math.cos(angle) * radius, 0.0, WORLD_SIZE)
            y = clamp(py + math.sin(angle) * radius, 0.0, WORLD_SIZE)
            r = float(self._fly_light_range) * (0.8 + rng.random() * 0.5)
            sr = float(self._fly_light_source_radius) * (0.7 + rng.random() * 0.7)
            self._fly_lights.append(
                _FlyingLight(
                    x=float(x),
                    y=float(y),
                    angle=float(angle),
                    radius=float(radius),
                    omega=float(omega),
                    range=float(r),
                    source_radius=float(sr),
                    color=c,
                )
            )

    def _update_ui_mouse(self) -> None:
        if self._debug_auto_dump:
            return
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        self._ui_mouse_x = clamp(float(mouse.x), 0.0, max(0.0, screen_w - 1.0))
        self._ui_mouse_y = clamp(float(mouse.y), 0.0, max(0.0, screen_h - 1.0))

    def _handle_debug_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._simulate = not self._simulate

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._draw_debug = not self._draw_debug
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._draw_occluders = not self._draw_occluders
        if rl.is_key_pressed(rl.KeyboardKey.KEY_THREE):
            self._cursor_light_enabled = not self._cursor_light_enabled
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FIVE):
            self._fly_lights_enabled = not self._fly_lights_enabled
            if self._fly_lights_enabled and not self._fly_lights:
                self._spawn_fly_lights(seed=0xF17_0BEE)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._debug_lightmap_preview = not self._debug_lightmap_preview
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F5):
            self._debug_dump_next_frame = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_F6):
            self._sdf_debug_mode = (self._sdf_debug_mode + 1) % 6

        shift = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
        occ_mul_step = 0.05 if not shift else 0.10
        occ_pad_step = 1.0 if not shift else 4.0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_O):
            self._occluder_radius_mul = clamp(self._occluder_radius_mul - occ_mul_step, 0.25, 2.50)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._occluder_radius_mul = clamp(self._occluder_radius_mul + occ_mul_step, 0.25, 2.50)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_K):
            self._occluder_radius_pad_px = clamp(self._occluder_radius_pad_px - occ_pad_step, -20.0, 60.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_L):
            self._occluder_radius_pad_px = clamp(self._occluder_radius_pad_px + occ_pad_step, -20.0, 60.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_MINUS) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_SUBTRACT):
            self._sdf_shadow_floor = clamp(self._sdf_shadow_floor - 0.05, 0.0, 0.9)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EQUAL) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ADD):
            self._sdf_shadow_floor = clamp(self._sdf_shadow_floor + 0.05, 0.0, 0.9)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            if shift:
                self._light_radius = max(80.0, self._light_radius - 20.0)
            else:
                self._light_source_radius = max(1.0, self._light_source_radius - 2.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            if shift:
                self._light_radius = min(1200.0, self._light_radius + 20.0)
            else:
                self._light_source_radius = min(80.0, self._light_source_radius + 2.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_COMMA):
            self._sdf_shadow_k = max(1.0, self._sdf_shadow_k / 1.25)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD):
            self._sdf_shadow_k = min(512.0, self._sdf_shadow_k * 1.25)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._reset_scene(seed=0xBEEF)

        amb_step = 0.10 if not shift else 0.25
        if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
            self._ambient_mul = clamp(self._ambient_mul - amb_step, 0.0, 8.0)
            self._update_ambient()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
            self._ambient_mul = clamp(self._ambient_mul + amb_step, 0.0, 8.0)
            self._update_ambient()

    def _ensure_sdf_shader(self) -> rl.Shader | None:
        if (
            self._sdf_shader is not None
            and int(getattr(self._sdf_shader, "id", 0)) > 0
            and rl.is_shader_valid(self._sdf_shader)
        ):
            return self._sdf_shader
        if self._sdf_shader_tried:
            return None
        self._sdf_shader_tried = True

        try:
            # Prefer raylib's default vertex shader to avoid attribute binding
            # mismatches across platforms/backends.
            shader = rl.load_shader_from_memory(None, _SDF_SHADOW_FS_330)
        except Exception:
            try:
                shader = rl.load_shader_from_memory(_SDF_SHADOW_VS_330, _SDF_SHADOW_FS_330)
            except Exception:
                self._sdf_shader = None
                return None

        if int(getattr(shader, "id", 0)) <= 0 or not rl.is_shader_valid(shader):
            self._sdf_shader = None
            return None

        self._sdf_shader = shader

        circles_loc = rl.get_shader_location(shader, "u_circles")
        if circles_loc < 0:
            circles_loc = rl.get_shader_location(shader, "u_circles[0]")

        self._sdf_shader_locs = {
            "u_resolution": rl.get_shader_location(shader, "u_resolution"),
            "u_light_color": rl.get_shader_location(shader, "u_light_color"),
            "u_light_pos": rl.get_shader_location(shader, "u_light_pos"),
            "u_light_range": rl.get_shader_location(shader, "u_light_range"),
            "u_light_source_radius": rl.get_shader_location(shader, "u_light_source_radius"),
            "u_shadow_k": rl.get_shader_location(shader, "u_shadow_k"),
            "u_shadow_floor": rl.get_shader_location(shader, "u_shadow_floor"),
            "u_debug_mode": rl.get_shader_location(shader, "u_debug_mode"),
            "u_circle_count": rl.get_shader_location(shader, "u_circle_count"),
            "u_circles": circles_loc,
        }
        self._sdf_shader_missing = [name for name, loc in self._sdf_shader_locs.items() if loc < 0]

        return self._sdf_shader

    def _ensure_render_target(self, rt: rl.RenderTexture | None, w: int, h: int) -> rl.RenderTexture:
        if rt is not None and int(getattr(rt, "id", 0)) > 0:
            if int(getattr(getattr(rt, "texture", None), "width", 0)) == w and int(getattr(getattr(rt, "texture", None), "height", 0)) == h:
                return rt
            rl.unload_render_texture(rt)
        return rl.load_render_texture(w, h)

    def _ensure_render_targets(self) -> None:
        w = int(max(1, rl.get_screen_width()))
        h = int(max(1, rl.get_screen_height()))
        self._light_rt = self._ensure_render_target(self._light_rt, w, h)

    def _reset_scene(self, *, seed: int) -> None:
        self._world.reset(seed=int(seed), player_count=1)
        self._player = self._world.players[0] if self._world.players else None
        self._world.update_camera(0.0)
        self._projectiles.clear()
        self._proj_fire_cd = 0.0
        self._cursor_light_enabled = True
        self._ambient_mul = 1.0
        self._update_ambient()
        if self._fly_lights_enabled:
            self._spawn_fly_lights(seed=int(seed) ^ 0xF17_0BEE)
        else:
            self._fly_lights.clear()

        rng = random.Random(int(seed))
        if self._player is None:
            return
        center_x = float(self._player.pos.x)
        center_y = float(self._player.pos.y)

        self._world.creatures.reset()
        types = [
            CreatureTypeId.ZOMBIE,
            CreatureTypeId.ALIEN,
            CreatureTypeId.SPIDER_SP1,
            CreatureTypeId.LIZARD,
        ]
        for idx in range(20):
            t = types[idx % len(types)]
            angle = rng.random() * math.tau
            radius = 120.0 + rng.random() * 260.0
            x = center_x + math.cos(angle) * radius
            y = center_y + math.sin(angle) * radius
            x = clamp(x, 40.0, WORLD_SIZE - 40.0)
            y = clamp(y, 40.0, WORLD_SIZE - 40.0)
            init = CreatureInit(
                origin_template_id=0,
                pos=Vec2(float(x), float(y)),
                heading=float(rng.random() * math.tau),
                phase_seed=float(rng.random() * 999.0),
                type_id=t,
                health=80.0,
                max_health=80.0,
                move_speed=1.0,
                reward_value=0.0,
                size=48.0 + rng.random() * 18.0,
                contact_damage=0.0,
            )
            self._world.creatures.spawn_init(init, rand=self._world.state.rng.rand)

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        runtime_dir = default_runtime_dir()
        if runtime_dir.is_dir():
            try:
                self._world.config = ensure_crimson_cfg(runtime_dir)
            except Exception:
                self._world.config = None
        else:
            self._world.config = None

        self._world.open()
        self._reset_scene(seed=0xBEEF)
        self._ensure_render_targets()

        try:
            img = rl.gen_image_color(1, 1, rl.WHITE)
            self._solid_white = rl.load_texture_from_image(img)
            rl.unload_image(img)
        except Exception:
            self._solid_white = None

        self._ui_mouse_x = float(rl.get_screen_width()) * 0.5
        self._ui_mouse_y = float(rl.get_screen_height()) * 0.5
        if self._debug_auto_dump:
            self._debug_dump_next_frame = True

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._sdf_shader is not None and int(getattr(self._sdf_shader, "id", 0)) > 0:
            rl.unload_shader(self._sdf_shader)
            self._sdf_shader = None
            self._sdf_shader_locs.clear()
            self._sdf_shader_missing.clear()
        if self._light_rt is not None and int(getattr(self._light_rt, "id", 0)) > 0:
            rl.unload_render_texture(self._light_rt)
            self._light_rt = None
        if self._solid_white is not None and int(getattr(self._solid_white, "id", 0)) > 0:
            rl.unload_texture(self._solid_white)
            self._solid_white = None
        self._world.close()

    def update(self, dt: float) -> None:
        dt_frame = float(dt)
        self._update_ui_mouse()
        self._handle_debug_input()

        aim_x, aim_y = self._world.screen_to_world(self._ui_mouse_x, self._ui_mouse_y)
        if self._player is not None:
            self._player.aim_x = float(aim_x)
            self._player.aim_y = float(aim_y)

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

        dt_world = dt_frame if self._simulate else 0.0
        self._world.update(
            dt_world,
            inputs=[
                PlayerInput(
                    move_x=move_x,
                    move_y=move_y,
                    aim_x=float(aim_x),
                    aim_y=float(aim_y),
                    fire_down=False,
                    fire_pressed=False,
                    reload_pressed=False,
                )
            ],
            auto_pick_perks=False,
            perk_progression_enabled=False,
        )

        if not self._debug_auto_dump and rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._proj_fire_cd -= dt_frame
            while self._proj_fire_cd <= 0.0:
                self._spawn_projectile(aim_x=float(aim_x), aim_y=float(aim_y))
                self._proj_fire_cd += float(self._proj_fire_interval)
        else:
            self._proj_fire_cd = max(0.0, self._proj_fire_cd - dt_frame)

        if dt_world > 0.0:
            if self._fly_lights_enabled and self._fly_lights and self._player is not None:
                px = float(self._player.pos.x)
                py = float(self._player.pos.y)
                for fl in self._fly_lights:
                    fl.angle += fl.omega * dt_world
                    wobble = 1.0 + 0.10 * math.sin(fl.angle * 0.7)
                    r = fl.radius * wobble
                    fl.x = clamp(px + math.cos(fl.angle) * r, 0.0, WORLD_SIZE)
                    fl.y = clamp(py + math.sin(fl.angle) * r, 0.0, WORLD_SIZE)

            keep: list[_EmissiveProjectile] = []
            margin = 80.0
            for proj in self._projectiles:
                proj.age += dt_world
                proj.x += proj.vx * dt_world
                proj.y += proj.vy * dt_world
                if proj.age >= proj.ttl:
                    continue
                if proj.x < -margin or proj.x > WORLD_SIZE + margin or proj.y < -margin or proj.y > WORLD_SIZE + margin:
                    continue
                keep.append(proj)
            self._projectiles = keep[-self._max_projectiles :]

    def _spawn_projectile(self, *, aim_x: float, aim_y: float) -> None:
        if self._player is None:
            return
        px = float(self._player.pos.x)
        py = float(self._player.pos.y)
        dx = float(aim_x) - px
        dy = float(aim_y) - py
        d = math.hypot(dx, dy)
        if d <= 1e-3:
            dx = 1.0
            dy = 0.0
            d = 1.0
        dx /= d
        dy /= d
        muzzle = 18.0
        x = px + dx * muzzle
        y = py + dy * muzzle
        speed = float(self._proj_speed)
        self._projectiles.append(
            _EmissiveProjectile(
                x=float(x),
                y=float(y),
                vx=float(dx) * speed,
                vy=float(dy) * speed,
                age=0.0,
                ttl=float(self._proj_ttl),
            )
        )

    def _dump_debug(self, *, light_x: float, light_y: float, sdf_ok: bool) -> None:
        if self._light_rt is None:
            return
        out_dir = Path("artifacts") / "lighting-debug"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            return

        self._debug_dump_count += 1
        prefix = f"{self._debug_dump_count:04d}"

        w = int(self._light_rt.texture.width)
        h = int(self._light_rt.texture.height)

        # Lightmap readback + samples.
        lightmap_path = out_dir / f"{prefix}_lightmap.png"
        samples: dict[str, list[int]] = {}
        approx_min_rgb = [255, 255, 255]
        approx_max_rgb = [0, 0, 0]
        try:
            img = rl.load_image_from_texture(self._light_rt.texture)
            rl.export_image(img, str(lightmap_path))

            iw = int(img.width)
            ih = int(img.height)

            def sample(x: float, y: float) -> list[int]:
                xi = max(0, min(iw - 1, int(x)))
                yi = max(0, min(ih - 1, int(y)))
                c = rl.get_image_color(img, xi, yi)
                return [int(c.r), int(c.g), int(c.b), int(c.a)]

            samples["light_xy"] = sample(light_x, light_y)
            samples["light_xy_flip_y"] = sample(light_x, float(ih - 1) - light_y)
            samples["center"] = sample(float(iw) * 0.5, float(ih) * 0.5)
            samples["center_flip_y"] = sample(float(iw) * 0.5, float(ih - 1) - float(ih) * 0.5)
            samples["tl"] = sample(0.0, 0.0)
            samples["bl"] = sample(0.0, float(ih - 1))

            step_x = max(1, iw // 32)
            step_y = max(1, ih // 32)
            for y in range(0, ih, step_y):
                for x in range(0, iw, step_x):
                    c = rl.get_image_color(img, x, y)
                    approx_min_rgb[0] = min(approx_min_rgb[0], int(c.r))
                    approx_min_rgb[1] = min(approx_min_rgb[1], int(c.g))
                    approx_min_rgb[2] = min(approx_min_rgb[2], int(c.b))
                    approx_max_rgb[0] = max(approx_max_rgb[0], int(c.r))
                    approx_max_rgb[1] = max(approx_max_rgb[1], int(c.g))
                    approx_max_rgb[2] = max(approx_max_rgb[2], int(c.b))

            rl.unload_image(img)
        except Exception:
            pass

        # Full-screen screenshot (after the frame is drawn).
        screenshot_path = out_dir / f"{prefix}_screen.png"
        fallback = Path.cwd() / screenshot_path.name
        try:
            if screenshot_path.exists():
                screenshot_path.unlink()
        except Exception:
            pass
        try:
            if fallback.exists():
                fallback.unlink()
        except Exception:
            pass
        try:
            rl.take_screenshot(str(screenshot_path))
        except Exception:
            pass
        if fallback.exists():
            try:
                fallback.replace(screenshot_path)
            except Exception:
                pass

        lt = self._light_tint
        builtin_locs: dict[str, int | None] = {}
        if self._sdf_shader is not None:
            try:
                locs = self._sdf_shader.locs
                builtin_locs = {
                    "map_diffuse": int(locs[rl.SHADER_LOC_MAP_DIFFUSE]),
                    "map_normal": int(locs[rl.SHADER_LOC_MAP_NORMAL]),
                    "vector_view": int(locs[rl.SHADER_LOC_VECTOR_VIEW]),
                    "matrix_mvp": int(locs[rl.SHADER_LOC_MATRIX_MVP]),
                    "matrix_model": int(locs[rl.SHADER_LOC_MATRIX_MODEL]),
                    "matrix_view": int(locs[rl.SHADER_LOC_MATRIX_VIEW]),
                    "matrix_projection": int(locs[rl.SHADER_LOC_MATRIX_PROJECTION]),
                    "color_diffuse": int(locs[rl.SHADER_LOC_COLOR_DIFFUSE]),
                    "color_ambient": int(locs[rl.SHADER_LOC_COLOR_AMBIENT]),
                    "color_specular": int(locs[rl.SHADER_LOC_COLOR_SPECULAR]),
                }
            except Exception:
                builtin_locs = {}
        stats = {
            "sdf_ok": bool(sdf_ok),
            "screen_size": [int(rl.get_screen_width()), int(rl.get_screen_height())],
            "light_rt_size": [w, h],
            "light_pos": [float(light_x), float(light_y)],
            "light_radius": float(self._light_radius),
            "light_source_radius": float(self._light_source_radius),
            "light_tint_rgba": [int(lt.r), int(lt.g), int(lt.b), int(lt.a)],
            "ambient_rgba": [int(self._ambient.r), int(self._ambient.g), int(self._ambient.b), int(self._ambient.a)],
            "ambient_mul": float(self._ambient_mul),
            "cursor_light_enabled": bool(self._cursor_light_enabled),
            "fly_lights_enabled": bool(self._fly_lights_enabled),
            "fly_light_count": int(len(self._fly_lights)),
            "shadow_k": float(self._sdf_shadow_k),
            "shadow_floor": float(self._sdf_shadow_floor),
            "occluder_radius_mul": float(self._occluder_radius_mul),
            "occluder_radius_pad_px": float(self._occluder_radius_pad_px),
            "debug_mode": int(self._sdf_debug_mode),
            "circle_count": int(len(self._last_sdf_circles)),
            "circles": [[float(x), float(y), float(r)] for (x, y, r) in self._last_sdf_circles[:16]],
            "projectile_count": int(len(self._projectiles)),
            "shader_uniform_locs": dict(self._sdf_shader_locs),
            "shader_uniform_missing": list(self._sdf_shader_missing),
            "shader_builtin_locs": builtin_locs,
            "lightmap_samples_rgba": samples,
            "lightmap_approx_min_rgb": approx_min_rgb,
            "lightmap_approx_max_rgb": approx_max_rgb,
            "paths": {"lightmap": str(lightmap_path), "screenshot": str(screenshot_path)},
        }
        stats_path = out_dir / f"{prefix}_stats.json"
        try:
            stats_path.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception:
            pass

    def _render_lightmap_sdf(self, *, light_x: float, light_y: float) -> bool:
        if self._light_rt is None:
            return False
        shader = self._ensure_sdf_shader()
        if shader is None:
            return False

        locs = self._sdf_shader_locs

        w = float(self._light_rt.texture.width)
        h = float(self._light_rt.texture.height)
        _cam_x, _cam_y, scale_x, scale_y = self._world.renderer._world_params()
        scale = (scale_x + scale_y) * 0.5

        def occ_radius(size: float) -> float:
            r = float(size) * 0.5 * scale
            r = r * float(self._occluder_radius_mul) + float(self._occluder_radius_pad_px)
            return max(1.0, r)

        circles: list[tuple[float, float, float]] = []

        if self._player is not None:
            px, py = self._world.world_to_screen(float(self._player.pos.x), float(self._player.pos.y))
            pr = occ_radius(float(self._player.size))
            circles.append((float(px), float(py), float(pr)))

        for creature in self._world.creatures.entries:
            if not creature.active:
                continue
            sx, sy = self._world.world_to_screen(float(creature.pos.x), float(creature.pos.y))
            cr = occ_radius(float(creature.size))
            circles.append((float(sx), float(sy), float(cr)))

        if len(circles) > _SDF_SHADOW_MAX_CIRCLES:
            circles = circles[:_SDF_SHADOW_MAX_CIRCLES]
        self._last_sdf_circles = circles

        def set_vec2(name: str, x: float, y: float) -> None:
            loc = locs.get(name, -1)
            if loc < 0:
                return
            buf = rl.ffi.new("float[2]", [float(x), float(y)])
            rl.set_shader_value(shader, loc, rl.ffi.cast("float *", buf), rl.SHADER_UNIFORM_VEC2)

        def set_vec4(name: str, x: float, y: float, z: float, q: float) -> None:
            loc = locs.get(name, -1)
            if loc < 0:
                return
            buf = rl.ffi.new("float[4]", [float(x), float(y), float(z), float(q)])
            rl.set_shader_value(shader, loc, rl.ffi.cast("float *", buf), rl.SHADER_UNIFORM_VEC4)

        def set_float(name: str, value: float) -> None:
            loc = locs.get(name, -1)
            if loc < 0:
                return
            rl.set_shader_value(shader, loc, rl.ffi.new("float *", float(value)), rl.SHADER_UNIFORM_FLOAT)

        def set_int(name: str, value: int) -> None:
            loc = locs.get(name, -1)
            if loc < 0:
                return
            rl.set_shader_value(shader, loc, rl.ffi.new("int *", int(value)), rl.SHADER_UNIFORM_INT)

        rl.begin_texture_mode(self._light_rt)
        rl.clear_background(self._ambient)
        # Ensure 2D lightmap passes are not affected by whatever depth state the
        # world renderer left behind.
        rl.rl_disable_depth_test()
        rl.rl_disable_depth_mask()
        rl.begin_shader_mode(shader)
        set_vec2("u_resolution", w, h)
        set_float("u_shadow_k", float(self._sdf_shadow_k))
        set_float("u_shadow_floor", float(self._sdf_shadow_floor))
        set_int("u_debug_mode", int(self._sdf_debug_mode))

        set_int("u_circle_count", len(circles))
        circles_loc = locs.get("u_circles", -1)
        if circles and circles_loc >= 0:
            flat: list[float] = []
            for cx, cy, cr in circles:
                flat.extend((float(cx), float(cy), float(cr), 1.0))
            buf = rl.ffi.new("float[]", flat)
            rl.set_shader_value_v(
                shader,
                circles_loc,
                rl.ffi.cast("float *", buf),
                rl.SHADER_UNIFORM_VEC4,
                len(circles),
            )
        rl.begin_blend_mode(rl.BLEND_ADDITIVE)

        lights: list[tuple[float, float, float, float, float, float, float]] = []

        def cursor_light() -> tuple[float, float, float, float, float, float, float]:
            lt = self._light_tint
            return (
                float(light_x),
                float(light_y),
                float(self._light_radius),
                float(self._light_source_radius),
                float(lt.r) / 255.0,
                float(lt.g) / 255.0,
                float(lt.b) / 255.0,
            )

        def proj_light(proj: _EmissiveProjectile) -> tuple[float, float, float, float, float, float, float]:
            sx, sy = self._world.world_to_screen(float(proj.x), float(proj.y))
            fade = clamp(1.0 - float(proj.age) / max(0.001, float(proj.ttl)), 0.0, 1.0)
            pr = self._proj_light_tint
            return (
                float(sx),
                float(sy),
                float(self._proj_light_range),
                float(self._proj_light_source_radius),
                float(pr.r) / 255.0 * fade,
                float(pr.g) / 255.0 * fade,
                float(pr.b) / 255.0 * fade,
            )

        if self._sdf_debug_mode != 0:
            if self._cursor_light_enabled:
                lights.append(cursor_light())
            elif self._projectiles:
                lights.append(proj_light(self._projectiles[-1]))
            elif self._fly_lights_enabled and self._fly_lights:
                fl = self._fly_lights[0]
                sx, sy = self._world.world_to_screen(float(fl.x), float(fl.y))
                c = fl.color
                lights.append(
                    (
                        float(sx),
                        float(sy),
                        float(fl.range),
                        float(fl.source_radius),
                        float(c.r) / 255.0,
                        float(c.g) / 255.0,
                        float(c.b) / 255.0,
                    )
                )
            else:
                # Debug mode still needs a pass to visualize shader output.
                lights.append(cursor_light())
        else:
            if self._cursor_light_enabled:
                lights.append(cursor_light())
            if self._projectiles:
                for proj in self._projectiles[-self._max_projectile_lights :]:
                    lights.append(proj_light(proj))
            if self._fly_lights_enabled and self._fly_lights:
                for fl in self._fly_lights[:12]:
                    sx, sy = self._world.world_to_screen(float(fl.x), float(fl.y))
                    c = fl.color
                    lights.append(
                        (
                            float(sx),
                            float(sy),
                            float(fl.range),
                            float(fl.source_radius),
                            float(c.r) / 255.0,
                            float(c.g) / 255.0,
                            float(c.b) / 255.0,
                        )
                    )

        def draw_fullscreen() -> None:
            if self._solid_white is not None and int(getattr(self._solid_white, "id", 0)) > 0:
                src = rl.Rectangle(0.0, 0.0, float(self._solid_white.width), float(self._solid_white.height))
                dst = rl.Rectangle(0.0, 0.0, float(w), float(h))
                rl.draw_texture_pro(self._solid_white, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
            else:
                rl.draw_rectangle(0, 0, int(w), int(h), rl.WHITE)

        for lx, ly, lrange, lsrc, lr, lg, lb in lights:
            if lx < -lrange or lx > w + lrange or ly < -lrange or ly > h + lrange:
                continue
            set_vec4("u_light_color", lr, lg, lb, 1.0)
            set_vec2("u_light_pos", lx, ly)
            set_float("u_light_range", lrange)
            set_float("u_light_source_radius", lsrc)
            draw_fullscreen()
            # Make sure each fullscreen pass is flushed before changing light
            # uniforms (raylib batches draws).
            rl.rl_draw_render_batch_active()

        rl.end_blend_mode()
        rl.end_shader_mode()
        rl.end_texture_mode()
        return True

    def draw(self) -> None:
        if self._player is None:
            rl.clear_background(rl.Color(10, 10, 12, 255))
            draw_ui_text(self._small, "Lighting debug view: missing player", 16.0, 16.0, scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return

        self._ensure_render_targets()
        if self._light_rt is None:
            rl.clear_background(rl.Color(10, 10, 12, 255))
            draw_ui_text(
                self._small,
                "Lighting debug view: missing render targets",
                16.0,
                16.0,
                scale=UI_TEXT_SCALE,
                color=UI_ERROR_COLOR,
            )
            return

        light_x = float(self._ui_mouse_x)
        light_y = float(self._ui_mouse_y)
        sdf_ok = self._render_lightmap_sdf(light_x=light_x, light_y=light_y)
        if not sdf_ok:
            rl.begin_texture_mode(self._light_rt)
            rl.clear_background(self._ambient)
            rl.end_texture_mode()

        # Draw the world, then multiply by the lightmap.
        rl.clear_background(rl.BLACK)
        self._world.draw(draw_aim_indicators=False, entity_alpha=1.0)

        src_light = rl.Rectangle(0.0, 0.0, float(self._light_rt.texture.width), -float(self._light_rt.texture.height))
        dst_light = rl.Rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
        rl.begin_blend_mode(rl.BLEND_MULTIPLIED)
        rl.draw_texture_pro(self._light_rt.texture, src_light, dst_light, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_blend_mode()

        if self._projectiles:
            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
            for proj in self._projectiles:
                sx, sy = self._world.world_to_screen(float(proj.x), float(proj.y))
                fade = clamp(1.0 - float(proj.age) / max(0.001, float(proj.ttl)), 0.0, 1.0)
                c = self._proj_light_tint
                rl.draw_circle(
                    int(sx),
                    int(sy),
                    float(self._proj_radius_px),
                    rl.Color(int(c.r), int(c.g), int(c.b), int(220.0 * fade)),
                )
            rl.end_blend_mode()

        if self._fly_lights_enabled and self._fly_lights:
            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
            for fl in self._fly_lights:
                sx, sy = self._world.world_to_screen(float(fl.x), float(fl.y))
                c = fl.color
                rl.draw_circle(
                    int(sx),
                    int(sy),
                    4.0,
                    rl.Color(int(c.r), int(c.g), int(c.b), 220),
                )
            rl.end_blend_mode()

        if self._debug_lightmap_preview:
            screen_w = float(rl.get_screen_width())
            scale = 0.25
            pad = 16.0
            preview_w = float(self._light_rt.texture.width) * scale
            preview_h = float(self._light_rt.texture.height) * scale
            dst_preview = rl.Rectangle(screen_w - preview_w - pad, pad, preview_w, preview_h)
            rl.begin_blend_mode(rl.BLEND_ALPHA)
            rl.draw_texture_pro(
                self._light_rt.texture,
                src_light,
                dst_preview,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
            rl.end_blend_mode()
            rl.draw_rectangle_lines(int(dst_preview.x), int(dst_preview.y), int(dst_preview.width), int(dst_preview.height), rl.Color(255, 255, 255, 120))

        _cam_x, _cam_y, scale_x, scale_y = self._world.renderer._world_params()
        scale = (scale_x + scale_y) * 0.5

        if self._draw_occluders:
            px, py = self._world.world_to_screen(float(self._player.pos.x), float(self._player.pos.y))
            rl.draw_circle_lines(
                int(px),
                int(py),
                int(max(1.0, float(self._player.size) * 0.5 * scale * float(self._occluder_radius_mul) + float(self._occluder_radius_pad_px))),
                rl.Color(80, 220, 120, 180),
            )
            for creature in self._world.creatures.entries:
                if not creature.active:
                    continue
                sx, sy = self._world.world_to_screen(float(creature.pos.x), float(creature.pos.y))
                r = float(creature.size) * 0.5 * scale * float(self._occluder_radius_mul) + float(self._occluder_radius_pad_px)
                rl.draw_circle_lines(int(sx), int(sy), int(max(1.0, r)), rl.Color(220, 80, 80, 180))

        rl.draw_circle_lines(int(light_x), int(light_y), 6, rl.Color(255, 255, 255, 220))
        if self._cursor_light_enabled:
            rl.draw_circle_lines(int(light_x), int(light_y), int(max(1.0, self._light_radius)), rl.Color(255, 255, 255, 40))
            rl.draw_circle_lines(
                int(light_x),
                int(light_y),
                int(max(1.0, self._light_source_radius)),
                rl.Color(255, 255, 255, 100),
            )

        if self._debug_dump_next_frame:
            self._debug_dump_next_frame = False
            self._dump_debug(light_x=light_x, light_y=light_y, sdf_ok=sdf_ok)
            if self._debug_auto_dump:
                self.close_requested = True

        if self._draw_debug:
            title = "Lighting debug view (night + SDF shadows)"
            lines = [
                title,
                "WASD move  MOUSE light pos",
                "SPACE simulate  R reset",
                f",/. shadow_k={self._sdf_shadow_k:.1f}",
                f"F6 sdf_debug={self._sdf_debug_mode}  (1 solid, 2 uv, 3 range, 4 atten, 5 shade)",
                f"+/- shadow_floor={self._sdf_shadow_floor:.2f}",
                f"[ ] disc_radius={self._light_source_radius:.0f}   shift+[ ] light_radius={self._light_radius:.0f}",
                f"O/P occ_mul={self._occluder_radius_mul:.2f}   K/L occ_pad_px={self._occluder_radius_pad_px:.1f}  (hold shift for bigger steps)",
                f"LMB shoot  proj={len(self._projectiles)}  proj_lights<= {self._max_projectile_lights}",
                f"3 cursor_light={'on' if self._cursor_light_enabled else 'off'}   N/M ambient_mul={self._ambient_mul:.2f}  (hold shift for bigger steps)",
                f"5 fly_lights={'on' if self._fly_lights_enabled else 'off'}  count={len(self._fly_lights)}",
                "1 ui  2 occluders  4 lightmap preview",
                "F5 dump debug (artifacts/lighting-debug/)",
            ]
            if not sdf_ok:
                lines.append("SDF shader unavailable (ambient-only fallback)")
            elif self._sdf_shader_missing:
                lines.append("SDF uniforms missing: " + ", ".join(self._sdf_shader_missing))
            x0 = 16.0
            y0 = 16.0
            lh = float(ui_line_height(self._small, scale=UI_TEXT_SCALE))
            for idx, line in enumerate(lines):
                draw_ui_text(
                    self._small,
                    line,
                    x0,
                    y0 + lh * float(idx),
                    scale=UI_TEXT_SCALE,
                    color=UI_TEXT_COLOR if idx < 5 else UI_HINT_COLOR,
                )


@register_view("lighting-debug", "Lighting (SDF)")
def _create_lighting_debug_view(*, ctx: ViewContext) -> LightingDebugView:
    return LightingDebugView(ctx)
