from __future__ import annotations

from contextlib import contextmanager
import math
import random
from pathlib import Path
from typing import Iterator

import pyray as rl

from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import ViewContext

from ..creatures.spawn import CreatureInit, CreatureTypeId
from ..game_world import GameWorld
from ..gameplay import PlayerInput
from .registry import register_view

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

_SDF_SHADOW_MAX_CIRCLES = 64
_SDF_SHADOW_MAX_STEPS = 64
_SDF_SHADOW_EPSILON = 0.75
_SDF_SHADOW_MIN_STEP = 1.0

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
uniform vec4 u_ambient;
uniform vec4 u_light_color;
uniform vec2 u_light_pos;
uniform float u_light_range;
uniform float u_light_source_radius;
uniform float u_shadow_k;
uniform int u_circle_count;
uniform vec4 u_circles[MAX_CIRCLES];

float map(vec2 p)
{{
    float d = 1e20;
    for (int i = 0; i < MAX_CIRCLES; i++)
    {{
        if (i >= u_circle_count) break;
        vec4 c = u_circles[i];
        d = min(d, length(p - c.xy) - c.z);
    }}
    return d;
}}

// Raymarched SDF soft shadows (Inigo Quilez + Sebastian Aaltonen improvement).
// `u_shadow_k` behaves like the original `k` hardness parameter.
float softshadow(vec2 ro, vec2 rd, float mint, float maxt, float k)
{{
    float res = 1.0;
    float t = mint;
    float ph = 1e20;
    for (int i = 0; i < {_SDF_SHADOW_MAX_STEPS} && t < maxt; i++)
    {{
        float h = map(ro + rd * t);
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

    vec2 to_light = u_light_pos - p;
    float dist = length(to_light);
    if (dist <= 1e-4 || dist > u_light_range)
    {{
        finalColor = vec4(u_ambient.rgb, 1.0);
        return;
    }}

    float atten = 1.0 - clamp(dist / u_light_range, 0.0, 1.0);
    atten = atten * atten;

    // Avoid self-shadowing artifacts for receiver pixels inside occluders (sprites).
    float d0 = map(p);
    float shadow = 1.0;
    if (d0 >= 0.0)
    {{
        float k = u_shadow_k;
        // Heuristic: larger disc lights soften shadows.
        if (u_light_source_radius > 0.0)
        {{
            k = u_shadow_k / max(1.0, u_light_source_radius * 0.10);
        }}
        vec2 rd = to_light / max(dist, 1e-4);
        float maxt = max(0.0, dist - max(0.0, u_light_source_radius));
        shadow = softshadow(p, rd, 2.0, maxt, k);
    }}

    vec3 lm = u_ambient.rgb + u_light_color.rgb * (atten * shadow);
    lm = clamp(lm, 0.0, 1.0);
    finalColor = vec4(lm, 1.0);
}}
"""


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


@contextmanager
def _blend_custom(src_factor: int, dst_factor: int, blend_equation: int) -> Iterator[None]:
    # NOTE: raylib/rlgl tracks custom blend factors as state; some backends only
    # apply them when switching the blend mode. Set factors both before and
    # after BeginBlendMode() to ensure the current draw uses the intended values.
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    rl.begin_blend_mode(rl.BLEND_CUSTOM)
    rl.rl_set_blend_factors(src_factor, dst_factor, blend_equation)
    try:
        yield
    finally:
        rl.end_blend_mode()


@contextmanager
def _blend_custom_separate(
    src_rgb: int,
    dst_rgb: int,
    src_alpha: int,
    dst_alpha: int,
    eq_rgb: int,
    eq_alpha: int,
) -> Iterator[None]:
    # NOTE: raylib/rlgl tracks custom blend factors as state; some backends only
    # apply them when switching the blend mode. Set factors both before and
    # after BeginBlendMode() to ensure the current draw uses the intended values.
    rl.rl_set_blend_factors_separate(src_rgb, dst_rgb, src_alpha, dst_alpha, eq_rgb, eq_alpha)
    rl.begin_blend_mode(rl.BLEND_CUSTOM_SEPARATE)
    rl.rl_set_blend_factors_separate(src_rgb, dst_rgb, src_alpha, dst_alpha, eq_rgb, eq_alpha)
    try:
        yield
    finally:
        rl.end_blend_mode()


def _circle_tangent_points(
    light_x: float,
    light_y: float,
    cx: float,
    cy: float,
    radius: float,
) -> tuple[tuple[float, float], tuple[float, float]] | None:
    ux = float(light_x) - float(cx)
    uy = float(light_y) - float(cy)
    dist_sq = ux * ux + uy * uy
    radius = float(radius)
    if dist_sq <= radius * radius:
        return None
    h = math.sqrt(max(0.0, dist_sq - radius * radius))
    inv = 1.0 / dist_sq
    k = radius * radius * inv
    m = radius * h * inv
    px, py = -uy, ux
    t1 = (float(cx) + k * ux + m * px, float(cy) + k * uy + m * py)
    t2 = (float(cx) + k * ux - m * px, float(cy) + k * uy - m * py)
    return t1, t2


def _circle_circle_tangents(
    c1x: float,
    c1y: float,
    r1: float,
    c2x: float,
    c2y: float,
    r2: float,
) -> list[tuple[tuple[float, float], tuple[float, float]]]:
    dx = float(c2x) - float(c1x)
    dy = float(c2y) - float(c1y)
    dist_sq = dx * dx + dy * dy
    if dist_sq <= 1e-9:
        return []

    r1 = float(r1)
    r2 = float(r2)
    dr = r1 - r2
    h_sq = dist_sq - dr * dr
    if h_sq < 0.0:
        return []

    h = math.sqrt(max(0.0, h_sq))
    out: list[tuple[tuple[float, float], tuple[float, float]]] = []
    for sign in (-1.0, 1.0):
        vx = (dx * dr + (-dy) * h * sign) / dist_sq
        vy = (dy * dr + dx * h * sign) / dist_sq
        p1 = (float(c1x) + vx * r1, float(c1y) + vy * r1)
        p2 = (float(c2x) + vx * r2, float(c2y) + vy * r2)
        out.append((p1, p2))
    return out


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
        )
        self._player = self._world.players[0] if self._world.players else None

        self.close_requested = False

        self._ui_mouse_x = 0.0
        self._ui_mouse_y = 0.0

        self._simulate = True
        self._draw_debug = True
        self._draw_occluders = False
        self._debug_shadow_wedges = False
        self._debug_lightmap_preview = False

        self._shadow_mode = "sdf"
        self._sdf_shadow_k = 64.0

        self._light_radius = 360.0
        self._light_is_disc = False
        self._light_source_radius = 14.0
        self._ambient = rl.Color(26, 26, 34, 255)
        self._light_tint = rl.Color(255, 245, 220, 255)

        self._light_texture: rl.Texture | None = None
        self._sdf_shader: rl.Shader | None = None
        self._sdf_shader_tried: bool = False
        self._sdf_shader_locs: dict[str, int] = {}
        self._scene_rt: rl.RenderTexture | None = None
        self._light_rt: rl.RenderTexture | None = None
        self._scratch_rt: rl.RenderTexture | None = None

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _draw_ui_text(self, text: str, x: float, y: float, color: rl.Color, scale: float = UI_TEXT_SCALE) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _update_ui_mouse(self) -> None:
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        self._ui_mouse_x = _clamp(float(mouse.x), 0.0, max(0.0, screen_w - 1.0))
        self._ui_mouse_y = _clamp(float(mouse.y), 0.0, max(0.0, screen_h - 1.0))

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
            self._debug_shadow_wedges = not self._debug_shadow_wedges
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._debug_lightmap_preview = not self._debug_lightmap_preview

        if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
            self._shadow_mode = "wedge" if self._shadow_mode == "sdf" else "sdf"

        if rl.is_key_pressed(rl.KeyboardKey.KEY_L):
            self._light_is_disc = not self._light_is_disc

        if rl.is_key_pressed(rl.KeyboardKey.KEY_MINUS):
            self._light_radius = max(80.0, self._light_radius - 20.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EQUAL):
            self._light_radius = min(1200.0, self._light_radius + 20.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._light_source_radius = max(0.0, self._light_source_radius - 2.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._light_source_radius = min(80.0, self._light_source_radius + 2.0)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_COMMA):
            self._sdf_shadow_k = max(1.0, self._sdf_shadow_k / 1.25)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD):
            self._sdf_shadow_k = min(512.0, self._sdf_shadow_k * 1.25)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._reset_scene(seed=0xBEEF)

    def _ensure_light_texture(self) -> rl.Texture:
        if self._light_texture is not None and int(getattr(self._light_texture, "id", 0)) > 0:
            return self._light_texture
        image = rl.gen_image_gradient_radial(
            256,
            256,
            0.0,
            rl.Color(255, 255, 255, 255),
            rl.Color(255, 255, 255, 0),
        )
        texture = rl.load_texture_from_image(image)
        rl.unload_image(image)
        self._light_texture = texture
        return texture

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
            "u_ambient": rl.get_shader_location(shader, "u_ambient"),
            "u_light_color": rl.get_shader_location(shader, "u_light_color"),
            "u_light_pos": rl.get_shader_location(shader, "u_light_pos"),
            "u_light_range": rl.get_shader_location(shader, "u_light_range"),
            "u_light_source_radius": rl.get_shader_location(shader, "u_light_source_radius"),
            "u_shadow_k": rl.get_shader_location(shader, "u_shadow_k"),
            "u_circle_count": rl.get_shader_location(shader, "u_circle_count"),
            "u_circles": circles_loc,
        }

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
        self._scene_rt = self._ensure_render_target(self._scene_rt, w, h)
        self._light_rt = self._ensure_render_target(self._light_rt, w, h)
        self._scratch_rt = self._ensure_render_target(self._scratch_rt, w, h)

    def _reset_scene(self, *, seed: int) -> None:
        self._world.reset(seed=int(seed), player_count=1)
        self._player = self._world.players[0] if self._world.players else None
        self._world.update_camera(0.0)

        rng = random.Random(int(seed))
        if self._player is None:
            return
        center_x = float(self._player.pos_x)
        center_y = float(self._player.pos_y)

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
            x = _clamp(x, 40.0, WORLD_SIZE - 40.0)
            y = _clamp(y, 40.0, WORLD_SIZE - 40.0)
            init = CreatureInit(
                origin_template_id=0,
                pos_x=float(x),
                pos_y=float(y),
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

        runtime_dir = Path("artifacts") / "runtime"
        if runtime_dir.is_dir():
            try:
                self._world.config = ensure_crimson_cfg(runtime_dir)
            except Exception:
                self._world.config = None
        else:
            self._world.config = None

        self._world.open()
        self._reset_scene(seed=0xBEEF)
        self._ensure_light_texture()
        self._ensure_render_targets()

        self._ui_mouse_x = float(rl.get_screen_width()) * 0.5
        self._ui_mouse_y = float(rl.get_screen_height()) * 0.5

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._light_texture is not None and int(getattr(self._light_texture, "id", 0)) > 0:
            rl.unload_texture(self._light_texture)
            self._light_texture = None
        if self._sdf_shader is not None and int(getattr(self._sdf_shader, "id", 0)) > 0:
            rl.unload_shader(self._sdf_shader)
            self._sdf_shader = None
            self._sdf_shader_locs.clear()
        if self._scene_rt is not None and int(getattr(self._scene_rt, "id", 0)) > 0:
            rl.unload_render_texture(self._scene_rt)
            self._scene_rt = None
        if self._light_rt is not None and int(getattr(self._light_rt, "id", 0)) > 0:
            rl.unload_render_texture(self._light_rt)
            self._light_rt = None
        if self._scratch_rt is not None and int(getattr(self._scratch_rt, "id", 0)) > 0:
            rl.unload_render_texture(self._scratch_rt)
            self._scratch_rt = None
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

    def _draw_shadow_wedge(
        self,
        *,
        light_x: float,
        light_y: float,
        occluder_x: float,
        occluder_y: float,
        occluder_radius: float,
        far_len: float,
        color: rl.Color,
    ) -> None:
        tangents = _circle_tangent_points(light_x, light_y, occluder_x, occluder_y, occluder_radius)
        if tangents is None:
            return
        (t1x, t1y), (t2x, t2y) = tangents

        d1x = t1x - light_x
        d1y = t1y - light_y
        d2x = t2x - light_x
        d2y = t2y - light_y
        len1 = math.hypot(d1x, d1y)
        len2 = math.hypot(d2x, d2y)
        if len1 <= 1e-6 or len2 <= 1e-6:
            return

        s1 = float(far_len) / len1
        s2 = float(far_len) / len2
        f1x = light_x + d1x * s1
        f1y = light_y + d1y * s1
        f2x = light_x + d2x * s2
        f2y = light_y + d2y * s2

        t1 = rl.Vector2(float(t1x), float(t1y))
        f1 = rl.Vector2(float(f1x), float(f1y))
        f2 = rl.Vector2(float(f2x), float(f2y))
        t2 = rl.Vector2(float(t2x), float(t2y))
        rl.draw_triangle(t1, f1, f2, color)
        rl.draw_triangle(t1, f2, t2, color)

    def _draw_quad_color(
        self,
        p0: tuple[float, float],
        p1: tuple[float, float],
        p2: tuple[float, float],
        p3: tuple[float, float],
        color: rl.Color,
    ) -> None:
        x0, y0 = p0
        x1, y1 = p1
        x2, y2 = p2
        x3, y3 = p3
        rl.rl_set_texture(0)
        rl.rl_begin(rl.RL_TRIANGLES)
        rl.rl_color4ub(color.r, color.g, color.b, color.a)
        rl.rl_vertex2f(float(x0), float(y0))
        rl.rl_color4ub(color.r, color.g, color.b, color.a)
        rl.rl_vertex2f(float(x1), float(y1))
        rl.rl_color4ub(color.r, color.g, color.b, color.a)
        rl.rl_vertex2f(float(x2), float(y2))
        rl.rl_color4ub(color.r, color.g, color.b, color.a)
        rl.rl_vertex2f(float(x0), float(y0))
        rl.rl_color4ub(color.r, color.g, color.b, color.a)
        rl.rl_vertex2f(float(x2), float(y2))
        rl.rl_color4ub(color.r, color.g, color.b, color.a)
        rl.rl_vertex2f(float(x3), float(y3))
        rl.rl_end()
        rl.rl_set_texture(0)

    def _draw_quad_gradient(
        self,
        p0: tuple[float, float],
        c0: rl.Color,
        p1: tuple[float, float],
        c1: rl.Color,
        p2: tuple[float, float],
        c2: rl.Color,
        p3: tuple[float, float],
        c3: rl.Color,
    ) -> None:
        x0, y0 = p0
        x1, y1 = p1
        x2, y2 = p2
        x3, y3 = p3
        rl.rl_set_texture(0)
        rl.rl_begin(rl.RL_TRIANGLES)
        rl.rl_color4ub(c0.r, c0.g, c0.b, c0.a)
        rl.rl_vertex2f(float(x0), float(y0))
        rl.rl_color4ub(c1.r, c1.g, c1.b, c1.a)
        rl.rl_vertex2f(float(x1), float(y1))
        rl.rl_color4ub(c2.r, c2.g, c2.b, c2.a)
        rl.rl_vertex2f(float(x2), float(y2))
        rl.rl_color4ub(c0.r, c0.g, c0.b, c0.a)
        rl.rl_vertex2f(float(x0), float(y0))
        rl.rl_color4ub(c2.r, c2.g, c2.b, c2.a)
        rl.rl_vertex2f(float(x2), float(y2))
        rl.rl_color4ub(c3.r, c3.g, c3.b, c3.a)
        rl.rl_vertex2f(float(x3), float(y3))
        rl.rl_end()
        rl.rl_set_texture(0)

    @staticmethod
    def _ray_far_point(p0: tuple[float, float], p1: tuple[float, float], far_len: float) -> tuple[float, float] | None:
        x0, y0 = p0
        x1, y1 = p1
        dx = float(x1) - float(x0)
        dy = float(y1) - float(y0)
        length = math.hypot(dx, dy)
        if length <= 1e-6:
            return None
        scale = float(far_len) / length
        return float(x1) + dx * scale, float(y1) + dy * scale

    @staticmethod
    def _tangent_side(light_x: float, light_y: float, cx: float, cy: float, point_x: float, point_y: float) -> int:
        vx = float(point_x) - float(light_x)
        vy = float(point_y) - float(light_y)
        cx = float(cx) - float(light_x)
        cy = float(cy) - float(light_y)
        cross = cx * vy - cy * vx
        if cross >= 0.0:
            return 1
        return -1

    def _draw_shadow_disc_with_penumbra(
        self,
        *,
        light_x: float,
        light_y: float,
        light_source_radius: float,
        occluder_x: float,
        occluder_y: float,
        occluder_radius: float,
        far_len: float,
    ) -> None:
        light_source_radius = float(light_source_radius)
        occluder_radius = float(occluder_radius)
        if light_source_radius <= 0.0 or occluder_radius <= 0.0:
            self._draw_shadow_wedge(
                light_x=float(light_x),
                light_y=float(light_y),
                occluder_x=float(occluder_x),
                occluder_y=float(occluder_y),
                occluder_radius=float(occluder_radius),
                far_len=float(far_len),
                color=rl.Color(0, 0, 0, 255),
            )
            return

        outer = _circle_circle_tangents(
            light_x,
            light_y,
            light_source_radius,
            occluder_x,
            occluder_y,
            occluder_radius,
        )
        inner = _circle_circle_tangents(
            light_x,
            light_y,
            light_source_radius,
            occluder_x,
            occluder_y,
            -occluder_radius,
        )

        if not outer:
            return

        outer_by_side: dict[int, tuple[tuple[float, float], tuple[float, float]]] = {}
        for p_light, p_occ in outer:
            side = self._tangent_side(light_x, light_y, occluder_x, occluder_y, p_occ[0], p_occ[1])
            outer_by_side[side] = (p_light, p_occ)

        inner_by_side: dict[int, tuple[tuple[float, float], tuple[float, float]]] = {}
        for p_light, p_occ in inner:
            side = self._tangent_side(light_x, light_y, occluder_x, occluder_y, p_occ[0], p_occ[1])
            inner_by_side[side] = (p_light, p_occ)

        # Penumbra: between outer and inner tangents on each side.
        black = rl.Color(0, 0, 0, 255)
        white = rl.Color(255, 255, 255, 255)
        for side in (-1, 1):
            outer_pair = outer_by_side.get(side)
            inner_pair = inner_by_side.get(side)
            if outer_pair is None or inner_pair is None:
                continue
            out_l, out_o = outer_pair
            in_l, in_o = inner_pair
            far_out = self._ray_far_point(out_l, out_o, far_len)
            far_in = self._ray_far_point(in_l, in_o, far_len)
            if far_out is None or far_in is None:
                continue
            # Gradient multiplies light from 0 (umbra edge) -> 1 (fully lit).
            self._draw_quad_gradient(
                in_o,
                black,
                far_in,
                black,
                far_out,
                white,
                out_o,
                white,
            )

        # Umbra: fully shadowed region between inner tangents.
        if len(inner) >= 2:
            (l1, o1), (l2, o2) = inner[0], inner[1]
            far1 = self._ray_far_point(l1, o1, far_len)
            far2 = self._ray_far_point(l2, o2, far_len)
            if far1 is not None and far2 is not None:
                self._draw_quad_color(o1, far1, far2, o2, rl.Color(0, 0, 0, 255))

    def _draw_shadow_wedge_debug(
        self,
        *,
        light_x: float,
        light_y: float,
        occluder_x: float,
        occluder_y: float,
        occluder_radius: float,
        far_len: float,
        color: rl.Color,
    ) -> None:
        tangents = _circle_tangent_points(light_x, light_y, occluder_x, occluder_y, occluder_radius)
        if tangents is None:
            return
        (t1x, t1y), (t2x, t2y) = tangents

        d1x = t1x - light_x
        d1y = t1y - light_y
        d2x = t2x - light_x
        d2y = t2y - light_y
        len1 = math.hypot(d1x, d1y)
        len2 = math.hypot(d2x, d2y)
        if len1 <= 1e-6 or len2 <= 1e-6:
            return

        s1 = float(far_len) / len1
        s2 = float(far_len) / len2
        f1x = light_x + d1x * s1
        f1y = light_y + d1y * s1
        f2x = light_x + d2x * s2
        f2y = light_y + d2y * s2

        t1 = rl.Vector2(float(t1x), float(t1y))
        t2 = rl.Vector2(float(t2x), float(t2y))
        f1 = rl.Vector2(float(f1x), float(f1y))
        f2 = rl.Vector2(float(f2x), float(f2y))
        rl.draw_line_v(t1, f1, color)
        rl.draw_line_v(t2, f2, color)
        rl.draw_circle(int(t1.x), int(t1.y), 3.0, color)
        rl.draw_circle(int(t2.x), int(t2.y), 3.0, color)

    def _draw_tangents_debug(
        self,
        *,
        light_x: float,
        light_y: float,
        light_source_radius: float,
        occluder_x: float,
        occluder_y: float,
        occluder_radius: float,
        far_len: float,
        outer_color: rl.Color,
        inner_color: rl.Color,
    ) -> None:
        outer = _circle_circle_tangents(
            light_x,
            light_y,
            float(light_source_radius),
            occluder_x,
            occluder_y,
            float(occluder_radius),
        )
        inner = _circle_circle_tangents(
            light_x,
            light_y,
            float(light_source_radius),
            occluder_x,
            occluder_y,
            -float(occluder_radius),
        )

        def draw_pair(p1: tuple[float, float], p2: tuple[float, float], color: rl.Color) -> None:
            x1, y1 = p1
            x2, y2 = p2
            rl.draw_line(int(x1), int(y1), int(x2), int(y2), color)
            rl.draw_circle(int(x1), int(y1), 3.0, color)
            rl.draw_circle(int(x2), int(y2), 3.0, color)
            dx = x2 - x1
            dy = y2 - y1
            length = math.hypot(dx, dy)
            if length <= 1e-6:
                return
            sx = float(far_len) / length
            fx = x2 + dx * sx
            fy = y2 + dy * sx
            rl.draw_line(int(x2), int(y2), int(fx), int(fy), rl.Color(color.r, color.g, color.b, min(255, int(color.a * 0.6))))

        for p1, p2 in outer:
            draw_pair(p1, p2, outer_color)
        for p1, p2 in inner:
            draw_pair(p1, p2, inner_color)

    def _render_lightmap(self, *, light_x: float, light_y: float) -> None:
        if self._light_rt is None or self._scratch_rt is None:
            return
        light_texture = self._ensure_light_texture()

        w = float(self._light_rt.texture.width)
        h = float(self._light_rt.texture.height)
        far_len = math.hypot(w, h) * 1.25
        _cam_x, _cam_y, scale_x, scale_y = self._world.renderer._world_params()
        scale = (scale_x + scale_y) * 0.5

        # 1) Start with ambient in the global lightmap.
        rl.begin_texture_mode(self._light_rt)
        rl.clear_background(self._ambient)
        rl.end_texture_mode()

        # 2) Per-light scratch: draw light, then carve shadows, then add to global.
        rl.begin_texture_mode(self._scratch_rt)
        rl.clear_background(rl.Color(0, 0, 0, 0))
        rl.end_texture_mode()

        # Light sprite pass.
        rl.begin_texture_mode(self._scratch_rt)
        radius = float(self._light_radius)
        dst = rl.Rectangle(float(light_x), float(light_y), radius * 2.0, radius * 2.0)
        origin = rl.Vector2(radius, radius)
        src = rl.Rectangle(0.0, 0.0, float(light_texture.width), float(light_texture.height))
        rl.begin_blend_mode(rl.BLEND_ALPHA)
        rl.draw_texture_pro(light_texture, src, dst, origin, 0.0, self._light_tint)
        rl.end_blend_mode()

        # Shadow pass: multiply scratch RGB by a visibility mask (src RGB).
        with _blend_custom_separate(
            rl.RL_ZERO,
            rl.RL_SRC_COLOR,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        ):
            if self._player is not None:
                px, py = self._world.world_to_screen(float(self._player.pos_x), float(self._player.pos_y))
                pr = float(self._player.size) * 0.5 * scale
                if math.hypot(px - light_x, py - light_y) <= float(self._light_radius) + pr:
                    if self._light_is_disc and self._light_source_radius > 0.0:
                        self._draw_shadow_disc_with_penumbra(
                            light_x=float(light_x),
                            light_y=float(light_y),
                            light_source_radius=float(self._light_source_radius),
                            occluder_x=float(px),
                            occluder_y=float(py),
                            occluder_radius=pr,
                            far_len=far_len,
                        )
                    else:
                        self._draw_shadow_wedge(
                            light_x=float(light_x),
                            light_y=float(light_y),
                            occluder_x=float(px),
                            occluder_y=float(py),
                            occluder_radius=pr,
                            far_len=far_len,
                            color=rl.Color(0, 0, 0, 255),
                        )

            for creature in self._world.creatures.entries:
                if not creature.active:
                    continue
                sx, sy = self._world.world_to_screen(float(creature.x), float(creature.y))
                cr = float(creature.size) * 0.5 * scale
                if math.hypot(sx - light_x, sy - light_y) > float(self._light_radius) + cr:
                    continue
                if self._light_is_disc and self._light_source_radius > 0.0:
                    self._draw_shadow_disc_with_penumbra(
                        light_x=float(light_x),
                        light_y=float(light_y),
                        light_source_radius=float(self._light_source_radius),
                        occluder_x=float(sx),
                        occluder_y=float(sy),
                        occluder_radius=cr,
                        far_len=far_len,
                    )
                else:
                    self._draw_shadow_wedge(
                        light_x=float(light_x),
                        light_y=float(light_y),
                        occluder_x=float(sx),
                        occluder_y=float(sy),
                        occluder_radius=cr,
                        far_len=far_len,
                        color=rl.Color(0, 0, 0, 255),
                    )

        rl.end_texture_mode()

        # Accumulate scratch into global lightmap (add rgb; preserve alpha).
        rl.begin_texture_mode(self._light_rt)
        with _blend_custom_separate(
            rl.RL_ONE,
            rl.RL_ONE,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        ):
            src_full = rl.Rectangle(0.0, 0.0, float(self._scratch_rt.texture.width), -float(self._scratch_rt.texture.height))
            dst_full = rl.Rectangle(0.0, 0.0, float(self._light_rt.texture.width), float(self._light_rt.texture.height))
            rl.draw_texture_pro(self._scratch_rt.texture, src_full, dst_full, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        rl.end_texture_mode()

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

        circles: list[tuple[float, float, float]] = []

        if self._player is not None:
            px, py = self._world.world_to_screen(float(self._player.pos_x), float(self._player.pos_y))
            pr = float(self._player.size) * 0.5 * scale
            circles.append((float(px), float(py), float(pr)))

        for creature in self._world.creatures.entries:
            if not creature.active:
                continue
            sx, sy = self._world.world_to_screen(float(creature.x), float(creature.y))
            cr = float(creature.size) * 0.5 * scale
            circles.append((float(sx), float(sy), float(cr)))

        if len(circles) > _SDF_SHADOW_MAX_CIRCLES:
            circles = circles[:_SDF_SHADOW_MAX_CIRCLES]

        def set_vec2(name: str, x: float, y: float) -> None:
            loc = locs.get(name, -1)
            if loc < 0:
                return
            rl.set_shader_value(shader, loc, rl.Vector2(float(x), float(y)), rl.SHADER_UNIFORM_VEC2)

        def set_vec4(name: str, x: float, y: float, z: float, q: float) -> None:
            loc = locs.get(name, -1)
            if loc < 0:
                return
            rl.set_shader_value(shader, loc, rl.Vector4(float(x), float(y), float(z), float(q)), rl.SHADER_UNIFORM_VEC4)

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
        with _blend_custom(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD):
            rl.begin_shader_mode(shader)
            set_vec2("u_resolution", w, h)

            amb = self._ambient
            set_vec4("u_ambient", float(amb.r) / 255.0, float(amb.g) / 255.0, float(amb.b) / 255.0, 1.0)

            lt = self._light_tint
            set_vec4("u_light_color", float(lt.r) / 255.0, float(lt.g) / 255.0, float(lt.b) / 255.0, 1.0)

            set_vec2("u_light_pos", float(light_x), float(light_y))
            set_float("u_light_range", float(self._light_radius))
            set_float("u_shadow_k", float(self._sdf_shadow_k))

            source_radius = float(self._light_source_radius) if self._light_is_disc else 0.0
            set_float("u_light_source_radius", source_radius)

            set_int("u_circle_count", len(circles))
            circles_loc = locs.get("u_circles", -1)
            if circles and circles_loc >= 0:
                flat: list[float] = []
                for cx, cy, cr in circles:
                    flat.extend((float(cx), float(cy), float(cr), 1.0))
                rl.set_shader_value_v(
                    shader,
                    circles_loc,
                    rl.ffi.new("float[]", flat),
                    rl.SHADER_UNIFORM_VEC4,
                    len(circles),
                )
            rl.draw_rectangle(0, 0, int(w), int(h), rl.WHITE)
            rl.end_shader_mode()
        rl.end_texture_mode()
        return True

    def draw(self) -> None:
        if self._player is None:
            rl.clear_background(rl.Color(10, 10, 12, 255))
            self._draw_ui_text("Lighting debug view: missing player", 16.0, 16.0, UI_ERROR_COLOR)
            return

        self._ensure_render_targets()
        if self._scene_rt is None or self._light_rt is None:
            rl.clear_background(rl.Color(10, 10, 12, 255))
            self._draw_ui_text("Lighting debug view: missing render targets", 16.0, 16.0, UI_ERROR_COLOR)
            return

        # Render the world into an offscreen texture first.
        rl.begin_texture_mode(self._scene_rt)
        self._world.draw(draw_aim_indicators=False, entity_alpha=1.0)
        rl.end_texture_mode()

        light_x = float(self._ui_mouse_x)
        light_y = float(self._ui_mouse_y)
        if self._shadow_mode == "sdf":
            if not self._render_lightmap_sdf(light_x=light_x, light_y=light_y):
                self._render_lightmap(light_x=light_x, light_y=light_y)
        else:
            self._render_lightmap(light_x=light_x, light_y=light_y)

        # Composite to screen: scene first, then lightmap multiplied.
        src_scene = rl.Rectangle(0.0, 0.0, float(self._scene_rt.texture.width), -float(self._scene_rt.texture.height))
        dst_scene = rl.Rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
        with _blend_custom(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD):
            rl.draw_texture_pro(self._scene_rt.texture, src_scene, dst_scene, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        src_light = rl.Rectangle(0.0, 0.0, float(self._light_rt.texture.width), -float(self._light_rt.texture.height))
        dst_light = rl.Rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
        with _blend_custom(rl.RL_DST_COLOR, rl.RL_ZERO, rl.RL_FUNC_ADD):
            rl.draw_texture_pro(self._light_rt.texture, src_light, dst_light, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        if self._debug_lightmap_preview:
            screen_w = float(rl.get_screen_width())
            scale = 0.25
            pad = 16.0
            preview_w = float(self._light_rt.texture.width) * scale
            preview_h = float(self._light_rt.texture.height) * scale
            dst_preview = rl.Rectangle(screen_w - preview_w - pad, pad, preview_w, preview_h)
            with _blend_custom(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD):
                rl.draw_texture_pro(
                    self._light_rt.texture,
                    src_light,
                    dst_preview,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.WHITE,
                )
            rl.draw_rectangle_lines(int(dst_preview.x), int(dst_preview.y), int(dst_preview.width), int(dst_preview.height), rl.Color(255, 255, 255, 120))

        _cam_x, _cam_y, scale_x, scale_y = self._world.renderer._world_params()
        scale = (scale_x + scale_y) * 0.5

        if self._draw_occluders:
            px, py = self._world.world_to_screen(float(self._player.pos_x), float(self._player.pos_y))
            rl.draw_circle_lines(
                int(px),
                int(py),
                int(max(1.0, self._player.size * 0.5 * scale)),
                rl.Color(80, 220, 120, 180),
            )
            for creature in self._world.creatures.entries:
                if not creature.active:
                    continue
                sx, sy = self._world.world_to_screen(float(creature.x), float(creature.y))
                r = float(creature.size) * 0.5 * scale
                rl.draw_circle_lines(int(sx), int(sy), int(max(1.0, r)), rl.Color(220, 80, 80, 180))

        if self._debug_shadow_wedges:
            far_len = math.hypot(float(rl.get_screen_width()), float(rl.get_screen_height())) * 1.25
            px, py = self._world.world_to_screen(float(self._player.pos_x), float(self._player.pos_y))
            pr = float(self._player.size) * 0.5 * scale
            if math.hypot(px - light_x, py - light_y) <= float(self._light_radius) + pr:
                if self._light_is_disc and self._light_source_radius > 0.0:
                    self._draw_tangents_debug(
                        light_x=float(light_x),
                        light_y=float(light_y),
                        light_source_radius=float(self._light_source_radius),
                        occluder_x=float(px),
                        occluder_y=float(py),
                        occluder_radius=pr,
                        far_len=far_len,
                        outer_color=rl.Color(80, 220, 120, 180),
                        inner_color=rl.Color(40, 180, 255, 220),
                    )
                else:
                    self._draw_shadow_wedge_debug(
                        light_x=light_x,
                        light_y=light_y,
                        occluder_x=float(px),
                        occluder_y=float(py),
                        occluder_radius=pr,
                        far_len=far_len,
                        color=rl.Color(80, 220, 120, 200),
                    )
            for creature in self._world.creatures.entries:
                if not creature.active:
                    continue
                sx, sy = self._world.world_to_screen(float(creature.x), float(creature.y))
                cr = float(creature.size) * 0.5 * scale
                if math.hypot(sx - light_x, sy - light_y) > float(self._light_radius) + cr:
                    continue
                if self._light_is_disc and self._light_source_radius > 0.0:
                    self._draw_tangents_debug(
                        light_x=float(light_x),
                        light_y=float(light_y),
                        light_source_radius=float(self._light_source_radius),
                        occluder_x=float(sx),
                        occluder_y=float(sy),
                        occluder_radius=cr,
                        far_len=far_len,
                        outer_color=rl.Color(255, 160, 80, 180),
                        inner_color=rl.Color(255, 80, 80, 220),
                    )
                else:
                    self._draw_shadow_wedge_debug(
                        light_x=light_x,
                        light_y=light_y,
                        occluder_x=float(sx),
                        occluder_y=float(sy),
                        occluder_radius=cr,
                        far_len=far_len,
                        color=rl.Color(255, 80, 80, 200),
                    )

        rl.draw_circle_lines(int(light_x), int(light_y), 6, rl.Color(255, 255, 255, 220))
        rl.draw_circle_lines(int(light_x), int(light_y), int(max(1.0, self._light_radius)), rl.Color(255, 255, 255, 40))
        if self._light_is_disc and self._light_source_radius > 0.0:
            rl.draw_circle_lines(
                int(light_x),
                int(light_y),
                int(max(1.0, self._light_source_radius)),
                rl.Color(255, 255, 255, 100),
            )

        if self._draw_debug:
            title = f"Lighting debug view (night + {self._shadow_mode} shadows)"
            lines = [
                title,
                "WASD move  MOUSE light pos",
                "SPACE simulate  R reset",
                (
                    f"M mode={self._shadow_mode}  ,/. sdf_k={self._sdf_shadow_k:.1f}"
                    if self._shadow_mode == "sdf"
                    else f"M mode={self._shadow_mode}"
                ),
                f"+/- light_radius={self._light_radius:.0f}  L disc={self._light_is_disc}",
                f"[ ] light_source_radius={self._light_source_radius:.0f}" if self._light_is_disc else "[ ] light_source_radius (disc mode)",
                "1 ui  2 occluders  3 tangent debug  4 lightmap preview",
            ]
            x0 = 16.0
            y0 = 16.0
            lh = float(self._ui_line_height())
            for idx, line in enumerate(lines):
                self._draw_ui_text(line, x0, y0 + lh * float(idx), UI_TEXT_COLOR if idx < 5 else UI_HINT_COLOR)


@register_view("lighting-debug", "Lighting (wedge + SDF)")
def _create_lighting_debug_view(*, ctx: ViewContext) -> LightingDebugView:
    return LightingDebugView(ctx)
