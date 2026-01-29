from __future__ import annotations

import math
import random
from pathlib import Path

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
    // Keep finite to avoid overflow in shadow math when there are no occluders
    // or when uniform data is missing.
    float d = 1e6;
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
    if (u_circle_count <= 0) return 1.0;
    float res = 1.0;
    float t = mint;
    float ph = 1e6;
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
        self._debug_lightmap_preview = False

        self._sdf_shadow_k = 64.0

        self._light_radius = 360.0
        self._light_is_disc = False
        self._light_source_radius = 14.0
        self._ambient = rl.Color(26, 26, 34, 255)
        self._light_tint = rl.Color(255, 245, 220, 255)

        self._sdf_shader: rl.Shader | None = None
        self._sdf_shader_tried: bool = False
        self._sdf_shader_locs: dict[str, int] = {}
        self._sdf_shader_missing: list[str] = []
        self._light_rt: rl.RenderTexture | None = None

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
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._debug_lightmap_preview = not self._debug_lightmap_preview

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
        self._ensure_render_targets()

        self._ui_mouse_x = float(rl.get_screen_width()) * 0.5
        self._ui_mouse_y = float(rl.get_screen_height()) * 0.5

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
        if self._light_rt is None:
            rl.clear_background(rl.Color(10, 10, 12, 255))
            self._draw_ui_text("Lighting debug view: missing render targets", 16.0, 16.0, UI_ERROR_COLOR)
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
            title = "Lighting debug view (night + SDF shadows)"
            lines = [
                title,
                "WASD move  MOUSE light pos",
                "SPACE simulate  R reset",
                f",/. sdf_k={self._sdf_shadow_k:.1f}",
                f"+/- light_radius={self._light_radius:.0f}  L disc={self._light_is_disc}",
                f"[ ] light_source_radius={self._light_source_radius:.0f}" if self._light_is_disc else "[ ] light_source_radius (disc mode)",
                "1 ui  2 occluders  4 lightmap preview",
            ]
            if not sdf_ok:
                lines.append("SDF shader unavailable (ambient-only fallback)")
            elif self._sdf_shader_missing:
                lines.append("SDF uniforms missing: " + ", ".join(self._sdf_shader_missing))
            x0 = 16.0
            y0 = 16.0
            lh = float(self._ui_line_height())
            for idx, line in enumerate(lines):
                self._draw_ui_text(line, x0, y0 + lh * float(idx), UI_TEXT_COLOR if idx < 5 else UI_HINT_COLOR)


@register_view("lighting-debug", "Lighting (SDF)")
def _create_lighting_debug_view(*, ctx: ViewContext) -> LightingDebugView:
    return LightingDebugView(ctx)
