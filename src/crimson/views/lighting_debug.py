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

        self._light_radius = 360.0
        self._ambient = rl.Color(26, 26, 34, 255)
        self._light_tint = rl.Color(255, 245, 220, 255)

        self._light_texture: rl.Texture | None = None
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

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._light_radius = max(80.0, self._light_radius - 20.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._light_radius = min(1200.0, self._light_radius + 20.0)

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

        # Shadow carve pass: hard-clear scratch in wedge regions.
        with _blend_custom_separate(rl.RL_ZERO, rl.RL_ZERO, rl.RL_ZERO, rl.RL_ZERO, rl.RL_FUNC_ADD, rl.RL_FUNC_ADD):
            if self._player is not None:
                px, py = self._world.world_to_screen(float(self._player.pos_x), float(self._player.pos_y))
                pr = float(self._player.size) * 0.5 * scale
                if math.hypot(px - light_x, py - light_y) <= float(self._light_radius) + pr:
                    self._draw_shadow_wedge(
                        light_x=float(light_x),
                        light_y=float(light_y),
                        occluder_x=float(px),
                        occluder_y=float(py),
                        occluder_radius=pr,
                        far_len=far_len,
                        color=rl.Color(0, 0, 0, 0),
                    )

            for creature in self._world.creatures.entries:
                if not creature.active:
                    continue
                sx, sy = self._world.world_to_screen(float(creature.x), float(creature.y))
                cr = float(creature.size) * 0.5 * scale
                if math.hypot(sx - light_x, sy - light_y) > float(self._light_radius) + cr:
                    continue
                self._draw_shadow_wedge(
                    light_x=float(light_x),
                    light_y=float(light_y),
                    occluder_x=float(sx),
                    occluder_y=float(sy),
                    occluder_radius=cr,
                    far_len=far_len,
                    color=rl.Color(0, 0, 0, 0),
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

        if self._draw_debug:
            lines = [
                "Lighting debug view (night + shadow wedges)",
                "WASD move  MOUSE light pos",
                "SPACE simulate  R reset",
                f"[ ] light_radius={self._light_radius:.0f}",
                "1 ui  2 occluders  3 wedge debug",
            ]
            x0 = 16.0
            y0 = 16.0
            lh = float(self._ui_line_height())
            for idx, line in enumerate(lines):
                self._draw_ui_text(line, x0, y0 + lh * float(idx), UI_TEXT_COLOR if idx < 4 else UI_HINT_COLOR)


@register_view("lighting-debug", "Lighting (shadow wedges)")
def _create_lighting_debug_view(*, ctx: ViewContext) -> LightingDebugView:
    return LightingDebugView(ctx)
