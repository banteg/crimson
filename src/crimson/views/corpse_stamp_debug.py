from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from crimson.creatures.anim import creature_corpse_frame_for_type
from crimson.creatures.spawn import CreatureTypeId
from grim.assets import resolve_asset_path
from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.terrain_render import GroundCorpseDecal, GroundRenderer, _maybe_alpha_test
from grim.view import View, ViewContext

from ..paths import default_runtime_dir
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view


WORLD_SIZE = 1024.0
WINDOW_W = 1024
WINDOW_H = 768

BG = rl.Color(235, 235, 235, 255)
UI_TEXT = rl.Color(20, 20, 20, 255)
UI_HINT = rl.Color(70, 70, 70, 255)
UI_ERROR = rl.Color(240, 80, 80, 255)


@dataclass(frozen=True, slots=True)
class _Step:
    name: str
    description: str


_STEPS: tuple[_Step, ...] = (
    _Step(name="clear", description="Clear the ground render target"),
    _Step(name="shadow", description="Bake shadow pass only (correct order)"),
    _Step(name="color", description="Bake color pass only (correct order)"),
    _Step(name="clear", description="Clear the ground render target"),
    _Step(name="color", description="Bake color pass only (wrong order)"),
    _Step(name="shadow", description="Bake shadow pass only (wrong order)"),
)


class CorpseStampDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self._owned_textures: list[rl.Texture] = []
        self._ground: GroundRenderer | None = None
        self._bodyset: rl.Texture | None = None

        self.close_requested = False
        self._step_index = 0
        self._corpse_size = 256.0
        self._corpse_rotation = 0.0
        self._screenshot_requested = False
        self._dump_requested = False
        self._dump_index = 0

    def _load_runtime_config(self) -> tuple[float, float | None, float | None]:
        runtime_dir = default_runtime_dir()
        if runtime_dir.is_dir():
            try:
                cfg = ensure_crimson_cfg(runtime_dir)
                return float(cfg.texture_scale), float(cfg.screen_width), float(cfg.screen_height)
            except Exception:
                return 1.0, None, None
        return 1.0, None, None

    def _dump_render_target(self) -> Path | None:
        ground = self._ground
        if ground is None or ground.render_target is None:
            return None

        log_dir = Path("artifacts") / "debug"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_dir = Path("artifacts")

        step = _STEPS[self._step_index]
        alpha_test = "a1" if bool(getattr(ground, "alpha_test", True)) else "a0"
        filename = f"corpse_stamp_rt_{self._dump_index:03d}_step{self._step_index + 1:02d}_{step.name}_{alpha_test}.png"
        out_path = log_dir / filename

        image = rl.load_image_from_texture(ground.render_target.texture)
        # Render textures are vertically flipped in raylib.
        rl.image_flip_vertical(image)
        try:
            rl.export_image(image, str(out_path))
        finally:
            rl.unload_image(image)
        self._dump_index += 1
        return out_path

    def _corpse_decal(self) -> GroundCorpseDecal:
        size = float(self._corpse_size)
        frame = creature_corpse_frame_for_type(int(CreatureTypeId.SPIDER_SP1))
        cx = WORLD_SIZE * 0.5
        cy = WORLD_SIZE * 0.5
        return GroundCorpseDecal(
            bodyset_frame=int(frame),
            top_left=Vec2(cx - size * 0.5, cy - size * 0.5),
            size=size,
            rotation_rad=float(self._corpse_rotation),
            tint=rl.Color(255, 255, 255, 255),
        )

    def _clear_ground(self) -> None:
        ground = self._ground
        if ground is None:
            return
        ground.create_render_target()
        if ground.render_target is None:
            return
        rl.begin_texture_mode(ground.render_target)
        rl.clear_background(BG)
        rl.end_texture_mode()
        # GroundRenderer treats this as an internal invariant; set it for debug fills.
        ground._render_target_ready = True

    def _bake_shadow_only(self) -> None:
        ground = self._ground
        bodyset = self._bodyset
        if ground is None or bodyset is None:
            return
        ground.create_render_target()
        if ground.render_target is None:
            return

        scale = ground._normalized_texture_scale()
        inv_scale = 1.0 / scale
        offset = 2.0 * scale / float(ground.width)
        ground._set_texture_filters((bodyset,), point=True)

        rl.begin_texture_mode(ground.render_target)
        with _maybe_alpha_test(ground.alpha_test):
            ground._draw_corpse_shadow_pass(bodyset, [self._corpse_decal()], inv_scale, offset)
        rl.end_texture_mode()

        ground._set_texture_filters((bodyset,), point=False)
        ground._render_target_ready = True

    def _bake_color_only(self) -> None:
        ground = self._ground
        bodyset = self._bodyset
        if ground is None or bodyset is None:
            return
        ground.bake_corpse_decals(bodyset, [self._corpse_decal()], shadow=False)

    def _apply_step(self) -> None:
        step = _STEPS[self._step_index]
        if step.name == "clear":
            self._clear_ground()
        elif step.name == "shadow":
            self._bake_shadow_only()
        elif step.name == "color":
            self._bake_color_only()

    def open(self) -> None:
        rl.set_window_size(WINDOW_W, WINDOW_H)
        self._missing_assets.clear()
        self._owned_textures.clear()
        self._ground = None
        self._bodyset = None
        self.close_requested = False
        self._step_index = 0

        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        base_path = resolve_asset_path(self._assets_root, "ter/ter_q1_base.png")
        bodyset_path = resolve_asset_path(self._assets_root, "game/bodyset.png")
        if base_path is None:
            self._missing_assets.append("ter/ter_q1_base.png")
        if bodyset_path is None:
            self._missing_assets.append("game/bodyset.png")
        if self._missing_assets:
            raise FileNotFoundError("Missing assets: " + ", ".join(self._missing_assets))

        base = rl.load_texture(str(base_path))
        bodyset = rl.load_texture(str(bodyset_path))
        self._owned_textures.extend([base, bodyset])
        self._bodyset = bodyset

        texture_scale, screen_w, screen_h = self._load_runtime_config()
        self._ground = GroundRenderer(
            texture=base,
            width=int(WORLD_SIZE),
            height=int(WORLD_SIZE),
            texture_scale=float(texture_scale),
            screen_width=screen_w,
            screen_height=screen_h,
        )
        self._ground.alpha_test = True
        self._clear_ground()

    def close(self) -> None:
        if self._ground is not None and self._ground.render_target is not None:
            rl.unload_render_texture(self._ground.render_target)
            self._ground.render_target = None
        self._ground = None
        self._bodyset = None

        for texture in self._owned_textures:
            rl.unload_texture(texture)
        self._owned_textures.clear()

        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        del dt
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._step_index = 0
            self._clear_ground()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_A):
            if self._ground is not None:
                self._ground.alpha_test = not bool(self._ground.alpha_test)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_N) or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._step_index = (self._step_index + 1) % len(_STEPS)
            self._apply_step()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_D):
            self._dump_requested = True

        if rl.is_key_down(rl.KeyboardKey.KEY_Q):
            self._corpse_rotation -= 0.04
        if rl.is_key_down(rl.KeyboardKey.KEY_E):
            self._corpse_rotation += 0.04

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def draw(self) -> None:
        rl.clear_background(BG)

        if self._missing_assets:
            draw_ui_text(
                self._small, "Missing assets: " + ", ".join(self._missing_assets), Vec2(24, 24), color=UI_ERROR
            )
            return

        ground = self._ground
        if ground is None:
            draw_ui_text(self._small, "Ground renderer not initialized.", Vec2(24, 24), color=UI_ERROR)
            return

        if self._dump_requested:
            self._dump_requested = False
            self._dump_render_target()

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        camera = Vec2(screen_w * 0.5 - WORLD_SIZE * 0.5, screen_h * 0.5 - WORLD_SIZE * 0.5)
        ground.draw(camera, screen_w=screen_w, screen_h=screen_h)

        # UI
        x = 24.0
        y = 20.0
        line = float(ui_line_height(self._small))
        step = _STEPS[self._step_index]
        alpha_test = bool(getattr(ground, "alpha_test", True))
        draw_ui_text(self._small, "Corpse stamp debug (SPIDER)", Vec2(x, y), color=UI_TEXT)
        y += line
        draw_ui_text(
            self._small,
            "N/Space: next step   R: reset   A: toggle alpha test   Q/E: rotate   P: screenshot   D: dump RT",
            Vec2(x, y),
            color=UI_HINT,
        )
        y += line
        draw_ui_text(
            self._small, f"step {self._step_index + 1}/{len(_STEPS)}: {step.description}", Vec2(x, y), color=UI_HINT
        )
        y += line
        draw_ui_text(
            self._small,
            f"alpha_test={'on' if alpha_test else 'off'}  size={self._corpse_size:.1f}  dump_index={self._dump_index}",
            Vec2(x, y),
            color=UI_HINT,
        )

        # Source preview (bodyset frame) in the corner for inspection.
        if self._bodyset is not None:
            frame = creature_corpse_frame_for_type(int(CreatureTypeId.SPIDER_SP1))
            src = ground._corpse_src(self._bodyset, int(frame))
            preview = 256.0
            pad = 18.0
            dst = rl.Rectangle(screen_w - preview - pad, pad, preview, preview)
            rl.draw_rectangle(int(dst.x) - 2, int(dst.y) - 2, int(preview) + 4, int(preview) + 4, rl.Color(0, 0, 0, 30))
            rl.draw_texture_pro(self._bodyset, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)


@register_view("corpse-stamp-debug", "Corpse stamp debug")
def build_corpse_stamp_debug_view(ctx: ViewContext) -> View:
    return CorpseStampDebugView(ctx)
