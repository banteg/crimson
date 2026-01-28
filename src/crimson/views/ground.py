from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from crimson.creatures.anim import creature_corpse_frame_for_type
from crimson.effects import FxQueue, FxQueueRotated
from crimson.render.terrain_fx import FxQueueTextures, bake_fx_queues
from grim.assets import resolve_asset_path
from grim.config import ensure_crimson_cfg
from grim.terrain_render import GroundRenderer
from ..quests import all_quests
from ..quests.types import QuestDefinition
from .quest_title_overlay import draw_quest_title_overlay
from .registry import register_view
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.view import View, ViewContext


UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(slots=True)
class GroundAssets:
    textures: dict[int, rl.Texture]


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


class GroundView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._assets: GroundAssets | None = None
        self._renderer: GroundRenderer | None = None
        self._camera_x = 0.0
        self._camera_y = 0.0
        self._quests: list[QuestDefinition] = []
        self._quest_index = 0
        self._terrain_seed: int | None = None
        self._fx_queue = FxQueue()
        self._fx_queue_rotated = FxQueueRotated()
        self._fx_textures: FxQueueTextures | None = None

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

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        self._grim_mono = load_grim_mono_font(self._assets_root, self._missing_assets)
        textures: dict[int, rl.Texture] = {}
        for terrain_id, rel_path in TERRAIN_TEXTURES:
            path = resolve_asset_path(self._assets_root, rel_path)
            if path is None:
                self._missing_assets.append(rel_path)
                continue
            textures[terrain_id] = rl.load_texture(str(path))
        if self._missing_assets:
            raise FileNotFoundError(f"Missing ground assets: {', '.join(self._missing_assets)}")
        self._assets = GroundAssets(textures=textures)
        self._quests = all_quests()
        self._fx_queue.clear()
        self._fx_queue_rotated.clear()
        particles_path = resolve_asset_path(self._assets_root, "game/particles.png")
        if particles_path is None:
            self._missing_assets.append("game/particles.png")
        bodyset_path = resolve_asset_path(self._assets_root, "game/bodyset.png")
        if bodyset_path is None:
            self._missing_assets.append("game/bodyset.png")
        if self._missing_assets:
            raise FileNotFoundError(f"Missing ground assets: {', '.join(self._missing_assets)}")
        self._fx_textures = FxQueueTextures(
            particles=rl.load_texture(str(particles_path)),
            bodyset=rl.load_texture(str(bodyset_path)),
        )
        texture_scale, screen_w, screen_h = self._load_runtime_config()
        if self._renderer is not None:
            self._renderer.texture_scale = texture_scale
            self._renderer.screen_width = screen_w
            self._renderer.screen_height = screen_h
        self._quest_index = 0
        self._apply_quest()

    def close(self) -> None:
        if self._assets is not None:
            for texture in self._assets.textures.values():
                rl.unload_texture(texture)
            self._assets = None
        if self._renderer is not None and self._renderer.render_target is not None:
            rl.unload_render_texture(self._renderer.render_target)
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        if self._fx_textures is not None:
            rl.unload_texture(self._fx_textures.particles)
            rl.unload_texture(self._fx_textures.bodyset)
            self._fx_textures = None
        self._fx_queue.clear()
        self._fx_queue_rotated.clear()

    def update(self, dt: float) -> None:
        speed = 240.0
        if rl.is_key_down(rl.KeyboardKey.KEY_A):
            self._camera_x += speed * dt
        if rl.is_key_down(rl.KeyboardKey.KEY_D):
            self._camera_x -= speed * dt
        if rl.is_key_down(rl.KeyboardKey.KEY_W):
            self._camera_y += speed * dt
        if rl.is_key_down(rl.KeyboardKey.KEY_S):
            self._camera_y -= speed * dt
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._quest_index = (self._quest_index - 1) % max(1, len(self._quests))
            self._apply_quest()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._quest_index = (self._quest_index + 1) % max(1, len(self._quests))
            self._apply_quest()
        if self._renderer is not None:
            self._renderer.process_pending()
            if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                mouse = rl.get_mouse_position()
                world_x = -self._camera_x + float(mouse.x)
                world_y = -self._camera_y + float(mouse.y)
                self._fx_queue.add(
                    effect_id=0x07,  # blood
                    pos_x=world_x,
                    pos_y=world_y,
                    width=30.0,
                    height=30.0,
                    rotation=0.0,
                    rgba=(1.0, 1.0, 1.0, 1.0),
                )
            if self._fx_textures is not None and (self._fx_queue.count or self._fx_queue_rotated.count):
                bake_fx_queues(
                    self._renderer,
                    fx_queue=self._fx_queue,
                    fx_queue_rotated=self._fx_queue_rotated,
                    textures=self._fx_textures,
                    corpse_frame_for_type=creature_corpse_frame_for_type,
                )

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return
        if self._renderer is None:
            self._draw_ui_text("Ground renderer not initialized.", 24, 24, UI_ERROR_COLOR)
            return
        self._renderer.draw(self._camera_x, self._camera_y)
        self._draw_quest_title_overlay()

    def _load_runtime_config(self) -> tuple[float, float | None, float | None]:
        runtime_dir = Path("artifacts") / "runtime"
        if runtime_dir.is_dir():
            try:
                cfg = ensure_crimson_cfg(runtime_dir)
                return (
                    cfg.texture_scale,
                    float(cfg.screen_width),
                    float(cfg.screen_height),
                )
            except Exception:
                return 1.0, None, None
        return 1.0, None, None

    def _apply_quest(self) -> None:
        if not self._quests or self._assets is None:
            return
        quest = self._quests[self._quest_index]
        base_id, overlay_id, detail_id = quest.terrain_ids or (0, 1, 0)
        textures = self._assets.textures
        base = textures.get(base_id)
        if base is None:
            return
        overlay = textures.get(overlay_id)
        detail = textures.get(detail_id)
        if self._renderer is None:
            texture_scale, screen_w, screen_h = self._load_runtime_config()
            self._renderer = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=1024,
                height=1024,
                texture_scale=texture_scale,
                screen_width=screen_w,
                screen_height=screen_h,
            )
        else:
            self._renderer.texture = base
            self._renderer.overlay = overlay
            self._renderer.overlay_detail = detail
        self._terrain_seed = self._quest_seed(quest.level)
        self._regenerate_terrain(reset_camera=True)

    def _regenerate_terrain(self, *, reset_camera: bool = False) -> None:
        renderer = self._renderer
        if renderer is None:
            return
        renderer.schedule_generate(seed=self._terrain_seed, layers=3)
        if reset_camera:
            self._camera_x = 0.0
            self._camera_y = 0.0

    def _quest_seed(self, level: str) -> int:
        tier_text, quest_text = level.split(".", 1)
        try:
            return int(tier_text) * 100 + int(quest_text)
        except ValueError:
            return sum(ord(ch) for ch in level)

    def _draw_quest_title_overlay(self) -> None:
        if self._grim_mono is None or not self._quests:
            return
        quest = self._quests[self._quest_index]
        draw_quest_title_overlay(self._grim_mono, quest.title, quest.level)


@register_view("ground", "Ground texture")
def build_ground_view(ctx: ViewContext) -> View:
    return GroundView(ctx)
