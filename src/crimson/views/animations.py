from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from ..spawn_templates import CreatureFlags, CreatureTypeId, SPAWN_TEMPLATES, SpawnTemplate
from .registry import register_view
from .types import View, ViewContext


@dataclass(frozen=True, slots=True)
class TypeAnimInfo:
    base: int
    anim_rate: float
    mirror: bool


TYPE_ANIM: dict[CreatureTypeId, TypeAnimInfo] = {
    CreatureTypeId.ZOMBIE: TypeAnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: TypeAnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: TypeAnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: TypeAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: TypeAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: TypeAnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}


class CreatureAnimationView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._textures: dict[str, rl.Texture] = {}
        self._templates: list[SpawnTemplate] = [
            entry
            for entry in SPAWN_TEMPLATES
            if entry.type_id is not None and entry.creature is not None
        ]
        self._index = 0
        self._phase = 0.0

    def open(self) -> None:
        self._missing_assets.clear()
        self._textures.clear()
        for entry in self._templates:
            if entry.creature is None:
                continue
            if entry.creature in self._textures:
                continue
            path = self._assets_root / "crimson" / "game" / f"{entry.creature}.png"
            if not path.is_file():
                self._missing_assets.append(str(path))
                continue
            self._textures[entry.creature] = rl.load_texture(str(path))

    def close(self) -> None:
        for texture in self._textures.values():
            rl.unload_texture(texture)
        self._textures.clear()

    def update(self, dt: float) -> None:
        template = self._current_template()
        if template is None or template.type_id is None:
            return
        info = TYPE_ANIM.get(template.type_id)
        if info is None:
            return
        self._phase += info.anim_rate * dt * 60.0

    def _current_template(self) -> SpawnTemplate | None:
        if not self._templates:
            return None
        return self._templates[self._index]

    def _advance_template(self, delta: int) -> None:
        if not self._templates:
            return
        self._index = (self._index + delta) % len(self._templates)
        self._phase = 0.0

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._advance_template(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._advance_template(-1)

    def _select_frame(
        self, template: SpawnTemplate, info: TypeAnimInfo
    ) -> tuple[int, bool, str]:
        flags = template.flags or CreatureFlags(0)
        long_strip = not (flags & CreatureFlags.ANIM_PING_PONG) or (
            flags & CreatureFlags.ANIM_LONG_STRIP
        )
        if long_strip:
            base_frame = int(self._phase) % 32
            frame = base_frame
            if flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                frame += 0x20
            mirror = info.mirror and base_frame >= 16
            return frame, mirror, "long"
        phase = int(self._phase) % 16
        if phase >= 8:
            phase = 15 - phase
        frame = info.base + 0x10 + phase
        return frame, False, "ping-pong"

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            rl.draw_text(message, 24, 24, 20, rl.Color(240, 80, 80, 255))
            return
        if not self._templates:
            rl.draw_text("No spawn templates loaded.", 24, 24, 20, rl.WHITE)
            return

        self._handle_input()
        template = self._current_template()
        if template is None or template.type_id is None or template.creature is None:
            rl.draw_text("Invalid template.", 24, 24, 20, rl.WHITE)
            return
        texture = self._textures.get(template.creature)
        if texture is None:
            rl.draw_text("Missing texture for creature.", 24, 24, 20, rl.WHITE)
            return
        info = TYPE_ANIM.get(template.type_id)
        if info is None:
            rl.draw_text("Missing anim info.", 24, 24, 20, rl.WHITE)
            return

        frame, mirror, mode = self._select_frame(template, info)
        grid = 8
        cell = texture.width / grid
        row = frame // grid
        col = frame % grid

        margin = 24
        title = f"{template.creature} (spawn 0x{template.spawn_id:02x})"
        rl.draw_text(title, margin, margin, 22, rl.Color(220, 220, 220, 255))
        hint = "Left/Right: spawn template"
        rl.draw_text(hint, margin, margin + 28, 16, rl.Color(140, 140, 140, 255))

        sheet_scale = min(
            1.0,
            (rl.get_screen_width() * 0.55 - margin * 2) / texture.width,
            (rl.get_screen_height() - margin * 2 - 60) / texture.height,
        )
        sheet_x = margin
        sheet_y = margin + 60
        sheet_w = texture.width * sheet_scale
        sheet_h = texture.height * sheet_scale

        src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
        dst = rl.Rectangle(float(sheet_x), float(sheet_y), float(sheet_w), float(sheet_h))
        rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        cell_w = sheet_w / grid
        cell_h = sheet_h / grid
        highlight = rl.Rectangle(
            float(sheet_x + col * cell_w),
            float(sheet_y + row * cell_h),
            float(cell_w),
            float(cell_h),
        )
        rl.draw_rectangle_lines_ex(highlight, 2, rl.Color(240, 200, 80, 255))

        preview_scale = 3.0
        preview_size = cell * preview_scale
        preview_x = sheet_x + sheet_w + 40
        preview_y = sheet_y + 40
        src_frame = rl.Rectangle(
            float(col * cell),
            float(row * cell),
            float(cell),
            float(cell),
        )
        dst_frame = rl.Rectangle(float(preview_x), float(preview_y), float(preview_size), float(preview_size))
        if mirror:
            dst_frame.x += dst_frame.width
            dst_frame.width = -dst_frame.width
        rl.draw_texture_pro(texture, src_frame, dst_frame, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        info_lines = [
            f"type_id={template.type_id.name}",
            f"flags={int(template.flags or 0):#x}",
            f"mode={mode}",
            f"frame=0x{frame:02x}",
            f"phase={self._phase:.2f}",
            f"mirror={'yes' if mirror else 'no'}",
        ]
        y = int(preview_y + preview_size + 16)
        for line in info_lines:
            rl.draw_text(line, int(preview_x), y, 18, rl.Color(200, 200, 200, 255))
            y += 20


@register_view("animations", "Creature animation preview")
def build_animation_view(ctx: ViewContext) -> View:
    return CreatureAnimationView(ctx)
