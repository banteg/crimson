from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from ..creatures.anim import creature_anim_advance_phase, creature_anim_select_frame
from ..creatures.spawn_templates import CreatureFlags, CreatureTypeId, SPAWN_TEMPLATES, SpawnTemplate
from .font_small import SmallFontData, draw_small_text, load_small_font
from .registry import register_view
from grim.view import View, ViewContext

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


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
        self._small: SmallFontData | None = None
        self._templates: list[SpawnTemplate] = [
            entry for entry in SPAWN_TEMPLATES if entry.type_id is not None and entry.creature is not None
        ]
        self._index = 0
        self._phase = 0.0
        self._move_speed = 2.0
        self._size = 50.0
        self._local_scale = 1.0
        self._paused = False
        self._last_dt = 0.0
        self._last_step = 0.0
        self._apply_template_defaults()

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
        self._textures.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
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
        if self._missing_assets:
            raise FileNotFoundError(f"Missing creature textures: {', '.join(self._missing_assets)}")

    def close(self) -> None:
        for texture in self._textures.values():
            rl.unload_texture(texture)
        self._textures.clear()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        self._last_dt = dt
        if self._paused:
            self._last_step = 0.0
            return
        template = self._current_template()
        if template is None or template.type_id is None:
            return
        info = TYPE_ANIM.get(template.type_id)
        if info is None:
            return
        flags = template.flags or CreatureFlags(0)
        self._phase, self._last_step = creature_anim_advance_phase(
            self._phase,
            anim_rate=info.anim_rate,
            move_speed=self._move_speed,
            dt=dt,
            size=self._size,
            local_scale=self._local_scale,
            flags=flags,
            ai_mode=0,
        )

    def _current_template(self) -> SpawnTemplate | None:
        if not self._templates:
            return None
        return self._templates[self._index]

    def _advance_template(self, delta: int) -> None:
        if not self._templates:
            return
        self._index = (self._index + delta) % len(self._templates)
        self._phase = 0.0
        self._apply_template_defaults()

    def _apply_template_defaults(self) -> None:
        template = self._current_template()
        if template is None:
            return
        self._move_speed = template.move_speed if template.move_speed is not None else 2.0
        self._size = template.size if template.size is not None else 50.0

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._advance_template(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._advance_template(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._move_speed = min(10.0, self._move_speed + 0.1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._move_speed = max(0.0, self._move_speed - 0.1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
            self._size = min(200.0, self._size + 1.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._size = max(1.0, self._size - 1.0)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._local_scale = min(1.0, self._local_scale + 0.05)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._local_scale = max(0.0, self._local_scale - 0.05)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not self._paused
        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._phase = 0.0

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return
        if not self._templates:
            self._draw_ui_text("No spawn templates loaded.", 24, 24, UI_TEXT_COLOR)
            return

        self._handle_input()
        template = self._current_template()
        if template is None or template.type_id is None or template.creature is None:
            self._draw_ui_text("Invalid template.", 24, 24, UI_TEXT_COLOR)
            return
        texture = self._textures.get(template.creature)
        if texture is None:
            self._draw_ui_text("Missing texture for creature.", 24, 24, UI_TEXT_COLOR)
            return
        info = TYPE_ANIM.get(template.type_id)
        if info is None:
            self._draw_ui_text("Missing anim info.", 24, 24, UI_TEXT_COLOR)
            return

        frame, mirror_applied, mode = creature_anim_select_frame(
            self._phase,
            base_frame=info.base,
            mirror_long=info.mirror,
            flags=template.flags or CreatureFlags(0),
        )
        grid = 8
        cell = texture.width / grid
        row = frame // grid
        col = frame % grid

        margin = 24
        title = f"{template.creature} (spawn 0x{template.spawn_id:02x})"
        self._draw_ui_text(title, margin, margin, UI_TEXT_COLOR)
        hint = (
            "Left/Right: spawn template  Up/Down: move_speed  PgUp/PgDn: size  "
            "[/]: local scale  Space: pause  R: reset"
        )
        self._draw_ui_text(hint, margin, margin + self._ui_line_height() + 6, UI_HINT_COLOR)

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
        tint_r = template.tint_r if template.tint_r is not None else 1.0
        tint_g = template.tint_g if template.tint_g is not None else 1.0
        tint_b = template.tint_b if template.tint_b is not None else 1.0
        tint_a = template.tint_a if template.tint_a is not None else 1.0
        tint = rl.Color(
            max(0, min(255, int(tint_r * 255))),
            max(0, min(255, int(tint_g * 255))),
            max(0, min(255, int(tint_b * 255))),
            max(0, min(255, int(tint_a * 255))),
        )
        rl.draw_texture_pro(texture, src_frame, dst_frame, rl.Vector2(0.0, 0.0), 0.0, tint)

        info_lines = [
            f"type_id={template.type_id.name}",
            f"flags={int(template.flags or 0):#x}",
            f"mode={mode}",
            f"frame=0x{frame:02x}",
            f"phase={self._phase:.6f}",
            f"template.move_speed={template.move_speed!r}",
            f"template.size={template.size!r}",
            f"template.tint=({template.tint_r!r}, {template.tint_g!r}, {template.tint_b!r}, {template.tint_a!r})",
            f"move_speed={self._move_speed:.2f}",
            f"size={self._size:.1f}",
            f"local_scale={self._local_scale:.2f}",
            f"dt={self._last_dt:.4f}s  step={self._last_step:.6f}",
            f"mirror_applied={'yes' if mirror_applied else 'no'}",
            f"paused={'yes' if self._paused else 'no'}",
        ]
        y = int(preview_y + preview_size + 16)
        for line in info_lines:
            self._draw_ui_text(line, preview_x, y, UI_TEXT_COLOR)
            y += self._ui_line_height() + 4


@register_view("animations", "Creature animation preview")
def build_animation_view(ctx: ViewContext) -> View:
    return CreatureAnimationView(ctx)
