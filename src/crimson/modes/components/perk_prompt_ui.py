from __future__ import annotations

from collections.abc import Callable

from grim.assets import RuntimeResources, TextureId
from grim.config import CrimsonConfig
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...ui.perk_menu import draw_ui_text

PERK_PROMPT_MAX_TIMER_MS = 200.0
PERK_PROMPT_OUTSET_X = 50.0
# Perk prompt bar geometry comes from `ui_menu_assets_init` + `ui_menu_layout_init`:
# - `ui_menu_item_element` is set_rect(512x64, offset -72,-60)
# - the perk prompt mutates quad coords: x = (x - 300) * 0.75, y = y * 0.75
PERK_PROMPT_BAR_SCALE = 0.75
PERK_PROMPT_BAR_BASE_OFFSET_X = -72.0
PERK_PROMPT_BAR_BASE_OFFSET_Y = -60.0
PERK_PROMPT_BAR_SHIFT_X = -300.0

# `ui_textLevelUp` is set_rect(75x25, offset -230,-27), then its quad coords are:
# x = x * 0.85 - 46, y = y * 0.85 - 4
PERK_PROMPT_LEVEL_UP_SCALE = 0.85
PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X = -230.0
PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y = -27.0
PERK_PROMPT_LEVEL_UP_BASE_W = 75.0
PERK_PROMPT_LEVEL_UP_BASE_H = 25.0
PERK_PROMPT_LEVEL_UP_SHIFT_X = -46.0
PERK_PROMPT_LEVEL_UP_SHIFT_Y = -4.0

PERK_PROMPT_TEXT_MARGIN_X = 16.0
PERK_PROMPT_TEXT_OFFSET_Y = 8.0


class PerkPromptUi:
    @staticmethod
    def label(config: CrimsonConfig, *, pending_count: int) -> str:
        if not config.ui_info_texts:
            return ""
        pending = int(pending_count)
        if pending <= 0:
            return ""
        suffix = f" ({pending})" if pending > 1 else ""
        return f"Press Mouse2 to pick a perk{suffix}"

    @staticmethod
    def hinge(*, screen_w: float | None = None) -> Vec2:
        if screen_w is None:
            screen_w = float(rl.get_screen_width())
        hinge_x = float(screen_w) + PERK_PROMPT_OUTSET_X
        hinge_y = 80.0 if int(screen_w) == 640 else 40.0
        return Vec2(hinge_x, hinge_y)

    @classmethod
    def rect(
        cls,
        *,
        resources: RuntimeResources,
        scale: float = 1.0,
    ) -> Rect:
        hinge = cls.hinge()
        tex = resources.texture(TextureId.UI_MENU_ITEM)
        bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
        bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
        local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
        local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
        return Rect.from_top_left(
            hinge.offset(dx=local_x, dy=local_y),
            bar_w,
            bar_h,
        )

    @classmethod
    def draw(
        cls,
        *,
        resources: RuntimeResources,
        label: str,
        timer_ms: float,
        pulse: float,
        ui_text_width: Callable[[str, float], int],
        text_color: rl.Color,
        scale: float = 1.0,
    ) -> None:
        alpha = float(timer_ms) / PERK_PROMPT_MAX_TIMER_MS
        if alpha <= 1e-3:
            return

        hinge = cls.hinge()
        # Prompt swings counter-clockwise; raylib's Y-down makes positive rotation clockwise.
        rot_deg = -(1.0 - alpha) * 90.0
        tint = rl.Color(255, 255, 255, int(255 * alpha))

        text_scale = float(scale)
        text_w = float(ui_text_width(label, text_scale))
        x = float(rl.get_screen_width()) - PERK_PROMPT_TEXT_MARGIN_X - text_w
        y = hinge.y + PERK_PROMPT_TEXT_OFFSET_Y
        color = rl.Color(int(text_color.r), int(text_color.g), int(text_color.b), int(255 * alpha))
        draw_ui_text(resources, label, Vec2(x, y), scale=text_scale, color=color)

        tex = resources.texture(TextureId.UI_MENU_ITEM)
        bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
        bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
        local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
        local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
        # Raylib clamps out-of-range UVs when the texture wrap mode is CLAMP.
        # Using src.x=tex.width with a negative width relies on REPEAT wrap to
        # wrap UVs back into range, making the bar disappear when clamped.
        src = rl.Rectangle(0.0, 0.0, -float(tex.width), float(tex.height))
        dst = rl.Rectangle(hinge.x, hinge.y, bar_w, bar_h)
        origin = rl.Vector2(float(-local_x), float(-local_y))
        rl.draw_texture_pro(tex, src, dst, origin, rot_deg, tint)

        tex = resources.texture(TextureId.UI_TEXT_LEVEL_UP)
        local_x = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_X
        local_y = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_Y
        w = PERK_PROMPT_LEVEL_UP_BASE_W * PERK_PROMPT_LEVEL_UP_SCALE
        h = PERK_PROMPT_LEVEL_UP_BASE_H * PERK_PROMPT_LEVEL_UP_SCALE
        pulse_alpha = (100.0 + float(int(float(pulse) * 155.0 / 1000.0))) / 255.0
        pulse_alpha = max(0.0, min(1.0, pulse_alpha))
        label_alpha = max(0.0, min(1.0, alpha * pulse_alpha))
        pulse_tint = rl.Color(255, 255, 255, int(255 * label_alpha))
        src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
        dst = rl.Rectangle(hinge.x, hinge.y, w, h)
        origin = rl.Vector2(float(-local_x), float(-local_y))
        rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
        if label_alpha > 0.0:
            rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
            rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
            rl.end_blend_mode()
