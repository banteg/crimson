from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.config import CrimsonConfig
from grim.geom import Rect, Vec2
from grim.math import clamp
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2

from ...input_codes import input_code_is_down, input_code_name, input_primary_just_pressed
from ...ui.perk_menu import draw_ui_text
from .perk_menu_controller import PerkMenuUiContext

UiTextWidthFn = Callable[[str], int]

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


@dataclass(slots=True)
class PerkPromptState:
    """Native `perk_prompt_timer`, `perk_prompt_hover_active`, `perk_prompt_pulse` and `mouse_button_down`."""

    timer_ms: float = 0.0
    hover: bool = False
    pulse: float = 0.0
    mouse_down: bool = False

    @staticmethod
    def label(config: CrimsonConfig) -> str:
        """`perk_prompt_update_and_render` draws the hint only with the info texts on."""
        if not config.gameplay.show_info_texts:
            return ""
        return f"Press {input_code_name(config.controls.pick_perk_code)} to pick a perk"

    @staticmethod
    def hinge(*, screen_w: float | None = None) -> Vec2:
        if screen_w is None:
            screen_w = float(canvas.width())
        hinge_x = float(screen_w) + PERK_PROMPT_OUTSET_X
        hinge_y = 80.0 if int(screen_w) == 640 else 40.0
        return Vec2(hinge_x, hinge_y)

    @classmethod
    def rect(cls, *, resources: RuntimeResources) -> Rect:
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

    def reset(self) -> None:
        self.timer_ms = 0.0
        self.hover = False
        self.pulse = 0.0
        self.mouse_down = False

    def tick_pulse(self, dt_ui_ms: float) -> None:
        """The sign glows up while hovered and fades otherwise; native runs this before the open check."""
        pulse_delta = float(dt_ui_ms) * (6.0 if self.hover else -2.0)
        self.pulse = clamp(self.pulse + pulse_delta, 0.0, 1000.0)

    def poll_open_request(
        self,
        *,
        ctx: PerkMenuUiContext,
        config: CrimsonConfig,
        pending_count: int,
        alive: bool,
        paused: bool,
        menu_active: bool,
        player_count: int,
    ) -> bool:
        """`gameplay_update_and_render`: the pick-perk key, Space, keypad + or a click on the sign opens the menu."""
        mouse_was_down = self.mouse_down
        self.mouse_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if paused or mouse_was_down or pending_count <= 0 or not alive or menu_active:
            return False
        if (
            input_code_is_down(config.controls.pick_perk_code, player_index=0)
            or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE)
            or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ADD)
        ):
            self.pulse = 1000.0
            return True
        self.hover = self.rect(resources=ctx.resources).contains(ctx.mouse)
        fire_codes = tuple(int(config.controls.player(idx).fire_code) for idx in range(4))
        return self.hover and input_primary_just_pressed(fire_codes=fire_codes, player_count=player_count)

    def tick_timer(self, *, pending_count: int, menu_active: bool, dt_ui_ms: float) -> None:
        """`perk_prompt_update_and_render`: swing in while a perk is pending in gameplay, out otherwise."""
        timer_delta = float(dt_ui_ms) if pending_count > 0 and not menu_active else -float(dt_ui_ms)
        self.timer_ms = clamp(self.timer_ms + timer_delta, 0.0, PERK_PROMPT_MAX_TIMER_MS)

    def draw(self, *, ctx: PerkMenuUiContext, config: CrimsonConfig, ui_text_width: UiTextWidthFn) -> None:
        alpha = float(self.timer_ms) / PERK_PROMPT_MAX_TIMER_MS
        if alpha <= 1e-3:
            return

        resources = ctx.resources
        label = self.label(config)
        hinge = self.hinge()
        # Prompt swings counter-clockwise; raylib's Y-down makes positive rotation clockwise.
        rot_deg = -(1.0 - alpha) * 90.0
        tint = rl_color(255, 255, 255, int(255 * alpha))

        if label:
            text_w = float(ui_text_width(label))
            x = float(canvas.width()) - PERK_PROMPT_TEXT_MARGIN_X - text_w
            y = hinge.y + PERK_PROMPT_TEXT_OFFSET_Y
            draw_ui_text(resources, label, Vec2(x, y), color=grim_color(1.0, 1.0, 1.0, alpha))

        tex = resources.texture(TextureId.UI_MENU_ITEM)
        bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
        bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
        local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
        local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
        # Raylib clamps out-of-range UVs when the texture wrap mode is CLAMP.
        # Using src.x=tex.width with a negative width relies on REPEAT wrap to
        # wrap UVs back into range, making the bar disappear when clamped.
        src = rl_rectangle(0.0, 0.0, -float(tex.width), float(tex.height))
        dst = rl_rectangle(hinge.x, hinge.y, bar_w, bar_h)
        origin = rl_vector2(float(-local_x), float(-local_y))
        rl.draw_texture_pro(tex, src, dst, origin, rot_deg, tint)

        tex = resources.texture(TextureId.UI_TEXT_LEVEL_UP)
        local_x = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_X
        local_y = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_Y
        w = PERK_PROMPT_LEVEL_UP_BASE_W * PERK_PROMPT_LEVEL_UP_SCALE
        h = PERK_PROMPT_LEVEL_UP_BASE_H * PERK_PROMPT_LEVEL_UP_SCALE
        pulse_alpha = (100.0 + float(int(float(self.pulse) * 155.0 / 1000.0))) / 255.0
        pulse_alpha = max(0.0, min(1.0, pulse_alpha))
        label_alpha = max(0.0, min(1.0, alpha * pulse_alpha))
        pulse_tint = rl_color(255, 255, 255, int(255 * label_alpha))
        src = rl_rectangle(0.0, 0.0, float(tex.width), float(tex.height))
        dst = rl_rectangle(hinge.x, hinge.y, w, h)
        origin = rl_vector2(float(-local_x), float(-local_y))
        rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
        if label_alpha > 0.0:
            rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
            rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
            rl.end_blend_mode()
