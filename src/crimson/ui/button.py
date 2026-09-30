from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.math import clamp
from grim.raylib_api import rl

from .focus import UiFocus


class UiButtonState(msgspec.Struct):
    label: str
    enabled: bool = True
    hovered: bool = False
    activated: bool = False
    hover_t: int = 0  # 0..1000
    press_t: int = 0  # 0..1000
    alpha: float = 1.0
    force_wide: bool = False
    # Whether it held the keyboard focus this frame (`ui_focus_update`), for the draw half's marker.
    focused: bool = False


def _resolve_button_textures(resources: RuntimeResources) -> tuple[rl.Texture, rl.Texture]:
    return (
        resources.texture(TextureId.UI_BUTTON_SM),
        resources.texture(TextureId.UI_BUTTON_MD),
    )


def button_width(resources: RuntimeResources, state: UiButtonState) -> float:
    """`ui_button_update` picks the plate from the label: 82px under 40px of text, else 145px."""
    if state.force_wide:
        return 145.0
    if measure_small_text_width(resources.small_font, state.label) < 40.0:
        return 82.0
    return 145.0


def button_hit_rect(*, pos: Vec2, width: float) -> Rect:
    # Mirrors ui_button_update: y is offset by +2, hit height is 0x1c (28).
    return Rect.from_top_left(pos.offset(dy=2.0), width, 28.0)


def button_update(
    resources: RuntimeResources,
    state: UiButtonState,
    *,
    focus: UiFocus,
    pos: Vec2,
    dt_ms: float,
    mouse: rl.Vector2,
    click: bool,
) -> bool:
    """`ui_button_update`'s input half: a click on the plate, or Enter while it holds the focus."""
    focused = focus.update(state)
    state.focused = focused
    if not state.enabled:
        state.hovered = False
    else:
        state.hovered = button_hit_rect(pos=pos, width=button_width(resources, state)).contains(mouse)
    if state.hovered:
        focus.set(state)

    # The highlight also comes up for a second after Tab lands on the button.
    lit = state.enabled and (state.hovered or (focused and focus.timer_ms > 800))
    delta = 6 if lit else -4
    state.hover_t = int(clamp(state.hover_t + int(dt_ms) * delta, 0.0, 1000.0))

    if state.press_t > 0:
        state.press_t = int(clamp(state.press_t - int(dt_ms) * 6, 0.0, 1000.0))

    state.activated = bool(state.enabled and ((focused and focus.enter) or (state.hovered and click)))
    if state.activated:
        state.press_t = 1000
    return state.activated


def button_draw(
    resources: RuntimeResources,
    state: UiButtonState,
    *,
    focus: UiFocus,
    pos: Vec2,
) -> None:
    if state.focused:
        focus.draw(pos.offset(dx=-16.0))
    width = button_width(resources, state)
    button_sm, button_md = _resolve_button_textures(resources)
    texture = button_md if width > 120.0 else button_sm

    if state.hover_t > 0:
        # ui_button_update: highlight fill uses a hover-scaled alpha and click-biased blue tint.
        # - base: (0.5, 0.5, 0.7)
        # - click_anim: +0.0005 / +0.0007, clamped to 1.0 (towards white)
        # - alpha: hover_anim * 0.001 * button.alpha
        r = 0.5
        g = 0.5
        b = 0.7
        if state.press_t > 0:
            click_t = state.press_t
            g = min(1.0, 0.5 + click_t * 0.0005)
            r = g
            b = min(1.0, 0.7 + click_t * 0.0007)
        a = state.hover_t * 0.001 * state.alpha
        hl = rl.Color(
            int(255 * r),
            int(255 * g),
            int(255 * b),
            int(255 * clamp(a, 0.0, 1.0)),
        )
        rl.draw_rectangle(
            int(pos.x + 12.0),
            int(pos.y + 5.0),
            int(width - 24.0),
            22,
            hl,
        )

    plate_tint = rl.Color(255, 255, 255, int(255 * clamp(state.alpha, 0.0, 1.0)))

    src = rl.Rectangle(0.0, 0.0, texture.width, texture.height)
    dst = rl.Rectangle(pos.x, pos.y, width, 32.0)
    rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, plate_tint)

    text_a = state.alpha if state.hovered else state.alpha * 0.7
    text_tint = rl.Color(255, 255, 255, int(255 * clamp(text_a, 0.0, 1.0)))
    text_w = measure_small_text_width(resources.small_font, state.label)
    text_pos = Vec2(pos.x + width * 0.5 - text_w * 0.5 + 1.0, pos.y + 10.0)
    draw_small_text(resources.small_font, state.label, text_pos, text_tint)
