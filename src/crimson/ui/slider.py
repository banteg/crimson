from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.geom import Vec2
from grim.raylib_api import rl

from .focus import UiFocus


class UiSegmentedSlider(msgspec.Struct):
    """Native `ui_segmented_slider_t`: `max` 8x16 segments, the first `value` of them lit."""

    value: int = 0
    max: int = 10
    min: int = 0
    enabled: bool = True
    focused: bool = False


def ui_segmented_slider_update(
    focus: UiFocus, slider: UiSegmentedSlider, pos: Vec2, *, mouse: Vec2, down: bool,
) -> None:
    """`ui_segmented_slider_update`'s input half.

    Hovering (3px either side of the segments, a pixel above and 18px tall) focuses the slider; Left/Right step it
    while focused, down to 0. While the button is down on it, the value is the segment under the mouse, so the
    first segment is 0 (then `min`): nothing holds a drag once the mouse leaves the slider.
    """
    focused = focus.update(slider)
    slider.focused = focused
    # `ui_mouse_inside_rect`: strictly inside.
    hovered = (
        pos.x - 3.0 < mouse.x < pos.x - 3.0 + float(slider.max * 8 + 6)
        and pos.y - 1.0 < mouse.y < pos.y - 1.0 + 18.0
    )
    if hovered:
        focus.set(slider)
    if focused and slider.enabled:
        if focus.right:
            slider.value = min(slider.max, slider.value + 1)
        if focus.left:
            slider.value = max(0, slider.value - 1)
    if hovered and down and slider.enabled:
        slider.value = int((mouse.x - pos.x) * 0.125)
        if slider.value < slider.min:
            slider.value = slider.min
        if slider.value > slider.max:
            slider.value = slider.max


def ui_segmented_slider_draw(resources: RuntimeResources, focus: UiFocus, slider: UiSegmentedSlider, pos: Vec2) -> None:
    """`ui_segmented_slider_update`'s draw half: the focus marker 16px left, every segment as `ui_rectOff` at half
    alpha, then the first `value` as `ui_rectOn` over them."""
    if slider.focused:
        focus.draw(pos.offset(dx=-16.0))
    rect_off = resources.texture(TextureId.UI_RECT_OFF)
    for i in range(slider.max):
        rl.draw_texture_pro(
            rect_off,
            rl.Rectangle(0.0, 0.0, float(rect_off.width), float(rect_off.height)),
            rl.Rectangle(pos.x + float(i * 8), pos.y, 8.0, 16.0),
            rl.Vector2(0.0, 0.0),
            0.0,
            grim_color(1.0, 1.0, 1.0, 0.5),
        )
    rect_on = resources.texture(TextureId.UI_RECT_ON)
    for i in range(slider.value):
        rl.draw_texture_pro(
            rect_on,
            rl.Rectangle(0.0, 0.0, float(rect_on.width), float(rect_on.height)),
            rl.Rectangle(pos.x + float(i * 8), pos.y, 8.0, 16.0),
            rl.Vector2(0.0, 0.0),
            0.0,
            grim_color(1.0, 1.0, 1.0, 1.0),
        )


__all__ = ["UiSegmentedSlider", "ui_segmented_slider_draw", "ui_segmented_slider_update"]
