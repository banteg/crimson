from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2

from .focus import UiFocus


class UiCheckbox(msgspec.Struct):
    """Native `ui_checkbox_t`."""

    label: str
    checked: bool = False
    disabled: bool = False
    hovered: bool = False
    focused: bool = False


def ui_checkbox_width(resources: RuntimeResources, checkbox: UiCheckbox) -> float:
    """The box and its label, 22px right of the box's left edge."""
    return measure_small_text_width(resources.small_font, checkbox.label) + 22.0


def ui_checkbox_update(
    resources: RuntimeResources, checkbox: UiCheckbox, pos: Vec2, *, focus: UiFocus, mouse: Vec2, click: bool,
) -> bool:
    """`ui_checkbox_update`'s input half: the 16px box and its label are hot; a click, or Enter while it holds
    the focus, toggles it (not while a rebind locks the focus).

    Returns whether it toggled.
    """
    focused = focus.update(checkbox)
    checkbox.focused = focused
    width = ui_checkbox_width(resources, checkbox)
    # `ui_mouse_inside_rect`: strictly inside a 16px tall rect.
    checkbox.hovered = (
        not checkbox.disabled and pos.x < mouse.x < pos.x + width and pos.y < mouse.y < pos.y + 16.0
    )
    if checkbox.hovered:
        focus.set(checkbox)
    # Native lets Enter toggle a disabled checkbox; the port keeps it disabled.
    pressed = (focused and focus.enter and not checkbox.disabled) or (checkbox.hovered and click)
    if pressed and not focus.input_locked:
        checkbox.checked = not checkbox.checked
        return True
    return False


def ui_checkbox_draw(resources: RuntimeResources, checkbox: UiCheckbox, pos: Vec2, *, focus: UiFocus) -> None:
    """`ui_checkbox_update`'s draw half: the focus marker, the box at 16x16, the label 22px right, dimmed unless
    hovered."""
    if checkbox.focused:
        focus.draw(pos.offset(dx=-16.0))
    texture = resources.texture(TextureId.UI_CHECK_ON if checkbox.checked else TextureId.UI_CHECK_OFF)
    rl.draw_texture_pro(
        texture,
        rl_rectangle(0.0, 0.0, float(texture.width), float(texture.height)),
        rl_rectangle(pos.x, pos.y, 16.0, 16.0),
        rl_vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )
    alpha = 1.0 if checkbox.hovered else 0.7
    draw_small_text(resources.small_font, checkbox.label, pos.offset(dx=22.0, dy=1.0), grim_color(1.0, 1.0, 1.0, alpha))
