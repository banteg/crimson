from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.math import clamp
from grim.raylib_api import rl

from .focus import UiFocus

# Perk selection screen panel uses ui_element-style timeline animation:
# - fully hidden until end_ms
# - slides in over (end_ms..start_ms)
# - fully visible at start_ms

# Layout offsets from the classic game (perk selection screen), derived from
# `perk_selection_screen_update` (see analysis/ghidra + BN).
MENU_PANEL_ANCHOR_X = 224.0
MENU_PANEL_ANCHOR_Y = 40.0
MENU_TITLE_X = 54.0
MENU_TITLE_Y = 6.0
MENU_TITLE_W = 128.0
MENU_TITLE_H = 32.0
MENU_SPONSOR_Y = -8.0
MENU_SPONSOR_X_EXPERT = -26.0
MENU_SPONSOR_X_MASTER = -28.0
MENU_LIST_Y_NORMAL = 50.0
MENU_LIST_Y_EXPERT = 40.0
MENU_LIST_STEP_NORMAL = 19.0
MENU_LIST_STEP_EXPERT = 18.0
MENU_DESC_X = -12.0
MENU_DESC_Y_AFTER_LIST = 32.0
MENU_DESC_Y_EXTRA_TIGHTEN = 20.0
MENU_BUTTON_X = 162.0
MENU_BUTTON_Y = 276.0
MENU_DESC_RIGHT_X = 480.0


class PerkMenuComputedLayout(msgspec.Struct):
    panel: Rect
    title: Rect
    sponsor_pos: Vec2
    list_pos: Vec2
    list_step_y: float
    desc: Rect
    cancel_pos: Vec2


def perk_menu_compute_layout(
    panel: Rect,
    *,
    choice_count: int,
    expert_owned: bool,
    master_owned: bool,
) -> PerkMenuComputedLayout:
    """`perk_selection_screen_update` lays out on `ui_element_slot_27`'s panel."""
    anchor_pos = Vec2(
        panel.x + MENU_PANEL_ANCHOR_X,
        panel.y + MENU_PANEL_ANCHOR_Y,
    )

    title = Rect.from_top_left(
        anchor_pos.offset(dx=MENU_TITLE_X, dy=MENU_TITLE_Y),
        MENU_TITLE_W,
        MENU_TITLE_H,
    )

    sponsor_pos = Vec2(
        anchor_pos.x + (MENU_SPONSOR_X_MASTER if master_owned else MENU_SPONSOR_X_EXPERT),
        anchor_pos.y + MENU_SPONSOR_Y,
    )

    list_step_y = MENU_LIST_STEP_EXPERT if expert_owned else MENU_LIST_STEP_NORMAL
    list_pos = Vec2(
        anchor_pos.x,
        anchor_pos.y + (MENU_LIST_Y_EXPERT if expert_owned else MENU_LIST_Y_NORMAL),
    )

    desc_pos = Vec2(
        anchor_pos.x + MENU_DESC_X,
        list_pos.y + choice_count * list_step_y + MENU_DESC_Y_AFTER_LIST,
    )
    if choice_count > 5:
        desc_pos = desc_pos.offset(dy=-MENU_DESC_Y_EXTRA_TIGHTEN)

    # Keep the description within the monitor screen area and above the button.
    desc_right = panel.x + MENU_DESC_RIGHT_X
    cancel_pos = anchor_pos.offset(dx=MENU_BUTTON_X, dy=MENU_BUTTON_Y)
    desc_size = Vec2(
        max(0.0, desc_right - desc_pos.x),
        max(0.0, cancel_pos.y - 12.0 - desc_pos.y),
    )
    desc = Rect.from_pos_size(desc_pos, desc_size)

    return PerkMenuComputedLayout(
        panel=panel,
        title=title,
        sponsor_pos=sponsor_pos,
        list_pos=list_pos,
        list_step_y=list_step_y,
        desc=desc,
        cancel_pos=cancel_pos,
    )


def _ui_text_width(resources: RuntimeResources, text: str) -> float:
    return measure_small_text_width(resources.small_font, text)


def draw_ui_text(
    resources: RuntimeResources,
    text: str,
    pos: Vec2,
    *,
    color: rl.Color,
) -> None:
    draw_small_text(resources.small_font, text, pos, color)


MENU_ITEM_RGB = (0x46, 0xB4, 0xF0)  # from ui_menu_item_update: rgb(70, 180, 240)
MENU_ITEM_ALPHA_IDLE = 0.6
MENU_ITEM_ALPHA_HOVER = 1.0


def menu_item_hit_rect(resources: RuntimeResources, label: str, *, pos: Vec2) -> Rect:
    return Rect.from_top_left(pos, _ui_text_width(resources, label), 16.0)


def draw_menu_item(
    resources: RuntimeResources,
    label: str,
    *,
    pos: Vec2,
    hovered: bool,
) -> float:
    alpha = MENU_ITEM_ALPHA_HOVER if hovered else MENU_ITEM_ALPHA_IDLE
    r, g, b = MENU_ITEM_RGB
    color = rl.Color(int(r), int(g), int(b), int(255 * alpha))
    draw_ui_text(resources, label, pos, color=color)
    width = _ui_text_width(resources, label)
    if width <= 0.0:
        width = 8.0
    grim_draw_rect_outline(pos.offset(dy=13.0), width, 1.0, color)
    return width


class UiMenuItem(msgspec.Struct):
    """Native `ui_menu_item_t`: an underlined text row (perk choices, rebind rows)."""

    label: str = ""
    enabled: bool = True
    hovered: bool = False
    activated: bool = False
    focused: bool = False


def ui_menu_item_update(
    item: UiMenuItem, *, focus: UiFocus, hit: Rect, mouse: rl.Vector2 | Vec2, click: bool,
) -> bool:
    """`ui_menu_item_update`'s input half over the row's hit rect: a click, or Enter while focused."""
    focused = focus.update(item)
    item.focused = focused
    item.hovered = hit.contains(mouse)
    if item.hovered:
        focus.set(item)
    item.activated = item.enabled and ((focused and focus.enter) or (item.hovered and click))
    return item.activated


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
    if _ui_text_width(resources, state.label) < 40.0:
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
    text_w = _ui_text_width(resources, state.label)
    text_pos = Vec2(pos.x + width * 0.5 - text_w * 0.5 + 1.0, pos.y + 10.0)
    draw_ui_text(resources, state.label, text_pos, color=text_tint)
