from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
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
