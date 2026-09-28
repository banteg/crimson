from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.math import clamp
from grim.raylib_api import rl

from .layout import menu_widescreen_y_shift

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


class PerkMenuLayout(msgspec.Struct):
    # Coordinates live in the original 640x480 UI space.
    # Capture (1024x768) shows the perk menu panel uses the 3-slice variant:
    #   open bbox (-108,119) -> (402,497)
    # which corresponds to ui_element pos (-45,110) + geom (-63,-81) and size 510x378.
    panel_pos: Vec2 = Vec2(-108.0, 29.0)
    panel_size: Vec2 = Vec2(510.0, 378.0)


class PerkMenuComputedLayout(msgspec.Struct):
    panel: Rect
    title: Rect
    sponsor_pos: Vec2
    list_pos: Vec2
    list_step_y: float
    desc: Rect
    cancel_pos: Vec2


def perk_menu_compute_layout(
    layout: PerkMenuLayout,
    *,
    screen_w: float,
    choice_count: int,
    expert_owned: bool,
    master_owned: bool,
    panel_slide_x: float = 0.0,
) -> PerkMenuComputedLayout:
    widescreen_shift_y = menu_widescreen_y_shift(screen_w)
    panel_pos = layout.panel_pos + Vec2(panel_slide_x, widescreen_shift_y)
    panel = Rect.from_pos_size(panel_pos, layout.panel_size)
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


def wrap_ui_text(resources: RuntimeResources, text: str, *, max_width: float) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines() or [""]:
        para = raw.strip()
        if not para:
            lines.append("")
            continue
        current = ""
        for word in para.split():
            candidate = word if not current else f"{current} {word}"
            if current and _ui_text_width(resources, candidate) > max_width:
                lines.append(current)
                current = word
            else:
                current = candidate
        if current:
            lines.append(current)
    return lines


def draw_wrapped_ui_text_in_rect(
    resources: RuntimeResources,
    text: str,
    *,
    rect: Rect,
    color: rl.Color,
) -> None:
    font = resources.small_font
    lines = wrap_ui_text(resources, text, max_width=rect.w)
    line_h = font.cell_size
    pos = rect.top_left
    max_y = rect.bottom
    for line in lines:
        if pos.y + line_h > max_y:
            break
        draw_ui_text(resources, line, pos, color=color)
        pos = pos.offset(dy=line_h)


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
    line_y = pos.y + 13.0
    rl.draw_line(int(pos.x), int(line_y), int(pos.x + width), int(line_y), color)
    return width


class UiButtonState(msgspec.Struct):
    label: str
    enabled: bool = True
    hovered: bool = False
    activated: bool = False
    hover_t: int = 0  # 0..1000
    press_t: int = 0  # 0..1000
    alpha: float = 1.0
    force_wide: bool = False


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
    pos: Vec2,
    dt_ms: float,
    mouse: rl.Vector2,
    click: bool,
    focused: bool = False,
) -> bool:
    if not state.enabled:
        state.hovered = False
    else:
        state.hovered = focused or button_hit_rect(pos=pos, width=button_width(resources, state)).contains(mouse)

    delta = 6 if (state.enabled and state.hovered) else -4
    state.hover_t = int(clamp(state.hover_t + int(dt_ms) * delta, 0.0, 1000.0))

    if state.press_t > 0:
        state.press_t = int(clamp(state.press_t - int(dt_ms) * 6, 0.0, 1000.0))

    state.activated = bool(state.enabled and state.hovered and click)
    if state.activated:
        state.press_t = 1000
    return state.activated


def button_draw(
    resources: RuntimeResources,
    state: UiButtonState,
    *,
    pos: Vec2,
) -> None:
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


def cursor_draw(resources: RuntimeResources, *, mouse: rl.Vector2, alpha: float = 1.0) -> None:
    tex = resources.texture(TextureId.UI_CURSOR)
    a = int(255 * clamp(alpha, 0.0, 1.0))
    tint = rl.Color(255, 255, 255, a)
    src = rl.Rectangle(0.0, 0.0, tex.width, tex.height)
    dst = rl.Rectangle(mouse.x, mouse.y, 32.0, 32.0)
    rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)
