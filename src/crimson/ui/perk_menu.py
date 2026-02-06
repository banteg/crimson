from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import pyray as rl

from grim.assets import TextureLoader
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp

from .layout import menu_widescreen_y_shift

# Perk selection screen panel uses ui_element-style timeline animation:
# - fully hidden until end_ms
# - slides in over (end_ms..start_ms)
# - fully visible at start_ms
PERK_MENU_ANIM_START_MS = 400.0
PERK_MENU_ANIM_END_MS = 100.0
PERK_MENU_TRANSITION_MS = PERK_MENU_ANIM_START_MS

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


@dataclass(slots=True)
class PerkMenuLayout:
    # Coordinates live in the original 640x480 UI space.
    # Capture (1024x768) shows the perk menu panel uses the 3-slice variant:
    #   open bbox (-108,119) -> (402,497)
    # which corresponds to ui_element pos (-45,110) + geom (-63,-81) and size 510x378.
    panel_x: float = -108.0
    panel_y: float = 29.0
    panel_w: float = 510.0
    panel_h: float = 378.0


@dataclass(slots=True)
class PerkMenuComputedLayout:
    panel: rl.Rectangle
    title: rl.Rectangle
    sponsor_x: float
    sponsor_y: float
    list_x: float
    list_y: float
    list_step_y: float
    desc: rl.Rectangle
    cancel_x: float
    cancel_y: float

def perk_menu_compute_layout(
    layout: PerkMenuLayout,
    *,
    screen_w: float,
    origin: Vec2,
    scale: float,
    choice_count: int,
    expert_owned: bool,
    master_owned: bool,
    panel_slide_x: float = 0.0,
) -> PerkMenuComputedLayout:
    layout_w = screen_w / scale if scale else screen_w
    widescreen_shift_y = menu_widescreen_y_shift(layout_w)
    panel_x = layout.panel_x + panel_slide_x
    panel_y = layout.panel_y + widescreen_shift_y
    panel = rl.Rectangle(
        origin.x + panel_x * scale,
        origin.y + panel_y * scale,
        layout.panel_w * scale,
        layout.panel_h * scale,
    )
    anchor_x = panel.x + MENU_PANEL_ANCHOR_X * scale
    anchor_y = panel.y + MENU_PANEL_ANCHOR_Y * scale

    title = rl.Rectangle(
        anchor_x + MENU_TITLE_X * scale,
        anchor_y + MENU_TITLE_Y * scale,
        MENU_TITLE_W * scale,
        MENU_TITLE_H * scale,
    )

    sponsor_x = anchor_x + (MENU_SPONSOR_X_MASTER if master_owned else MENU_SPONSOR_X_EXPERT) * scale
    sponsor_y = anchor_y + MENU_SPONSOR_Y * scale

    list_step_y = MENU_LIST_STEP_EXPERT if expert_owned else MENU_LIST_STEP_NORMAL
    list_x = anchor_x
    list_y = anchor_y + (MENU_LIST_Y_EXPERT if expert_owned else MENU_LIST_Y_NORMAL) * scale

    desc_x = anchor_x + MENU_DESC_X * scale
    desc_y = list_y + float(choice_count) * list_step_y * scale + MENU_DESC_Y_AFTER_LIST * scale
    if choice_count > 5:
        desc_y -= MENU_DESC_Y_EXTRA_TIGHTEN * scale

    # Keep the description within the monitor screen area and above the button.
    desc_right = panel.x + MENU_DESC_RIGHT_X * scale
    cancel_x = anchor_x + MENU_BUTTON_X * scale
    cancel_y = anchor_y + MENU_BUTTON_Y * scale
    desc_w = max(0.0, float(desc_right - desc_x))
    desc_h = max(0.0, float(cancel_y - 12.0 * scale - desc_y))
    desc = rl.Rectangle(float(desc_x), float(desc_y), float(desc_w), float(desc_h))

    return PerkMenuComputedLayout(
        panel=panel,
        title=title,
        sponsor_x=float(sponsor_x),
        sponsor_y=float(sponsor_y),
        list_x=float(list_x),
        list_y=float(list_y),
        list_step_y=float(list_step_y * scale),
        desc=desc,
        cancel_x=float(cancel_x),
        cancel_y=float(cancel_y),
    )

def ui_element_slide_x(
    t_ms: float,
    *,
    start_ms: float,
    end_ms: float,
    width: float,
    direction_flag: int = 0,
) -> float:
    """
    Slide offset helper matching ui_element_update semantics (see MenuView._ui_element_anim).

    direction_flag=0: slide from left  (-width -> 0)
    direction_flag=1: slide from right (+width -> 0)
    """

    if start_ms <= end_ms or width <= 0.0:
        return 0.0

    width = abs(float(width))
    t = float(t_ms)
    if t < float(end_ms):
        slide = width
    elif t < float(start_ms):
        elapsed = t - float(end_ms)
        span = float(start_ms) - float(end_ms)
        p = elapsed / span if span > 1e-6 else 1.0
        slide = (1.0 - p) * width
    else:
        slide = 0.0

    return slide if int(direction_flag) else -slide


def perk_menu_panel_slide_x(t_ms: float, *, width: float) -> float:
    return ui_element_slide_x(
        t_ms,
        start_ms=PERK_MENU_ANIM_START_MS,
        end_ms=PERK_MENU_ANIM_END_MS,
        width=width,
        direction_flag=0,
    )


@dataclass(slots=True)
class PerkMenuAssets:
    menu_panel: rl.Texture | None
    title_pick_perk: rl.Texture | None
    title_level_up: rl.Texture | None
    menu_item: rl.Texture | None
    button_sm: rl.Texture | None
    button_md: rl.Texture | None
    cursor: rl.Texture | None
    aim: rl.Texture | None
    missing: list[str] = field(default_factory=list)


def load_perk_menu_assets(assets_root: Path) -> PerkMenuAssets:
    loader = TextureLoader.from_assets_root(assets_root)
    return PerkMenuAssets(
        menu_panel=loader.get(name="ui_menuPanel", paq_rel="ui/ui_menuPanel.jaz", fs_rel="ui/ui_menuPanel.png"),
        title_pick_perk=loader.get(
            name="ui_textPickAPerk",
            paq_rel="ui/ui_textPickAPerk.jaz",
            fs_rel="ui/ui_textPickAPerk.png",
        ),
        title_level_up=loader.get(
            name="ui_textLevelUp",
            paq_rel="ui/ui_textLevelUp.jaz",
            fs_rel="ui/ui_textLevelUp.png",
        ),
        menu_item=loader.get(name="ui_menuItem", paq_rel="ui/ui_menuItem.jaz", fs_rel="ui/ui_menuItem.png"),
        button_sm=loader.get(name="ui_buttonSm", paq_rel="ui/ui_button_64x32.jaz", fs_rel="ui/ui_button_64x32.png"),
        button_md=loader.get(
            name="ui_buttonMd",
            paq_rel="ui/ui_button_128x32.jaz",
            fs_rel="ui/ui_button_128x32.png",
        ),
        cursor=loader.get(name="ui_cursor", paq_rel="ui/ui_cursor.jaz", fs_rel="ui/ui_cursor.png"),
        aim=loader.get(name="ui_aim", paq_rel="ui/ui_aim.jaz", fs_rel="ui/ui_aim.png"),
        missing=loader.missing,
    )


def _ui_text_width(font: SmallFontData | None, text: str, scale: float) -> float:
    if font is None:
        return float(rl.measure_text(text, int(20 * scale)))
    return float(measure_small_text_width(font, text, scale))


def draw_ui_text(
    font: SmallFontData | None,
    text: str,
    x: float,
    y: float,
    *,
    scale: float,
    color: rl.Color,
) -> None:
    if font is not None:
        draw_small_text(font, text, Vec2(x, y), scale, color)
    else:
        rl.draw_text(text, int(x), int(y), int(20 * scale), color)


def wrap_ui_text(font: SmallFontData | None, text: str, *, max_width: float, scale: float) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines() or [""]:
        para = raw.strip()
        if not para:
            lines.append("")
            continue
        current = ""
        for word in para.split():
            candidate = word if not current else f"{current} {word}"
            if current and _ui_text_width(font, candidate, scale) > max_width:
                lines.append(current)
                current = word
            else:
                current = candidate
        if current:
            lines.append(current)
    return lines


MENU_ITEM_RGB = (0x46, 0xB4, 0xF0)  # from ui_menu_item_update: rgb(70, 180, 240)
MENU_ITEM_ALPHA_IDLE = 0.6
MENU_ITEM_ALPHA_HOVER = 1.0


def menu_item_hit_rect(font: SmallFontData | None, label: str, *, pos: Vec2, scale: float) -> rl.Rectangle:
    width = _ui_text_width(font, label, scale)
    height = 16.0 * scale
    return rl.Rectangle(float(pos.x), float(pos.y), float(width), float(height))


def draw_menu_item(
    font: SmallFontData | None,
    label: str,
    *,
    x: float,
    y: float,
    scale: float,
    hovered: bool,
) -> float:
    alpha = MENU_ITEM_ALPHA_HOVER if hovered else MENU_ITEM_ALPHA_IDLE
    r, g, b = MENU_ITEM_RGB
    color = rl.Color(int(r), int(g), int(b), int(255 * alpha))
    draw_ui_text(font, label, x, y, scale=scale, color=color)
    width = _ui_text_width(font, label, scale)
    line_y = y + 13.0 * scale
    rl.draw_line(int(x), int(line_y), int(x + width), int(line_y), color)
    return float(width)


class UiButtonTextures(Protocol):
    button_sm: rl.Texture | None
    button_md: rl.Texture | None


@dataclass(slots=True)
class UiButtonTextureSet:
    button_sm: rl.Texture | None
    button_md: rl.Texture | None


@dataclass(slots=True)
class UiButtonState:
    label: str
    enabled: bool = True
    hovered: bool = False
    activated: bool = False
    hover_t: int = 0  # 0..1000
    press_t: int = 0  # 0..1000
    alpha: float = 1.0
    force_wide: bool = False


def button_width(font: SmallFontData | None, label: str, *, scale: float, force_wide: bool) -> float:
    text_w = _ui_text_width(font, label, scale)
    if force_wide:
        return 145.0 * scale
    if text_w < 40.0 * scale:
        return 82.0 * scale
    return 145.0 * scale


def button_hit_rect(*, pos: Vec2, width: float) -> rl.Rectangle:
    # Mirrors ui_button_update: y is offset by +2, hit height is 0x1c (28).
    return rl.Rectangle(float(pos.x), float(pos.y + 2.0), float(width), float(28.0))


def button_update(
    state: UiButtonState,
    *,
    x: float,
    y: float,
    width: float,
    dt_ms: float,
    mouse: rl.Vector2,
    click: bool,
) -> bool:
    if not state.enabled:
        state.hovered = False
    else:
        state.hovered = rl.check_collision_point_rec(mouse, button_hit_rect(pos=Vec2(x, y), width=width))

    delta = 6 if (state.enabled and state.hovered) else -4
    state.hover_t = int(clamp(float(state.hover_t + int(dt_ms) * delta), 0.0, 1000.0))

    if state.press_t > 0:
        state.press_t = int(clamp(float(state.press_t - int(dt_ms) * 6), 0.0, 1000.0))

    state.activated = bool(state.enabled and state.hovered and click)
    if state.activated:
        state.press_t = 1000
    return state.activated


def button_draw(
    assets: UiButtonTextures,
    font: SmallFontData | None,
    state: UiButtonState,
    *,
    x: float,
    y: float,
    width: float,
    scale: float,
) -> None:
    texture = assets.button_md if width > 120.0 * scale else assets.button_sm
    if texture is None:
        return

    if state.hover_t > 0:
        # ui_button_update: highlight fill uses a hover-scaled alpha and click-biased blue tint.
        # - base: (0.5, 0.5, 0.7)
        # - click_anim: +0.0005 / +0.0007, clamped to 1.0 (towards white)
        # - alpha: hover_anim * 0.001 * button.alpha
        r = 0.5
        g = 0.5
        b = 0.7
        if state.press_t > 0:
            click_t = float(state.press_t)
            g = min(1.0, 0.5 + click_t * 0.0005)
            r = g
            b = min(1.0, 0.7 + click_t * 0.0007)
        a = float(state.hover_t) * 0.001 * state.alpha
        hl = rl.Color(
            int(255 * r),
            int(255 * g),
            int(255 * b),
            int(255 * clamp(a, 0.0, 1.0)),
        )
        rl.draw_rectangle(
            int(x + 12.0 * scale),
            int(y + 5.0 * scale),
            int(width - 24.0 * scale),
            int(22.0 * scale),
            hl,
        )

    plate_tint = rl.Color(255, 255, 255, int(255 * clamp(state.alpha, 0.0, 1.0)))

    src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
    dst = rl.Rectangle(float(x), float(y), float(width), float(32.0 * scale))
    rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, plate_tint)

    text_a = state.alpha if state.hovered else state.alpha * 0.7
    text_tint = rl.Color(255, 255, 255, int(255 * clamp(text_a, 0.0, 1.0)))
    text_w = _ui_text_width(font, state.label, scale)
    text_x = x + width * 0.5 - text_w * 0.5 + 1.0 * scale
    text_y = y + 10.0 * scale
    draw_ui_text(font, state.label, text_x, text_y, scale=scale, color=text_tint)


def cursor_draw(assets: PerkMenuAssets, *, mouse: rl.Vector2, scale: float, alpha: float = 1.0) -> None:
    tex = assets.cursor
    if tex is None:
        return
    a = int(255 * clamp(alpha, 0.0, 1.0))
    tint = rl.Color(255, 255, 255, a)
    size = 32.0 * scale
    src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
    dst = rl.Rectangle(float(mouse.x), float(mouse.y), size, size)
    rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)
