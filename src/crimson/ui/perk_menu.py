from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pyray as rl

from grim.assets import TextureLoader
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width


UI_BASE_WIDTH = 640.0
UI_BASE_HEIGHT = 480.0


MENU_PANEL_SLICE_Y1 = 130.0
MENU_PANEL_SLICE_Y2 = 150.0

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
    # Matches the classic menu panel: pos (-45, 110) + offset (20, -82).
    panel_x: float = -25.0
    panel_y: float = 28.0
    panel_w: float = 512.0
    panel_h: float = 379.0


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


def ui_scale(screen_w: float, screen_h: float) -> float:
    # Classic UI renders in backbuffer pixels; keep menu scale fixed.
    return 1.0


def ui_origin(screen_w: float, screen_h: float, scale: float) -> tuple[float, float]:
    return 0.0, 0.0


def _menu_widescreen_y_shift(layout_w: float) -> float:
    # ui_menu_layout_init: pos_y += (screen_width / 640.0) * 150.0 - 150.0
    return (layout_w / UI_BASE_WIDTH) * 150.0 - 150.0


def perk_menu_compute_layout(
    layout: PerkMenuLayout,
    *,
    screen_w: float,
    origin_x: float,
    origin_y: float,
    scale: float,
    choice_count: int,
    expert_owned: bool,
    master_owned: bool,
    panel_slide_x: float = 0.0,
) -> PerkMenuComputedLayout:
    layout_w = screen_w / scale if scale else screen_w
    widescreen_shift_y = _menu_widescreen_y_shift(layout_w)
    panel_x = layout.panel_x + panel_slide_x
    panel_y = layout.panel_y + widescreen_shift_y
    panel = rl.Rectangle(
        origin_x + panel_x * scale,
        origin_y + panel_y * scale,
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


def draw_menu_panel(texture: rl.Texture, *, dst: rl.Rectangle, tint: rl.Color = rl.WHITE) -> None:
    scale = float(dst.width) / float(texture.width)
    top_h = MENU_PANEL_SLICE_Y1 * scale
    bottom_h = (float(texture.height) - MENU_PANEL_SLICE_Y2) * scale
    mid_h = float(dst.height) - top_h - bottom_h
    if mid_h < 0.0:
        src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
        rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)
        return

    src_w = float(texture.width)
    src_h = float(texture.height)

    src_top = rl.Rectangle(0.0, 0.0, src_w, MENU_PANEL_SLICE_Y1)
    src_mid = rl.Rectangle(0.0, MENU_PANEL_SLICE_Y1, src_w, MENU_PANEL_SLICE_Y2 - MENU_PANEL_SLICE_Y1)
    src_bot = rl.Rectangle(0.0, MENU_PANEL_SLICE_Y2, src_w, src_h - MENU_PANEL_SLICE_Y2)

    dst_top = rl.Rectangle(float(dst.x), float(dst.y), float(dst.width), top_h)
    dst_mid = rl.Rectangle(float(dst.x), float(dst.y) + top_h, float(dst.width), mid_h)
    dst_bot = rl.Rectangle(float(dst.x), float(dst.y) + top_h + mid_h, float(dst.width), bottom_h)

    origin = rl.Vector2(0.0, 0.0)
    rl.draw_texture_pro(texture, src_top, dst_top, origin, 0.0, tint)
    rl.draw_texture_pro(texture, src_mid, dst_mid, origin, 0.0, tint)
    rl.draw_texture_pro(texture, src_bot, dst_bot, origin, 0.0, tint)


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
    _loader: TextureLoader | None = None

    def unload(self) -> None:
        if self._loader is not None:
            self._loader.unload()
            self._loader = None


def load_perk_menu_assets(assets_root: Path) -> PerkMenuAssets:
    loader = TextureLoader.from_assets_root(assets_root, strict=False)
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
        button_sm=loader.get(name="ui_buttonSm", paq_rel="ui/ui_button_82x32.jaz", fs_rel="ui/ui_button_82x32.png"),
        button_md=loader.get(
            name="ui_buttonMd",
            paq_rel="ui/ui_button_145x32.jaz",
            fs_rel="ui/ui_button_145x32.png",
        ),
        cursor=loader.get(name="ui_cursor", paq_rel="ui/ui_cursor.jaz", fs_rel="ui/ui_cursor.png"),
        aim=loader.get(name="ui_aim", paq_rel="ui/ui_aim.jaz", fs_rel="ui/ui_aim.png"),
        missing=loader.missing,
        _loader=loader,
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
        draw_small_text(font, text, x, y, scale, color)
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


def menu_item_hit_rect(font: SmallFontData | None, label: str, *, x: float, y: float, scale: float) -> rl.Rectangle:
    width = _ui_text_width(font, label, scale)
    height = 16.0 * scale
    return rl.Rectangle(float(x), float(y), float(width), float(height))


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


def button_hit_rect(*, x: float, y: float, width: float) -> rl.Rectangle:
    # Mirrors ui_button_update: y is offset by +2, hit height is 0x1c (28).
    return rl.Rectangle(float(x), float(y + 2.0), float(width), float(28.0))


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
        state.hovered = rl.check_collision_point_rec(mouse, button_hit_rect(x=x, y=y, width=width))

    delta = 6 if (state.enabled and state.hovered) else -4
    state.hover_t = int(_clamp(float(state.hover_t + int(dt_ms) * delta), 0.0, 1000.0))

    if state.press_t > 0:
        state.press_t = int(_clamp(float(state.press_t - int(dt_ms) * 6), 0.0, 1000.0))

    state.activated = bool(state.enabled and state.hovered and click)
    if state.activated:
        state.press_t = 1000
    return state.activated


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def button_draw(
    assets: PerkMenuAssets,
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
        alpha = 0.5
        if state.press_t > 0:
            alpha = min(1.0, 0.5 + (float(state.press_t) * 0.0005))
        hl = rl.Color(255, 255, 255, int(255 * alpha * 0.25 * state.alpha))
        rl.draw_rectangle(int(x + 12.0 * scale), int(y + 5.0 * scale), int(width - 24.0 * scale), int(22.0 * scale), hl)

    tint_a = state.alpha if state.hovered else state.alpha * 0.7
    tint = rl.Color(255, 255, 255, int(255 * _clamp(tint_a, 0.0, 1.0)))

    src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
    dst = rl.Rectangle(float(x), float(y), float(width), float(32.0 * scale))
    rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)

    text_w = _ui_text_width(font, state.label, scale)
    text_x = x + width * 0.5 - text_w * 0.5 + 1.0 * scale
    text_y = y + 10.0 * scale
    draw_ui_text(font, state.label, text_x, text_y, scale=scale, color=tint)


def cursor_draw(assets: PerkMenuAssets, *, mouse: rl.Vector2, scale: float, alpha: float = 1.0) -> None:
    tex = assets.cursor
    if tex is None:
        return
    a = int(255 * _clamp(alpha, 0.0, 1.0))
    tint = rl.Color(255, 255, 255, a)
    size = 32.0 * scale
    src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
    dst = rl.Rectangle(float(mouse.x), float(mouse.y), size, size)
    rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)
