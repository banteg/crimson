from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, find_paq_path, load_paq_entries_from_path
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


def perk_menu_compute_layout(
    layout: PerkMenuLayout,
    *,
    origin_x: float,
    origin_y: float,
    scale: float,
    choice_count: int,
    expert_owned: bool,
    master_owned: bool,
) -> PerkMenuComputedLayout:
    panel = rl.Rectangle(
        origin_x + layout.panel_x * scale,
        origin_y + layout.panel_y * scale,
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


def _resolve_asset(assets_root: Path, rel_path: str) -> Path | None:
    direct = assets_root / rel_path
    if direct.is_file():
        return direct
    legacy = assets_root / "crimson" / rel_path
    if legacy.is_file():
        return legacy
    return None


def _load_from_cache(cache: PaqTextureCache, name: str, rel_path: str, missing: list[str]) -> rl.Texture | None:
    try:
        asset = cache.get_or_load(name, rel_path)
        return asset.texture
    except Exception:
        missing.append(rel_path)
        return None


def _load_from_path(assets_root: Path, rel_path: str, missing: list[str]) -> rl.Texture | None:
    path = _resolve_asset(assets_root, rel_path)
    if path is None:
        missing.append(rel_path)
        return None
    return rl.load_texture(str(path))


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
    _owned_textures: tuple[rl.Texture, ...] = ()
    _cache: PaqTextureCache | None = None
    _cache_owned: bool = False

    def unload(self) -> None:
        if self._cache is not None and self._cache_owned:
            self._cache.unload()
        for texture in self._owned_textures:
            rl.unload_texture(texture)
        self._owned_textures = ()
        self._cache = None
        self._cache_owned = False


def load_perk_menu_assets(assets_root: Path) -> PerkMenuAssets:
    paq_path = find_paq_path(assets_root)
    if paq_path is not None:
        try:
            entries = load_paq_entries_from_path(paq_path)
            cache = PaqTextureCache(entries=entries, textures={})
            missing: list[str] = []
            assets = PerkMenuAssets(
                menu_panel=_load_from_cache(cache, "ui_menuPanel", "ui/ui_menuPanel.jaz", missing),
                title_pick_perk=_load_from_cache(cache, "ui_textPickAPerk", "ui/ui_textPickAPerk.jaz", missing),
                title_level_up=_load_from_cache(cache, "ui_textLevelUp", "ui/ui_textLevelUp.jaz", missing),
                menu_item=_load_from_cache(cache, "ui_menuItem", "ui/ui_menuItem.jaz", missing),
                button_sm=_load_from_cache(cache, "ui_buttonSm", "ui/ui_button_82x32.jaz", missing),
                button_md=_load_from_cache(cache, "ui_buttonMd", "ui/ui_button_145x32.jaz", missing),
                cursor=_load_from_cache(cache, "ui_cursor", "ui/ui_cursor.jaz", missing),
                aim=_load_from_cache(cache, "ui_aim", "ui/ui_aim.jaz", missing),
                missing=missing,
            )
            assets._cache = cache
            assets._cache_owned = True
            return assets
        except Exception:
            pass

    missing: list[str] = []
    menu_panel = _load_from_path(assets_root, "ui/ui_menuPanel.png", missing)
    title_pick_perk = _load_from_path(assets_root, "ui/ui_textPickAPerk.png", missing)
    title_level_up = _load_from_path(assets_root, "ui/ui_textLevelUp.png", missing)
    menu_item = _load_from_path(assets_root, "ui/ui_menuItem.png", missing)
    button_sm = _load_from_path(assets_root, "ui/ui_button_82x32.png", missing)
    button_md = _load_from_path(assets_root, "ui/ui_button_145x32.png", missing)
    cursor = _load_from_path(assets_root, "ui/ui_cursor.png", missing)
    aim = _load_from_path(assets_root, "ui/ui_aim.png", missing)
    owned = tuple(
        tex
        for tex in (
            menu_panel,
            title_pick_perk,
            title_level_up,
            menu_item,
            button_sm,
            button_md,
            cursor,
            aim,
        )
        if tex is not None
    )
    return PerkMenuAssets(
        menu_panel=menu_panel,
        title_pick_perk=title_pick_perk,
        title_level_up=title_level_up,
        menu_item=menu_item,
        button_sm=button_sm,
        button_md=button_md,
        cursor=cursor,
        aim=aim,
        missing=missing,
        _owned_textures=owned,
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
