from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, load_paq_entries
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width


UI_BASE_WIDTH = 1024.0
UI_BASE_HEIGHT = 768.0


@dataclass(slots=True)
class PerkMenuLayout:
    # Layout is tuned to match the classic perk selection screen:
    # the visible "monitor" area inside ui_menuPanel is centered.
    panel_x: float = 172.0
    panel_y: float = 256.0
    panel_w: float = 512.0
    panel_h: float = 256.0

    title_x: float = 448.0
    title_y: float = 224.0
    title_w: float = 128.0
    title_h: float = 32.0

    # Menu items live in the monitor body and are underlined.
    list_x: float = 377.0
    list_y: float = 320.0
    list_step_y: float = 19.0

    desc_x: float = 470.0
    desc_y: float = 320.0
    desc_w: float = 200.0
    desc_h: float = 148.0

    button_y: float = 462.0
    cancel_x: float = 582.0
    button_h: float = 32.0


def ui_scale(screen_w: float, screen_h: float) -> float:
    scale = min(screen_w / UI_BASE_WIDTH, screen_h / UI_BASE_HEIGHT)
    if scale < 0.75:
        return 0.75
    if scale > 1.5:
        return 1.5
    return float(scale)


def ui_origin(screen_w: float, screen_h: float, scale: float) -> tuple[float, float]:
    origin_x = (screen_w - UI_BASE_WIDTH * scale) * 0.5
    origin_y = (screen_h - UI_BASE_HEIGHT * scale) * 0.5
    return origin_x, origin_y


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
    button_sm: rl.Texture | None
    button_md: rl.Texture | None
    cursor: rl.Texture | None
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
    paq_path = assets_root / "crimson.paq"
    if paq_path.is_file():
        try:
            entries = load_paq_entries(assets_root)
            cache = PaqTextureCache(entries=entries, textures={})
            missing: list[str] = []
            assets = PerkMenuAssets(
                menu_panel=_load_from_cache(cache, "ui_menuPanel", "ui/ui_menuPanel.jaz", missing),
                title_pick_perk=_load_from_cache(cache, "ui_textPickAPerk", "ui/ui_textPickAPerk.jaz", missing),
                button_sm=_load_from_cache(cache, "ui_buttonSm", "ui/ui_button_82x32.jaz", missing),
                button_md=_load_from_cache(cache, "ui_buttonMd", "ui/ui_button_145x32.jaz", missing),
                cursor=_load_from_cache(cache, "ui_cursor", "ui/ui_cursor.jaz", missing),
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
    button_sm = _load_from_path(assets_root, "ui/ui_button_82x32.png", missing)
    button_md = _load_from_path(assets_root, "ui/ui_button_145x32.png", missing)
    cursor = _load_from_path(assets_root, "ui/ui_cursor.png", missing)
    owned = tuple(
        tex
        for tex in (
            menu_panel,
            title_pick_perk,
            button_sm,
            button_md,
            cursor,
        )
        if tex is not None
    )
    return PerkMenuAssets(
        menu_panel=menu_panel,
        title_pick_perk=title_pick_perk,
        button_sm=button_sm,
        button_md=button_md,
        cursor=cursor,
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
