from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, load_paq_entries
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from ..gameplay import BonusHudState, PlayerState
from ..weapons import WEAPON_BY_ID

HUD_TEXT_COLOR = rl.Color(220, 220, 220, 255)
HUD_HINT_COLOR = rl.Color(170, 170, 180, 255)
HUD_ACCENT_COLOR = rl.Color(240, 200, 80, 255)

HUD_BASE_WIDTH = 1024.0
HUD_BASE_HEIGHT = 768.0


@dataclass(slots=True)
class HudAssets:
    game_top: rl.Texture | None
    life_heart: rl.Texture | None
    wicons: rl.Texture | None
    clock_table: rl.Texture | None
    clock_pointer: rl.Texture | None
    bonuses: rl.Texture | None
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


def hud_ui_scale(screen_w: float, screen_h: float) -> float:
    scale = min(screen_w / HUD_BASE_WIDTH, screen_h / HUD_BASE_HEIGHT)
    if scale < 0.75:
        return 0.75
    if scale > 1.5:
        return 1.5
    return float(scale)


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


def load_hud_assets_from_cache(cache: PaqTextureCache) -> HudAssets:
    missing: list[str] = []
    assets = HudAssets(
        game_top=_load_from_cache(cache, "iGameUI", "ui/ui_gameTop.jaz", missing),
        life_heart=_load_from_cache(cache, "iHeart", "ui/ui_lifeHeart.jaz", missing),
        wicons=_load_from_cache(cache, "ui_wicons", "ui/ui_wicons.jaz", missing),
        clock_table=_load_from_cache(cache, "ui_clockTable", "ui/ui_clockTable.jaz", missing),
        clock_pointer=_load_from_cache(cache, "ui_clockPointer", "ui/ui_clockPointer.jaz", missing),
        bonuses=_load_from_cache(cache, "bonuses", "game/bonuses.jaz", missing),
        missing=missing,
    )
    return assets


def load_hud_assets(assets_root: Path) -> HudAssets:
    paq_path = assets_root / "crimson.paq"
    if paq_path.is_file():
        try:
            entries = load_paq_entries(assets_root)
            cache = PaqTextureCache(entries=entries, textures={})
            assets = load_hud_assets_from_cache(cache)
            assets._cache = cache
            assets._cache_owned = True
            return assets
        except Exception:
            pass

    missing: list[str] = []
    game_top = _load_from_path(assets_root, "ui/ui_gameTop.png", missing)
    life_heart = _load_from_path(assets_root, "ui/ui_lifeHeart.png", missing)
    wicons = _load_from_path(assets_root, "ui/ui_wicons.png", missing)
    clock_table = _load_from_path(assets_root, "ui/ui_clockTable.png", missing)
    clock_pointer = _load_from_path(assets_root, "ui/ui_clockPointer.png", missing)
    bonuses = _load_from_path(assets_root, "game/bonuses.png", missing)
    owned = tuple(tex for tex in (game_top, life_heart, wicons, clock_table, clock_pointer, bonuses) if tex is not None)
    return HudAssets(
        game_top=game_top,
        life_heart=life_heart,
        wicons=wicons,
        clock_table=clock_table,
        clock_pointer=clock_pointer,
        bonuses=bonuses,
        missing=missing,
        _owned_textures=owned,
    )


def _draw_text(font: SmallFontData | None, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
    if font is not None:
        draw_small_text(font, text, x, y, scale, color)
    else:
        rl.draw_text(text, int(x), int(y), int(18 * scale), color)


def _measure_text(font: SmallFontData | None, text: str, scale: float) -> float:
    if font is not None:
        return measure_small_text_width(font, text, scale)
    return float(len(text)) * 10.0 * scale


def _format_elapsed_time(elapsed_ms: float) -> str:
    total_seconds = max(0, int(elapsed_ms) // 1000)
    seconds = total_seconds % 60
    minutes = (total_seconds // 60) % 60
    hours = total_seconds // 3600
    if hours > 0:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def _weapon_icon_index(weapon_id: int) -> int | None:
    entry = WEAPON_BY_ID.get(int(weapon_id))
    icon_index = entry.icon_index if entry is not None else None
    if icon_index is None or icon_index < 0 or icon_index > 31:
        return None
    return int(icon_index)


def _weapon_icon_src(texture: rl.Texture, icon_index: int) -> rl.Rectangle:
    grid = 8
    cell_w = float(texture.width) / grid
    cell_h = float(texture.height) / grid
    frame = int(icon_index) * 2
    col = frame % grid
    row = frame // grid
    return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w * 2), float(cell_h))


def _bonus_icon_src(texture: rl.Texture, icon_id: int) -> rl.Rectangle:
    grid = 4
    cell_w = float(texture.width) / grid
    cell_h = float(texture.height) / grid
    col = int(icon_id) % grid
    row = int(icon_id) // grid
    return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w), float(cell_h))


def draw_hud_overlay(
    assets: HudAssets,
    *,
    player: PlayerState,
    bonus_hud: BonusHudState | None = None,
    elapsed_ms: float = 0.0,
    score: int | None = None,
    font: SmallFontData | None = None,
) -> float:
    screen_w = float(rl.get_screen_width())
    screen_h = float(rl.get_screen_height())
    scale = hud_ui_scale(screen_w, screen_h)
    margin = 12.0 * scale
    gap = 6.0 * scale
    text_scale = 1.0 * scale
    line_h = float(font.cell_size) * text_scale if font is not None else 18.0 * text_scale

    max_y = margin

    game_top = assets.game_top
    if game_top is not None:
        panel_scale = scale
        panel_w = float(game_top.width) * panel_scale
        panel_h = float(game_top.height) * panel_scale
        panel_x = (screen_w - panel_w) * 0.5
        panel_y = 0.0
        src = rl.Rectangle(0.0, 0.0, float(game_top.width), float(game_top.height))
        dst = rl.Rectangle(panel_x, panel_y, panel_w, panel_h)
        rl.draw_texture_pro(game_top, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        max_y = max(max_y, panel_y + panel_h)

    health = max(0, int(round(player.health)))
    hp_text = f"HP {health}"
    hp_x = margin
    hp_y = margin
    heart = assets.life_heart
    if heart is not None:
        heart_scale = scale
        heart_w = float(heart.width) * heart_scale
        heart_h = float(heart.height) * heart_scale
        rl.draw_texture_ex(heart, rl.Vector2(hp_x, hp_y), 0.0, heart_scale, rl.WHITE)
        hp_x += heart_w + gap
        max_y = max(max_y, hp_y + heart_h)
    _draw_text(font, hp_text, hp_x, hp_y + (line_h * 0.1), text_scale, HUD_TEXT_COLOR)
    max_y = max(max_y, hp_y + line_h)

    ammo_text = f"Ammo {player.ammo}/{player.clip_size}"
    ammo_y = hp_y + max(line_h, (float(heart.height) * scale if heart is not None else line_h)) + gap
    ammo_x = margin
    icon_index = _weapon_icon_index(player.weapon_id)
    wicons = assets.wicons
    if wicons is not None and icon_index is not None:
        src = _weapon_icon_src(wicons, icon_index)
        icon_scale = scale
        dst = rl.Rectangle(ammo_x, ammo_y, src.width * icon_scale, src.height * icon_scale)
        rl.draw_texture_pro(wicons, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        ammo_x += dst.width + gap
        max_y = max(max_y, ammo_y + dst.height)
    _draw_text(font, ammo_text, ammo_x, ammo_y + (line_h * 0.1), text_scale, HUD_TEXT_COLOR)
    max_y = max(max_y, ammo_y + line_h)

    if player.reload_timer_max > 0.0:
        progress = 1.0 - (player.reload_timer / player.reload_timer_max)
        progress = max(0.0, min(1.0, progress))
        bar_w = 120.0 * scale
        bar_h = 6.0 * scale
        bar_x = ammo_x
        bar_y = ammo_y + line_h + gap
        rl.draw_rectangle(int(bar_x), int(bar_y), int(bar_w), int(bar_h), rl.Color(50, 50, 60, 200))
        rl.draw_rectangle(int(bar_x), int(bar_y), int(bar_w * progress), int(bar_h), rl.Color(200, 200, 220, 220))
        max_y = max(max_y, bar_y + bar_h)

    time_text = f"Time {_format_elapsed_time(elapsed_ms)}"
    score_value = int(player.experience if score is None else score)
    score_text = f"XP {score_value}"
    right_x = screen_w - margin
    time_w = _measure_text(font, time_text, text_scale)
    score_w = _measure_text(font, score_text, text_scale)
    time_x = right_x - time_w
    score_x = right_x - score_w
    time_y = margin
    score_y = time_y + line_h + gap * 0.5
    _draw_text(font, time_text, time_x, time_y, text_scale, HUD_TEXT_COLOR)
    _draw_text(font, score_text, score_x, score_y, text_scale, HUD_TEXT_COLOR)
    max_y = max(max_y, score_y + line_h)

    if bonus_hud is not None:
        slots = [slot for slot in bonus_hud.slots if slot.active]
    else:
        slots = []
    if slots:
        bonus_x = margin
        bonus_y = max(max_y + gap, score_y + line_h + gap)
        _draw_text(font, "Bonuses", bonus_x, bonus_y, text_scale, HUD_HINT_COLOR)
        bonus_y += line_h + gap * 0.5
        max_y = max(max_y, bonus_y)

        for slot in slots[:10]:
            icon_drawn = False
            if assets.bonuses is not None and slot.icon_id >= 0:
                src = _bonus_icon_src(assets.bonuses, slot.icon_id)
                icon_scale = scale * 0.9
                dst = rl.Rectangle(bonus_x, bonus_y, src.width * icon_scale, src.height * icon_scale)
                rl.draw_texture_pro(assets.bonuses, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
                label_x = bonus_x + dst.width + gap
                icon_drawn = True
                max_y = max(max_y, bonus_y + dst.height)
            else:
                label_x = bonus_x

            if not icon_drawn and assets.wicons is not None:
                alt_icon_index = _weapon_icon_index(player.weapon_id)
                if alt_icon_index is not None:
                    src = _weapon_icon_src(assets.wicons, alt_icon_index)
                    icon_scale = scale * 0.8
                    dst = rl.Rectangle(bonus_x, bonus_y, src.width * icon_scale, src.height * icon_scale)
                    rl.draw_texture_pro(assets.wicons, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
                    label_x = bonus_x + dst.width + gap
                    max_y = max(max_y, bonus_y + dst.height)

            _draw_text(font, slot.label, label_x, bonus_y + (line_h * 0.1), text_scale, HUD_ACCENT_COLOR)
            bonus_y += line_h + gap
            max_y = max(max_y, bonus_y)

    return max_y
