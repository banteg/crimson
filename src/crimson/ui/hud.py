from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import math

import pyray as rl

from grim.assets import PaqTextureCache, find_paq_path, load_paq_entries_from_path
from grim.fonts.small import SmallFontData, draw_small_text
from ..gameplay import BonusHudState, PlayerState
from ..weapons import WEAPON_BY_ID

HUD_TEXT_COLOR = rl.Color(220, 220, 220, 255)
HUD_HINT_COLOR = rl.Color(170, 170, 180, 255)
HUD_ACCENT_COLOR = rl.Color(240, 200, 80, 255)

HUD_BASE_WIDTH = 1024.0
HUD_BASE_HEIGHT = 768.0

HUD_TOP_BAR_ALPHA = 0.7
HUD_ICON_ALPHA = 0.8
HUD_PANEL_ALPHA = 0.9
HUD_HEALTH_BG_ALPHA = 0.5
HUD_AMMO_DIM_ALPHA = 0.3

HUD_TOP_BAR_POS = (0.0, 0.0)
HUD_TOP_BAR_SIZE = (512.0, 64.0)
HUD_HEART_CENTER = (27.0, 21.0)
HUD_HEALTH_BAR_POS = (64.0, 16.0)
HUD_HEALTH_BAR_SIZE = (120.0, 9.0)
HUD_WEAPON_ICON_POS = (220.0, 2.0)
HUD_WEAPON_ICON_SIZE = (64.0, 32.0)
HUD_CLOCK_POS = (220.0, 2.0)
HUD_CLOCK_SIZE = (32.0, 32.0)
HUD_CLOCK_ALPHA = 0.9
HUD_AMMO_BASE_POS = (300.0, 10.0)
HUD_AMMO_BAR_SIZE = (6.0, 16.0)
HUD_AMMO_BAR_STEP = 6.0
HUD_AMMO_BAR_LIMIT = 30
HUD_AMMO_BAR_CLAMP = 20
HUD_AMMO_TEXT_OFFSET = (8.0, 1.0)
HUD_SURV_PANEL_POS = (-68.0, 60.0)
HUD_SURV_PANEL_SIZE = (182.0, 53.0)
HUD_SURV_XP_LABEL_POS = (4.0, 78.0)
HUD_SURV_XP_VALUE_POS = (26.0, 74.0)
HUD_SURV_LVL_VALUE_POS = (85.0, 79.0)
HUD_SURV_PROGRESS_POS = (26.0, 91.0)
HUD_SURV_PROGRESS_WIDTH = 54.0
HUD_BONUS_BASE_Y = 121.0
HUD_BONUS_ICON_SIZE = 32.0
HUD_BONUS_TEXT_OFFSET = (36.0, 6.0)
HUD_BONUS_SPACING = 52.0
HUD_BONUS_PANEL_OFFSET_Y = -11.0


@dataclass(slots=True)
class HudAssets:
    game_top: rl.Texture | None
    life_heart: rl.Texture | None
    ind_life: rl.Texture | None
    ind_panel: rl.Texture | None
    ind_bullet: rl.Texture | None
    ind_fire: rl.Texture | None
    ind_rocket: rl.Texture | None
    ind_electric: rl.Texture | None
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
        ind_life=_load_from_cache(cache, "ui_indLife", "ui/ui_indLife.jaz", missing),
        ind_panel=_load_from_cache(cache, "ui_indPanel", "ui/ui_indPanel.jaz", missing),
        ind_bullet=_load_from_cache(cache, "ui_indBullet", "ui/ui_indBullet.jaz", missing),
        ind_fire=_load_from_cache(cache, "ui_indFire", "ui/ui_indFire.jaz", missing),
        ind_rocket=_load_from_cache(cache, "ui_indRocket", "ui/ui_indRocket.jaz", missing),
        ind_electric=_load_from_cache(cache, "ui_indElectric", "ui/ui_indElectric.jaz", missing),
        wicons=_load_from_cache(cache, "ui_wicons", "ui/ui_wicons.jaz", missing),
        clock_table=_load_from_cache(cache, "ui_clockTable", "ui/ui_clockTable.jaz", missing),
        clock_pointer=_load_from_cache(cache, "ui_clockPointer", "ui/ui_clockPointer.jaz", missing),
        bonuses=_load_from_cache(cache, "bonuses", "game/bonuses.jaz", missing),
        missing=missing,
    )
    return assets


def load_hud_assets(assets_root: Path) -> HudAssets:
    paq_path = find_paq_path(assets_root)
    if paq_path is not None:
        try:
            entries = load_paq_entries_from_path(paq_path)
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
    ind_life = _load_from_path(assets_root, "ui/ui_indLife.png", missing)
    ind_panel = _load_from_path(assets_root, "ui/ui_indPanel.png", missing)
    ind_bullet = _load_from_path(assets_root, "ui/ui_indBullet.png", missing)
    ind_fire = _load_from_path(assets_root, "ui/ui_indFire.png", missing)
    ind_rocket = _load_from_path(assets_root, "ui/ui_indRocket.png", missing)
    ind_electric = _load_from_path(assets_root, "ui/ui_indElectric.png", missing)
    wicons = _load_from_path(assets_root, "ui/ui_wicons.png", missing)
    clock_table = _load_from_path(assets_root, "ui/ui_clockTable.png", missing)
    clock_pointer = _load_from_path(assets_root, "ui/ui_clockPointer.png", missing)
    bonuses = _load_from_path(assets_root, "game/bonuses.png", missing)
    owned = tuple(
        tex
        for tex in (
            game_top,
            life_heart,
            ind_life,
            ind_panel,
            ind_bullet,
            ind_fire,
            ind_rocket,
            ind_electric,
            wicons,
            clock_table,
            clock_pointer,
            bonuses,
        )
        if tex is not None
    )
    return HudAssets(
        game_top=game_top,
        life_heart=life_heart,
        ind_life=ind_life,
        ind_panel=ind_panel,
        ind_bullet=ind_bullet,
        ind_fire=ind_fire,
        ind_rocket=ind_rocket,
        ind_electric=ind_electric,
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


def _with_alpha(color: rl.Color, alpha: float) -> rl.Color:
    alpha = max(0.0, min(1.0, float(alpha)))
    return rl.Color(color.r, color.g, color.b, int(color.a * alpha))


def _weapon_icon_index(weapon_id: int) -> int | None:
    entry = WEAPON_BY_ID.get(int(weapon_id))
    icon_index = entry.icon_index if entry is not None else None
    if icon_index is None or icon_index < 0 or icon_index > 31:
        return None
    return int(icon_index)


def _weapon_ammo_class(weapon_id: int) -> int:
    entry = WEAPON_BY_ID.get(int(weapon_id))
    value = entry.ammo_class if entry is not None else None
    return int(value) if value is not None else 0


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
    alpha: float = 1.0,
    show_weapon: bool = True,
    show_xp: bool = True,
    show_time: bool = False,
) -> float:
    screen_w = float(rl.get_screen_width())
    screen_h = float(rl.get_screen_height())
    scale = hud_ui_scale(screen_w, screen_h)
    text_scale = 1.0 * scale
    line_h = float(font.cell_size) * text_scale if font is not None else 18.0 * text_scale

    def sx(value: float) -> float:
        return value * scale

    def sy(value: float) -> float:
        return value * scale

    max_y = 0.0
    alpha = max(0.0, min(1.0, float(alpha)))
    text_color = _with_alpha(HUD_TEXT_COLOR, alpha)
    accent_color = _with_alpha(HUD_ACCENT_COLOR, alpha)
    panel_text_color = _with_alpha(HUD_TEXT_COLOR, alpha * HUD_PANEL_ALPHA)

    # Top bar background.
    if assets.game_top is not None:
        src = rl.Rectangle(0.0, 0.0, float(assets.game_top.width), float(assets.game_top.height))
        dst = rl.Rectangle(
            sx(HUD_TOP_BAR_POS[0]),
            sy(HUD_TOP_BAR_POS[1]),
            sx(HUD_TOP_BAR_SIZE[0]),
            sy(HUD_TOP_BAR_SIZE[1]),
        )
        top_alpha = alpha * HUD_TOP_BAR_ALPHA
        rl.draw_texture_pro(
            assets.game_top,
            src,
            dst,
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.Color(255, 255, 255, int(255 * top_alpha)),
        )
        max_y = max(max_y, dst.y + dst.height)

    # Pulsing heart.
    if assets.life_heart is not None:
        t = max(0.0, elapsed_ms) / 1000.0
        pulse_speed = 5.0 if player.health < 30.0 else 2.0
        pulse = (math.sin(t * pulse_speed) ** 4) * 4.0 + 14.0
        size = pulse * 2.0
        center_x, center_y = HUD_HEART_CENTER
        dst = rl.Rectangle(
            sx(center_x - pulse),
            sy(center_y - pulse),
            sx(size),
            sy(size),
        )
        src = rl.Rectangle(0.0, 0.0, float(assets.life_heart.width), float(assets.life_heart.height))
        rl.draw_texture_pro(
            assets.life_heart,
            src,
            dst,
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.Color(255, 255, 255, int(255 * alpha * HUD_ICON_ALPHA)),
        )
        max_y = max(max_y, dst.y + dst.height)

    # Health bar.
    if assets.ind_life is not None:
        bar_x, bar_y = HUD_HEALTH_BAR_POS
        bar_w, bar_h = HUD_HEALTH_BAR_SIZE
        bg_dst = rl.Rectangle(sx(bar_x), sy(bar_y), sx(bar_w), sy(bar_h))
        bg_src = rl.Rectangle(0.0, 0.0, float(assets.ind_life.width), float(assets.ind_life.height))
        rl.draw_texture_pro(
            assets.ind_life,
            bg_src,
            bg_dst,
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.Color(255, 255, 255, int(255 * alpha * HUD_HEALTH_BG_ALPHA)),
        )
        health_ratio = max(0.0, min(1.0, player.health / 100.0))
        if health_ratio > 0.0:
            fill_w = bar_w * health_ratio
            fill_dst = rl.Rectangle(sx(bar_x), sy(bar_y), sx(fill_w), sy(bar_h))
            fill_src = rl.Rectangle(0.0, 0.0, float(assets.ind_life.width) * health_ratio, float(assets.ind_life.height))
            rl.draw_texture_pro(
                assets.ind_life,
                fill_src,
                fill_dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * alpha * HUD_ICON_ALPHA)),
            )
        max_y = max(max_y, bg_dst.y + bg_dst.height)

    # Weapon icon.
    if show_weapon and assets.wicons is not None:
        icon_index = _weapon_icon_index(player.weapon_id)
        if icon_index is not None:
            src = _weapon_icon_src(assets.wicons, icon_index)
            dst = rl.Rectangle(
                sx(HUD_WEAPON_ICON_POS[0]),
                sy(HUD_WEAPON_ICON_POS[1]),
                sx(HUD_WEAPON_ICON_SIZE[0]),
                sy(HUD_WEAPON_ICON_SIZE[1]),
            )
            rl.draw_texture_pro(
                assets.wicons,
                src,
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * alpha * HUD_ICON_ALPHA)),
            )
            max_y = max(max_y, dst.y + dst.height)

    # Ammo bars.
    if show_weapon:
        ammo_tex = None
        ammo_class = _weapon_ammo_class(player.weapon_id)
        if ammo_class == 1:
            ammo_tex = assets.ind_fire
        elif ammo_class == 2:
            ammo_tex = assets.ind_rocket
        elif ammo_class == 0:
            ammo_tex = assets.ind_bullet
        else:
            ammo_tex = assets.ind_electric

        if ammo_tex is not None:
            base_x, base_y = HUD_AMMO_BASE_POS
            bars = max(0, int(player.clip_size))
            if bars > HUD_AMMO_BAR_LIMIT:
                bars = HUD_AMMO_BAR_CLAMP
            ammo_count = max(0, int(player.ammo))
            base_alpha = alpha * HUD_ICON_ALPHA
            for idx in range(bars):
                bar_alpha = base_alpha if idx < ammo_count else base_alpha * HUD_AMMO_DIM_ALPHA
                dst = rl.Rectangle(
                    sx(base_x + idx * HUD_AMMO_BAR_STEP),
                    sy(base_y),
                    sx(HUD_AMMO_BAR_SIZE[0]),
                    sy(HUD_AMMO_BAR_SIZE[1]),
                )
                src = rl.Rectangle(0.0, 0.0, float(ammo_tex.width), float(ammo_tex.height))
                rl.draw_texture_pro(
                    ammo_tex,
                    src,
                    dst,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.Color(255, 255, 255, int(255 * bar_alpha)),
                )
                max_y = max(max_y, dst.y + dst.height)
            if ammo_count > bars:
                extra = ammo_count - bars
                text_x = base_x + bars * HUD_AMMO_BAR_STEP + HUD_AMMO_TEXT_OFFSET[0]
                text_y = base_y + HUD_AMMO_TEXT_OFFSET[1]
                _draw_text(font, f"+ {extra}", sx(text_x), sy(text_y), text_scale, text_color)

    # Survival XP panel.
    xp_value = int(player.experience if score is None else score)
    if show_xp and assets.ind_panel is not None:
        panel_x, panel_y = HUD_SURV_PANEL_POS
        panel_w, panel_h = HUD_SURV_PANEL_SIZE
        dst = rl.Rectangle(sx(panel_x), sy(panel_y), sx(panel_w), sy(panel_h))
        src = rl.Rectangle(0.0, 0.0, float(assets.ind_panel.width), float(assets.ind_panel.height))
        rl.draw_texture_pro(
            assets.ind_panel,
            src,
            dst,
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.Color(255, 255, 255, int(255 * alpha * HUD_PANEL_ALPHA)),
        )
        max_y = max(max_y, dst.y + dst.height)

    if show_xp:
        _draw_text(
            font,
            "Xp",
            sx(HUD_SURV_XP_LABEL_POS[0]),
            sy(HUD_SURV_XP_LABEL_POS[1]),
            text_scale,
            panel_text_color,
        )
        _draw_text(
            font,
            f"{xp_value}",
            sx(HUD_SURV_XP_VALUE_POS[0]),
            sy(HUD_SURV_XP_VALUE_POS[1]),
            text_scale,
            panel_text_color,
        )
        _draw_text(
            font,
            f"{int(player.level)}",
            sx(HUD_SURV_LVL_VALUE_POS[0]),
            sy(HUD_SURV_LVL_VALUE_POS[1]),
            text_scale,
            panel_text_color,
        )

        # Progress bar (approximation of XP -> next level).
        progress_ratio = (xp_value % 1000) / 1000.0 if xp_value > 0 else 0.0
        bar_x, bar_y = HUD_SURV_PROGRESS_POS
        bar_w = HUD_SURV_PROGRESS_WIDTH
        bar_h = 4.0
        bg_color = rl.Color(40, 40, 48, int(255 * alpha * 0.6))
        fg_color = rl.Color(220, 220, 220, int(255 * alpha))
        rl.draw_rectangle(int(sx(bar_x)), int(sy(bar_y)), int(sx(bar_w)), int(sy(bar_h)), bg_color)
        rl.draw_rectangle(
            int(sx(bar_x) + sx(1.0)),
            int(sy(bar_y) + sy(1.0)),
            int(sx((bar_w - 2.0) * progress_ratio)),
            int(sy(bar_h - 2.0)),
            fg_color,
        )
        max_y = max(max_y, sy(bar_y + bar_h))

    # Mode time clock/text (rush/typo-style HUD).
    if show_time:
        time_seconds = max(0, int(elapsed_ms) // 1000)
        if assets.clock_table is not None:
            dst = rl.Rectangle(
                sx(HUD_CLOCK_POS[0]),
                sy(HUD_CLOCK_POS[1]),
                sx(HUD_CLOCK_SIZE[0]),
                sy(HUD_CLOCK_SIZE[1]),
            )
            src = rl.Rectangle(0.0, 0.0, float(assets.clock_table.width), float(assets.clock_table.height))
            rl.draw_texture_pro(
                assets.clock_table,
                src,
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * alpha * HUD_CLOCK_ALPHA)),
            )
            max_y = max(max_y, dst.y + dst.height)
        if assets.clock_pointer is not None:
            dst = rl.Rectangle(
                sx(HUD_CLOCK_POS[0]),
                sy(HUD_CLOCK_POS[1]),
                sx(HUD_CLOCK_SIZE[0]),
                sy(HUD_CLOCK_SIZE[1]),
            )
            src = rl.Rectangle(0.0, 0.0, float(assets.clock_pointer.width), float(assets.clock_pointer.height))
            rotation = float(time_seconds) * 6.0
            origin = rl.Vector2(sx(HUD_CLOCK_SIZE[0] * 0.5), sy(HUD_CLOCK_SIZE[1] * 0.5))
            rl.draw_texture_pro(
                assets.clock_pointer,
                src,
                dst,
                origin,
                rotation,
                rl.Color(255, 255, 255, int(255 * alpha * HUD_CLOCK_ALPHA)),
            )
            max_y = max(max_y, dst.y + dst.height)
        time_text = f"{time_seconds} seconds"
        _draw_text(font, time_text, sx(255.0), sy(10.0), text_scale, text_color)
        max_y = max(max_y, sy(10.0 + line_h))

    # Bonus HUD slots (text + icons), anchored below the survival panel.
    slots = [slot for slot in bonus_hud.slots if slot.active] if bonus_hud is not None else []
    if slots:
        bonus_x = sx(4.0)
        bonus_y = sy(HUD_BONUS_BASE_Y)
        for slot in slots[:16]:
            if assets.ind_panel is not None:
                panel_x, panel_y = HUD_SURV_PANEL_POS
                dst = rl.Rectangle(
                    sx(panel_x),
                    bonus_y + sy(HUD_BONUS_PANEL_OFFSET_Y),
                    sx(HUD_SURV_PANEL_SIZE[0]),
                    sy(HUD_SURV_PANEL_SIZE[1]),
                )
                src = rl.Rectangle(0.0, 0.0, float(assets.ind_panel.width), float(assets.ind_panel.height))
                rl.draw_texture_pro(
                    assets.ind_panel,
                    src,
                    dst,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.Color(255, 255, 255, int(255 * alpha * HUD_TOP_BAR_ALPHA)),
                )
                max_y = max(max_y, dst.y + dst.height)

            icon_drawn = False
            if assets.bonuses is not None and slot.icon_id >= 0:
                src = _bonus_icon_src(assets.bonuses, slot.icon_id)
                dst = rl.Rectangle(bonus_x, bonus_y, sx(HUD_BONUS_ICON_SIZE), sy(HUD_BONUS_ICON_SIZE))
                rl.draw_texture_pro(
                    assets.bonuses,
                    src,
                    dst,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.Color(255, 255, 255, int(255 * alpha)),
                )
                label_x = bonus_x + sx(HUD_BONUS_TEXT_OFFSET[0])
                icon_drawn = True
                max_y = max(max_y, dst.y + dst.height)
            else:
                label_x = bonus_x

            if not icon_drawn and assets.wicons is not None:
                alt_icon_index = _weapon_icon_index(player.weapon_id)
                if alt_icon_index is not None:
                    src = _weapon_icon_src(assets.wicons, alt_icon_index)
                    dst = rl.Rectangle(bonus_x, bonus_y, sx(HUD_BONUS_ICON_SIZE), sy(HUD_BONUS_ICON_SIZE))
                    rl.draw_texture_pro(
                        assets.wicons,
                        src,
                        dst,
                        rl.Vector2(0.0, 0.0),
                        0.0,
                        rl.Color(255, 255, 255, int(255 * alpha)),
                    )
                    label_x = bonus_x + sx(HUD_BONUS_TEXT_OFFSET[0])
                    max_y = max(max_y, dst.y + dst.height)

            _draw_text(
                font,
                slot.label,
                label_x,
                bonus_y + sy(HUD_BONUS_TEXT_OFFSET[1]),
                text_scale,
                accent_color,
            )
            bonus_y += sy(HUD_BONUS_SPACING)
            max_y = max(max_y, bonus_y)

    return max_y
