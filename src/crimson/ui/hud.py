from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import math

import pyray as rl

from grim.assets import TextureLoader
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


def hud_ui_scale(screen_w: float, screen_h: float) -> float:
    scale = min(screen_w / HUD_BASE_WIDTH, screen_h / HUD_BASE_HEIGHT)
    if scale < 0.75:
        return 0.75
    if scale > 1.5:
        return 1.5
    return float(scale)


def load_hud_assets(assets_root: Path) -> HudAssets:
    loader = TextureLoader.from_assets_root(assets_root)
    return HudAssets(
        game_top=loader.get(name="iGameUI", paq_rel="ui/ui_gameTop.jaz", fs_rel="ui/ui_gameTop.png"),
        life_heart=loader.get(name="iHeart", paq_rel="ui/ui_lifeHeart.jaz", fs_rel="ui/ui_lifeHeart.png"),
        ind_life=loader.get(name="ui_indLife", paq_rel="ui/ui_indLife.jaz", fs_rel="ui/ui_indLife.png"),
        ind_panel=loader.get(name="ui_indPanel", paq_rel="ui/ui_indPanel.jaz", fs_rel="ui/ui_indPanel.png"),
        ind_bullet=loader.get(name="ui_indBullet", paq_rel="ui/ui_indBullet.jaz", fs_rel="ui/ui_indBullet.png"),
        ind_fire=loader.get(name="ui_indFire", paq_rel="ui/ui_indFire.jaz", fs_rel="ui/ui_indFire.png"),
        ind_rocket=loader.get(name="ui_indRocket", paq_rel="ui/ui_indRocket.jaz", fs_rel="ui/ui_indRocket.png"),
        ind_electric=loader.get(
            name="ui_indElectric",
            paq_rel="ui/ui_indElectric.jaz",
            fs_rel="ui/ui_indElectric.png",
        ),
        wicons=loader.get(name="ui_wicons", paq_rel="ui/ui_wicons.jaz", fs_rel="ui/ui_wicons.png"),
        clock_table=loader.get(name="ui_clockTable", paq_rel="ui/ui_clockTable.jaz", fs_rel="ui/ui_clockTable.png"),
        clock_pointer=loader.get(
            name="ui_clockPointer",
            paq_rel="ui/ui_clockPointer.jaz",
            fs_rel="ui/ui_clockPointer.png",
        ),
        bonuses=loader.get(name="bonuses", paq_rel="game/bonuses.jaz", fs_rel="game/bonuses.png"),
        missing=loader.missing,
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
    players: list[PlayerState] | None = None,
    bonus_hud: BonusHudState | None = None,
    elapsed_ms: float = 0.0,
    score: int | None = None,
    font: SmallFontData | None = None,
    alpha: float = 1.0,
    show_weapon: bool = True,
    show_xp: bool = True,
    show_time: bool = False,
) -> float:
    hud_players = list(players) if players is not None else [player]
    if not hud_players:
        hud_players = [player]
    player_count = len(hud_players)

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
        src = rl.Rectangle(0.0, 0.0, float(assets.life_heart.width), float(assets.life_heart.height))
        if player_count == 1:
            base_center_x, base_center_y = HUD_HEART_CENTER
            heart_step_y = 0.0
            heart_scale = 1.0
        else:
            base_center_x = 27.0
            base_center_y = 12.0
            heart_step_y = 15.0
            heart_scale = 0.5

        for idx, hud_player in enumerate(hud_players):
            pulse_speed = 5.0 if hud_player.health < 30.0 else 2.0
            phase = float(idx) * (math.pi * 0.5)
            pulse = ((math.sin(t * pulse_speed + phase) ** 4) * 4.0 + 14.0) * heart_scale
            size = pulse * 2.0
            center_y = base_center_y + float(idx) * heart_step_y
            dst = rl.Rectangle(
                sx(base_center_x - pulse),
                sy(center_y - pulse),
                sx(size),
                sy(size),
            )
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
        bg_src = rl.Rectangle(0.0, 0.0, float(assets.ind_life.width), float(assets.ind_life.height))
        if player_count > 1:
            bar_y = 6.0

        for idx, hud_player in enumerate(hud_players):
            bar_y_offset = float(idx) * 16.0 if player_count > 1 else 0.0
            bg_dst = rl.Rectangle(sx(bar_x), sy(bar_y + bar_y_offset), sx(bar_w), sy(bar_h))
            rl.draw_texture_pro(
                assets.ind_life,
                bg_src,
                bg_dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * alpha * HUD_HEALTH_BG_ALPHA)),
            )
            health_ratio = max(0.0, min(1.0, hud_player.health / 100.0))
            if health_ratio > 0.0:
                fill_w = bar_w * health_ratio
                fill_dst = rl.Rectangle(sx(bar_x), sy(bar_y + bar_y_offset), sx(fill_w), sy(bar_h))
                fill_src = rl.Rectangle(
                    0.0,
                    0.0,
                    float(assets.ind_life.width) * health_ratio,
                    float(assets.ind_life.height),
                )
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
        if player_count == 1:
            base_x, base_y = HUD_WEAPON_ICON_POS
            icon_w, icon_h = HUD_WEAPON_ICON_SIZE
            icon_step_y = 0.0
        else:
            base_x = 220.0
            base_y = 4.0
            icon_w = 32.0
            icon_h = 16.0
            icon_step_y = 16.0

        for idx, hud_player in enumerate(hud_players):
            icon_index = _weapon_icon_index(hud_player.weapon_id)
            if icon_index is None:
                continue
            src = _weapon_icon_src(assets.wicons, icon_index)
            dst = rl.Rectangle(
                sx(base_x),
                sy(base_y + float(idx) * icon_step_y),
                sx(icon_w),
                sy(icon_h),
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
        if player_count == 1:
            ammo_base_x, ammo_base_y = HUD_AMMO_BASE_POS
            ammo_step_y = 0.0
        else:
            ammo_base_x = 290.0
            ammo_base_y = 4.0
            ammo_step_y = 14.0

        base_alpha = alpha * HUD_ICON_ALPHA
        for player_idx, hud_player in enumerate(hud_players):
            ammo_tex = None
            ammo_class = _weapon_ammo_class(hud_player.weapon_id)
            if ammo_class == 1:
                ammo_tex = assets.ind_fire
            elif ammo_class == 2:
                ammo_tex = assets.ind_rocket
            elif ammo_class == 0:
                ammo_tex = assets.ind_bullet
            else:
                ammo_tex = assets.ind_electric
            if ammo_tex is None:
                continue

            base_y = ammo_base_y + float(player_idx) * ammo_step_y
            bars = max(0, int(hud_player.clip_size))
            if bars > HUD_AMMO_BAR_LIMIT:
                bars = HUD_AMMO_BAR_CLAMP
            ammo_count = max(0, int(hud_player.ammo))
            for idx in range(bars):
                bar_alpha = base_alpha if idx < ammo_count else base_alpha * HUD_AMMO_DIM_ALPHA
                dst = rl.Rectangle(
                    sx(ammo_base_x + idx * HUD_AMMO_BAR_STEP),
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
                text_x = ammo_base_x + bars * HUD_AMMO_BAR_STEP + HUD_AMMO_TEXT_OFFSET[0]
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
        time_ms = max(0.0, float(elapsed_ms))
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
            rotation = time_ms / 1000.0 * 6.0
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
        total_seconds = int(time_ms) // 1000
        minutes = max(0, total_seconds // 60)
        seconds = max(0, total_seconds % 60)
        time_text = f"{minutes:02d}:{seconds:02d}"
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
