from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import math

import pyray as rl

from grim.assets import TextureLoader
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from ..game_modes import GameMode
from ..gameplay import BonusHudState, PlayerState, survival_level_threshold
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
HUD_XP_BAR_RGBA = (0.1, 0.3, 0.6, 1.0)
HUD_QUEST_LEFT_Y_SHIFT = 80.0


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


@dataclass(frozen=True, slots=True)
class HudRenderFlags:
    show_health: bool
    show_weapon: bool
    show_xp: bool
    show_time: bool
    show_quest_hud: bool


@dataclass(slots=True)
class HudState:
    survival_xp_smoothed: int = 0

    def smooth_xp(self, target: int, frame_dt_ms: float) -> int:
        target = int(target)
        if target <= 0:
            self.survival_xp_smoothed = 0
            return 0

        smoothed = int(self.survival_xp_smoothed)
        if smoothed == target:
            return smoothed

        step = max(1, int(frame_dt_ms) // 2)
        diff = abs(smoothed - target)
        if diff > 1000:
            step *= diff // 100

        if smoothed < target:
            smoothed += step
            if smoothed > target:
                smoothed = target
        else:
            smoothed -= step
            if smoothed < target:
                smoothed = target

        self.survival_xp_smoothed = smoothed
        return smoothed


@dataclass(frozen=True, slots=True)
class HudLayout:
    scale: float
    text_scale: float
    line_h: float
    hud_y_shift: float


def hud_flags_for_game_mode(game_mode_id: int) -> HudRenderFlags:
    """Match `hud_update_and_render` (0x0041ca90) flag mapping."""

    mode = int(game_mode_id)
    if mode == int(GameMode.QUESTS):
        return HudRenderFlags(
            show_health=True,
            show_weapon=True,
            show_xp=True,
            show_time=False,
            show_quest_hud=True,
        )
    if mode == int(GameMode.SURVIVAL):
        return HudRenderFlags(
            show_health=True,
            show_weapon=True,
            show_xp=True,
            show_time=False,
            show_quest_hud=False,
        )
    if mode == int(GameMode.RUSH):
        return HudRenderFlags(
            show_health=True,
            show_weapon=False,
            show_xp=False,
            show_time=True,
            show_quest_hud=False,
        )
    if mode == int(GameMode.TYPO):
        return HudRenderFlags(
            show_health=True,
            show_weapon=False,
            show_xp=True,
            show_time=True,
            show_quest_hud=False,
        )
    return HudRenderFlags(
        show_health=False,
        show_weapon=False,
        show_xp=False,
        show_time=False,
        show_quest_hud=False,
    )


def hud_ui_scale(screen_w: float, screen_h: float) -> float:
    scale = min(screen_w / HUD_BASE_WIDTH, screen_h / HUD_BASE_HEIGHT)
    if scale < 0.75:
        return 0.75
    if scale > 1.5:
        return 1.5
    return float(scale)


def hud_layout(screen_w: float, screen_h: float, *, font: SmallFontData | None, show_quest_hud: bool) -> HudLayout:
    scale = hud_ui_scale(float(screen_w), float(screen_h))
    text_scale = 1.0 * scale
    line_h = float(font.cell_size) * text_scale if font is not None else 18.0 * text_scale
    hud_y_shift = HUD_QUEST_LEFT_Y_SHIFT if show_quest_hud else 0.0
    return HudLayout(scale=scale, text_scale=text_scale, line_h=line_h, hud_y_shift=hud_y_shift)


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


def _draw_text(font: SmallFontData | None, text: str, pos: Vec2, scale: float, color: rl.Color) -> None:
    if font is not None:
        draw_small_text(font, text, Vec2(pos.x, pos.y), scale, color)
    else:
        rl.draw_text(text, int(pos.x), int(pos.y), int(18 * scale), color)


def _with_alpha(color: rl.Color, alpha: float) -> rl.Color:
    alpha = max(0.0, min(1.0, float(alpha)))
    return rl.Color(color.r, color.g, color.b, int(color.a * alpha))


def _quest_panel_slide_x(time_ms: float) -> float:
    time_ms = float(time_ms)
    if time_ms < 1000.0:
        return (1000.0 - time_ms) * -0.128
    return 0.0


def _survival_xp_progress_ratio(*, xp: int, level: int) -> float:
    level = max(1, int(level))
    prev_threshold = 0 if level <= 1 else survival_level_threshold(level - 1)
    next_threshold = survival_level_threshold(level)
    if next_threshold <= prev_threshold:
        return 0.0
    return (int(xp) - prev_threshold) / float(next_threshold - prev_threshold)


def _draw_progress_bar(pos: Vec2, width: float, ratio: float, rgba: tuple[float, float, float, float], scale: float) -> None:
    ratio = max(0.0, min(1.0, float(ratio)))
    width = max(0.0, float(width))
    if width <= 0.0:
        return
    bar_h = 4.0 * scale
    inner_h = 2.0 * scale
    bg_color = rl.Color(
        int(255 * rgba[0] * 0.6),
        int(255 * rgba[1] * 0.6),
        int(255 * rgba[2] * 0.6),
        int(255 * rgba[3] * 0.4),
    )
    fg_color = rl.Color(
        int(255 * rgba[0]),
        int(255 * rgba[1]),
        int(255 * rgba[2]),
        int(255 * rgba[3]),
    )
    rl.draw_rectangle(int(pos.x), int(pos.y), int(width), int(bar_h), bg_color)
    inner_w = max(0.0, (width - 2.0 * scale) * ratio)
    rl.draw_rectangle(int(pos.x + scale), int(pos.y + scale), int(inner_w), int(inner_h), fg_color)


def draw_target_health_bar(*, pos: Vec2, width: float, ratio: float, alpha: float = 1.0, scale: float = 1.0) -> None:
    ratio = max(0.0, min(1.0, float(ratio)))
    alpha = max(0.0, min(1.0, float(alpha)))
    scale = max(0.1, float(scale))

    # Matches `hud_update_and_render` (0x0041ca90): color shifts from red->green as ratio increases.
    r = (1.0 - ratio) * 0.9 + 0.1
    g = ratio * 0.9 + 0.1
    rgba = (r, g, 0.7, 0.2 * alpha)
    _draw_progress_bar(pos, float(width), ratio, rgba, scale)


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
    state: HudState,
    player: PlayerState,
    players: list[PlayerState] | None = None,
    bonus_hud: BonusHudState | None = None,
    elapsed_ms: float = 0.0,
    score: int | None = None,
    font: SmallFontData | None = None,
    alpha: float = 1.0,
    frame_dt_ms: float | None = None,
    show_health: bool = True,
    show_weapon: bool = True,
    show_xp: bool = True,
    show_time: bool = False,
    show_quest_hud: bool = False,
    quest_progress_ratio: float | None = None,
    small_indicators: bool = False,
) -> float:
    if frame_dt_ms is None:
        frame_dt_ms = max(0.0, float(rl.get_frame_time()) * 1000.0)
    state = state or HudState()
    hud_players = list(players) if players is not None else [player]
    if not hud_players:
        hud_players = [player]
    player_count = len(hud_players)

    screen_w = float(rl.get_screen_width())
    screen_h = float(rl.get_screen_height())
    layout = hud_layout(screen_w, screen_h, font=font, show_quest_hud=show_quest_hud)
    scale = layout.scale
    text_scale = layout.text_scale
    line_h = layout.line_h

    def sx(value: float) -> float:
        return value * scale

    def sy(value: float) -> float:
        return value * scale

    max_y = 0.0
    alpha = max(0.0, min(1.0, float(alpha)))
    text_color = _with_alpha(HUD_TEXT_COLOR, alpha)
    panel_text_color = _with_alpha(HUD_TEXT_COLOR, alpha * HUD_PANEL_ALPHA)
    hud_y_shift = layout.hud_y_shift

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
    if show_health and assets.life_heart is not None:
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
    if show_health and assets.ind_life is not None:
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
                _draw_text(font, f"+ {extra}", Vec2(sx(text_x), sy(text_y)), text_scale, text_color)

    # Quest HUD panels (mm:ss timer + progress).
    if show_quest_hud:
        time_ms = max(0.0, float(elapsed_ms))
        slide_x = _quest_panel_slide_x(time_ms)

        quest_panel_alpha = alpha * 0.7
        quest_text_color = _with_alpha(HUD_TEXT_COLOR, quest_panel_alpha)

        if assets.ind_panel is not None:
            src = rl.Rectangle(0.0, 0.0, float(assets.ind_panel.width), float(assets.ind_panel.height))

            # Sliding top panel (first second).
            dst = rl.Rectangle(sx(slide_x - 90.0), sy(67.0), sx(182.0), sy(53.0))
            rl.draw_texture_pro(
                assets.ind_panel,
                src,
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * quest_panel_alpha)),
            )
            max_y = max(max_y, dst.y + dst.height)

            # Static progress panel.
            dst = rl.Rectangle(sx(-80.0), sy(107.0), sx(182.0), sy(53.0))
            rl.draw_texture_pro(
                assets.ind_panel,
                src,
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * quest_panel_alpha)),
            )
            max_y = max(max_y, dst.y + dst.height)

        # Clock table + pointer inside the sliding panel.
        clock_alpha = alpha * HUD_CLOCK_ALPHA
        if assets.clock_table is not None:
            dst = rl.Rectangle(sx(slide_x + 2.0), sy(78.0), sx(32.0), sy(32.0))
            src = rl.Rectangle(0.0, 0.0, float(assets.clock_table.width), float(assets.clock_table.height))
            rl.draw_texture_pro(
                assets.clock_table,
                src,
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * clock_alpha)),
            )

        if assets.clock_pointer is not None:
            # NOTE: Raylib's draw_texture_pro uses dst.x/y as the rotation origin position;
            # offset by half-size so the 32x32 quad stays aligned with the table.
            dst = rl.Rectangle(sx(slide_x + 2.0 + 16.0), sy(78.0 + 16.0), sx(32.0), sy(32.0))
            src = rl.Rectangle(0.0, 0.0, float(assets.clock_pointer.width), float(assets.clock_pointer.height))
            rotation = time_ms / 1000.0 * 6.0
            origin = rl.Vector2(sx(16.0), sy(16.0))
            rl.draw_texture_pro(
                assets.clock_pointer,
                src,
                dst,
                origin,
                rotation,
                rl.Color(255, 255, 255, int(255 * clock_alpha)),
            )

        total_seconds = max(0, int(time_ms) // 1000)
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        _draw_text(font, f"{minutes}:{seconds:02d}", Vec2(sx(slide_x + 32.0), sy(86.0)), text_scale, quest_text_color)

        _draw_text(font, "Progress", Vec2(sx(18.0), sy(122.0)), text_scale, quest_text_color)

        if quest_progress_ratio is not None:
            ratio = max(0.0, min(1.0, float(quest_progress_ratio)))
            quest_bar_rgba = (0.2, 0.8, 0.3, alpha * 0.8)
            _draw_progress_bar(Vec2(sx(10.0), sy(139.0)), sx(70.0), ratio, quest_bar_rgba, scale)

    # Survival XP panel.
    xp_target = int(player.experience if score is None else score)
    xp_display = state.smooth_xp(xp_target, frame_dt_ms) if show_xp else xp_target
    if show_xp and assets.ind_panel is not None:
        panel_x, panel_y = HUD_SURV_PANEL_POS
        panel_y += hud_y_shift
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
            Vec2(sx(HUD_SURV_XP_LABEL_POS[0]), sy(HUD_SURV_XP_LABEL_POS[1] + hud_y_shift)),
            text_scale,
            panel_text_color,
        )
        _draw_text(
            font,
            f"{xp_display}",
            Vec2(sx(HUD_SURV_XP_VALUE_POS[0]), sy(HUD_SURV_XP_VALUE_POS[1] + hud_y_shift)),
            text_scale,
            panel_text_color,
        )
        _draw_text(
            font,
            f"{int(player.level)}",
            Vec2(sx(HUD_SURV_LVL_VALUE_POS[0]), sy(HUD_SURV_LVL_VALUE_POS[1] + hud_y_shift)),
            text_scale,
            panel_text_color,
        )

        progress_ratio = _survival_xp_progress_ratio(xp=xp_target, level=int(player.level))
        bar_x, bar_y = HUD_SURV_PROGRESS_POS
        bar_y += hud_y_shift
        bar_w = HUD_SURV_PROGRESS_WIDTH
        bar_rgba = (HUD_XP_BAR_RGBA[0], HUD_XP_BAR_RGBA[1], HUD_XP_BAR_RGBA[2], HUD_XP_BAR_RGBA[3] * alpha)
        _draw_progress_bar(Vec2(sx(bar_x), sy(bar_y)), sx(bar_w), progress_ratio, bar_rgba, scale)
        max_y = max(max_y, sy(bar_y + 4.0))

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
            # NOTE: Raylib's draw_texture_pro uses dst.x/y as the rotation origin position;
            # offset by half-size so the 32x32 quad stays aligned with the table.
            dst = rl.Rectangle(
                sx(HUD_CLOCK_POS[0] + HUD_CLOCK_SIZE[0] * 0.5),
                sy(HUD_CLOCK_POS[1] + HUD_CLOCK_SIZE[1] * 0.5),
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
        total_seconds = max(0, int(time_ms) // 1000)
        time_text = f"{total_seconds} seconds"
        _draw_text(font, time_text, Vec2(sx(255.0), sy(10.0)), text_scale, text_color)
        max_y = max(max_y, sy(10.0 + line_h))

    # Bonus HUD slots (icon + timers), slide in/out from the left.
    bonus_bottom_y = float(HUD_BONUS_BASE_Y + hud_y_shift)
    if bonus_hud is not None:
        bonus_y = float(HUD_BONUS_BASE_Y + hud_y_shift)
        bonus_panel_alpha = alpha * 0.7
        bonus_text_color = _with_alpha(HUD_TEXT_COLOR, bonus_panel_alpha)
        bar_rgba = (HUD_XP_BAR_RGBA[0], HUD_XP_BAR_RGBA[1], HUD_XP_BAR_RGBA[2], bonus_panel_alpha)

        slots = bonus_hud.slots[:16]
        for slot in slots:
            if not slot.active:
                continue

            if slot.slide_x < -184.0:
                bonus_y += HUD_BONUS_SPACING
                continue

            has_alt = slot.timer_ref_alt is not None and player_count > 1
            timer = float(slot.timer_value)
            timer_alt = float(slot.timer_value_alt) if has_alt else 0.0

            # Slot panel.
            if assets.ind_panel is not None:
                if not small_indicators:
                    panel_x = slot.slide_x
                    panel_y = bonus_y + HUD_BONUS_PANEL_OFFSET_Y
                    panel_w = 182.0
                    panel_h = 53.0
                else:
                    panel_x = (slot.slide_x - 100.0) + 4.0
                    panel_y = bonus_y + 5.0
                    panel_w = 182.0
                    panel_h = 26.5

                src = rl.Rectangle(0.0, 0.0, float(assets.ind_panel.width), float(assets.ind_panel.height))
                dst = rl.Rectangle(sx(panel_x), sy(panel_y), sx(panel_w), sy(panel_h))
                rl.draw_texture_pro(
                    assets.ind_panel,
                    src,
                    dst,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.Color(255, 255, 255, int(255 * bonus_panel_alpha)),
                )
                max_y = max(max_y, dst.y + dst.height)

            # Slot icon.
            if assets.bonuses is not None and slot.icon_id >= 0:
                src = _bonus_icon_src(assets.bonuses, slot.icon_id)
                dst = rl.Rectangle(
                    sx(slot.slide_x - 1.0),
                    sy(bonus_y),
                    sx(HUD_BONUS_ICON_SIZE),
                    sy(HUD_BONUS_ICON_SIZE),
                )
                rl.draw_texture_pro(
                    assets.bonuses,
                    src,
                    dst,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.Color(255, 255, 255, int(255 * alpha)),
                )
                max_y = max(max_y, dst.y + dst.height)

            # Slot timer bars.
            if not small_indicators:
                if not has_alt:
                    _draw_progress_bar(
                        Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 21.0)),
                        sx(100.0),
                        timer * 0.05,
                        bar_rgba,
                        scale,
                    )
                    _draw_text(font, slot.label, Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 6.0)), text_scale, bonus_text_color)
                else:
                    _draw_progress_bar(
                        Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 17.0)),
                        sx(100.0),
                        timer * 0.05,
                        bar_rgba,
                        scale,
                    )
                    _draw_progress_bar(
                        Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 23.0)),
                        sx(100.0),
                        timer_alt * 0.05,
                        bar_rgba,
                        scale,
                    )
                    _draw_text(font, slot.label, Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 2.0)), text_scale, bonus_text_color)
            else:
                if not has_alt:
                    _draw_progress_bar(
                        Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 17.0)),
                        sx(32.0),
                        timer * 0.05,
                        bar_rgba,
                        scale,
                    )
                else:
                    _draw_progress_bar(
                        Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 13.0)),
                        sx(32.0),
                        timer * 0.05,
                        bar_rgba,
                        scale,
                    )
                    _draw_progress_bar(
                        Vec2(sx(slot.slide_x + 36.0), sy(bonus_y + 19.0)),
                        sx(32.0),
                        timer_alt * 0.05,
                        bar_rgba,
                        scale,
                    )

            bonus_y += HUD_BONUS_SPACING
            max_y = max(max_y, sy(bonus_y))
        bonus_bottom_y = bonus_y

    # Weapon aux timer overlay (weapon name popup).
    if assets.ind_panel is not None and assets.wicons is not None:
        aux_base_y = float(bonus_bottom_y)
        aux_step_y = 32.0
        for idx, hud_player in enumerate(hud_players):
            aux_timer = float(hud_player.aux_timer)
            if aux_timer <= 0.0:
                continue

            fade = 2.0 - aux_timer if aux_timer > 1.0 else aux_timer
            fade = max(0.0, min(1.0, fade)) * alpha
            if fade <= 1e-3:
                continue

            panel_alpha = fade * 0.8
            text_alpha = fade

            panel_x = -12.0
            panel_y = (aux_base_y - 17.0) + float(idx) * aux_step_y
            panel_w = 182.0
            panel_h = 53.0

            src = rl.Rectangle(0.0, 0.0, float(assets.ind_panel.width), float(assets.ind_panel.height))
            dst = rl.Rectangle(sx(panel_x), sy(panel_y), sx(panel_w), sy(panel_h))
            rl.draw_texture_pro(
                assets.ind_panel,
                src,
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, int(255 * panel_alpha)),
            )
            max_y = max(max_y, dst.y + dst.height)

            icon_index = _weapon_icon_index(hud_player.weapon_id)
            if icon_index is not None:
                src = _weapon_icon_src(assets.wicons, icon_index)
                icon_x = 105.0
                icon_y = (aux_base_y - 5.0) + float(idx) * aux_step_y
                dst = rl.Rectangle(sx(icon_x), sy(icon_y), sx(60.0), sy(30.0))
                rl.draw_texture_pro(
                    assets.wicons,
                    src,
                    dst,
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.Color(255, 255, 255, int(255 * panel_alpha)),
                )
                max_y = max(max_y, dst.y + dst.height)

            weapon_entry = WEAPON_BY_ID.get(int(hud_player.weapon_id))
            weapon_name = weapon_entry.name if weapon_entry is not None else f"weapon_{int(hud_player.weapon_id)}"
            weapon_color = _with_alpha(HUD_TEXT_COLOR, text_alpha)
            _draw_text(
                font,
                weapon_name,
                Vec2(sx(8.0), sy((aux_base_y + 1.0) + float(idx) * aux_step_y)),
                text_scale,
                weapon_color,
            )

    return max_y
