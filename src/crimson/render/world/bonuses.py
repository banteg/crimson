from __future__ import annotations

import math

from grim import canvas
from grim.assets import TextureId
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2

from ...bonuses import BONUS_BY_ID, BonusId
from ...bonuses.pool import bonus_find_aim_hover_entry, bonus_label_for_entry
from ...weapons import WEAPON_BY_ID, WeaponId
from . import viewport
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx


def bonus_icon_src(texture: rl.Texture, icon_id: int) -> rl.Rectangle:
    grid = 4
    cell_w = float(texture.width) / grid
    cell_h = float(texture.height) / grid
    col = int(icon_id) % grid
    row = int(icon_id) // grid
    return rl_rectangle(float(col * cell_w), float(row * cell_h), float(cell_w), float(cell_h))


def weapon_icon_src(texture: rl.Texture, icon_index: int) -> rl.Rectangle:
    grid = 8
    cell_w = float(texture.width) / float(grid)
    cell_h = float(texture.height) / float(grid)
    frame = int(icon_index) * 2
    col = frame % grid
    row = frame // grid
    return rl_rectangle(float(col * cell_w), float(row * cell_h), float(cell_w * 2), float(cell_h))


def bonus_fade(time_left: float, time_max: float) -> float:
    time_left = float(time_left)
    time_max = float(time_max)
    if time_left <= 0.0 or time_max <= 0.0:
        return 0.0
    if time_left < 0.5:
        return clamp(time_left * 2.0, 0.0, 1.0)
    age = time_max - time_left
    if age < 0.5:
        return clamp(age * 2.0, 0.0, 1.0)
    return 1.0


def bonus_bubble_fade(time_left: float, time_max: float) -> float:
    """Native shell fade: blink during the final two seconds, then clamp."""
    time_left = float(time_left)
    time_max = float(time_max)

    fade = 1.0
    if time_left < 2.0:
        blink = math.sin(time_left * 18.84955596923828)
        fade = time_left * (0.25 if blink > 0.0 else 0.5)

    age = time_max - time_left
    if age < 0.5:
        fade = age * 2.0
    return clamp(fade, 0.0, 1.0)


def bonus_icon_pulse(phase: float) -> float:
    """Native inner-icon size pulse (`pow(sin(phase), 2.0)`)."""
    return math.sin(float(phase)) ** 2 * 0.25 + 0.75


def draw_bonus_pickups(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    alpha: float = 1.0,
) -> None:
    """`bonus_render`'s pickup passes: every bubble and icon, then every weapon icon."""

    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return
    frame = render_ctx.frame
    resources = frame.resources
    bonuses_texture = resources.texture(TextureId.BONUSES)
    wicons_texture = resources.texture(TextureId.UI_WICONS)
    entries = frame.state.bonus_pool.entries

    bubble_src = bonus_icon_src(bonuses_texture, 0)
    bubble_size = 32.0 * scale
    for idx, bonus in enumerate(entries):
        if bonus.bonus_id == BonusId.UNUSED:
            continue
        time_left = float(bonus.time_left)
        time_max = float(bonus.time_max)
        screen = viewport.world_to_screen_with(bonus.pos, camera=camera, view_scale=view_scale)
        bubble_alpha = bonus_bubble_fade(time_left, time_max) * 0.9 * alpha
        bubble_dst = rl_rectangle(screen.x, screen.y, bubble_size, bubble_size)
        bubble_origin = rl_vector2(bubble_size * 0.5, bubble_size * 0.5)
        bubble_tint = rl_color(255, 255, 255, int(bubble_alpha * 255.0 + 0.5))
        rl.draw_texture_pro(bonuses_texture, bubble_src, bubble_dst, bubble_origin, 0.0, bubble_tint)

        meta = BONUS_BY_ID.get(bonus.bonus_id)
        icon_id = int(meta.icon_id) if meta is not None and meta.icon_id is not None else -1
        if icon_id < 0:
            continue
        if bonus.bonus_id == BonusId.POINTS and int(bonus.amount) == 1000:
            icon_id += 1
        icon_scale = bonus_fade(time_left, time_max) * bonus_icon_pulse(float(idx) + float(frame.bonus_anim_phase)) * alpha
        if icon_scale <= 1e-3:
            continue
        src = bonus_icon_src(bonuses_texture, icon_id)
        size = 32.0 * icon_scale * scale
        rotation_rad = math.sin(float(idx) - float(frame.elapsed_ms) * 0.003) * 0.2
        dst = rl_rectangle(screen.x, screen.y, size, size)
        origin = rl_vector2(size * 0.5, size * 0.5)
        icon_tint = rl_color(255, 255, 255, int(alpha * 255.0 + 0.5))
        rl.draw_texture_pro(bonuses_texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), icon_tint)

    for bonus in entries:
        if bonus.bonus_id != BonusId.WEAPON or bonus.amount not in WEAPON_BY_ID:
            continue
        icon_index = int(WEAPON_BY_ID[WeaponId(bonus.amount)].icon_index)
        if not (0 <= icon_index <= 31):
            continue
        fade = bonus_fade(float(bonus.time_left), float(bonus.time_max))
        icon_scale = fade * bonus_icon_pulse(float(frame.bonus_anim_phase)) * alpha
        if icon_scale <= 1e-3:
            continue
        screen = viewport.world_to_screen_with(bonus.pos, camera=camera, view_scale=view_scale)
        src = weapon_icon_src(wicons_texture, icon_index)
        w = 60.0 * icon_scale * scale
        h = 30.0 * icon_scale * scale
        dst = rl_rectangle(screen.x, screen.y, w, h)
        origin = rl_vector2(w * 0.5, h * 0.5)
        icon_tint = rl_color(255, 255, 255, int(fade * alpha * 255.0 + 0.5))
        rl.draw_texture_pro(wicons_texture, src, dst, origin, 0.0, icon_tint)


def draw_bonus_hover_labels(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
) -> None:
    """`bonus_render`'s label for the bonus under each living player's aim.

    Native draws it once in white at a fixed 0.7 alpha, whatever the transition.
    """

    frame = render_ctx.frame
    font = frame.resources.small_font
    text_scale = 1.0
    screen_w = float(canvas.width())

    color = rl_color(255, 255, 255, int(0.7 * 255.0))

    for player in frame.players:
        if player.health <= 0.0:
            continue
        hovered = bonus_find_aim_hover_entry(player, frame.state.bonus_pool)
        if hovered is None:
            continue
        _idx, entry = hovered
        label = bonus_label_for_entry(entry)
        if not label:
            continue

        aim = player.aim
        aim_screen = viewport.world_to_screen_with(aim, camera=camera, view_scale=view_scale)
        x = aim_screen.x + 16.0
        y = aim_screen.y - 7.0

        if font is not None:
            text_w = measure_small_text_width(font, label)
        else:
            text_w = float(rl.measure_text(label, int(18 * text_scale)))
        if x + text_w > screen_w:
            x = max(0.0, screen_w - text_w)

        if font is not None:
            draw_small_text(font, label, Vec2(x, y), color)
        else:
            rl.draw_text(label, int(x), int(y), int(18 * text_scale), color)
