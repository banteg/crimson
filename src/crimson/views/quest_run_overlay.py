from __future__ import annotations

import pyray as rl

from grim.fonts.grim_mono import GrimMonoFont
from grim.math import clamp

from .quest_title_overlay import draw_quest_title_overlay

QUEST_TITLE_FADE_IN_MS = 500.0
QUEST_TITLE_HOLD_MS = 1000.0
QUEST_TITLE_FADE_OUT_MS = 500.0
QUEST_TITLE_TOTAL_MS = QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS + QUEST_TITLE_FADE_OUT_MS

QUEST_COMPLETE_BANNER_BASE_W = 256.0
QUEST_COMPLETE_BANNER_BASE_H = 32.0
QUEST_COMPLETE_BANNER_SCALE_BASE = 0.95
QUEST_COMPLETE_BANNER_SCALE_RATE = 0.0004 * 0.13
QUEST_COMPLETE_BANNER_FADE_IN_MS = 500.0
QUEST_COMPLETE_BANNER_HOLD_END_MS = 1500.0
QUEST_COMPLETE_BANNER_FADE_OUT_END_MS = 2000.0


def quest_level_label(major: int, minor: int) -> str:
    major = int(major)
    minor = int(minor)
    while minor > 10:
        major += 1
        minor -= 10
    return f"{major}.{minor}"


def quest_title_alpha(timer_ms: float) -> float:
    timer_ms = float(timer_ms)
    if timer_ms <= 0.0 or timer_ms > QUEST_TITLE_TOTAL_MS:
        return 0.0
    if timer_ms < QUEST_TITLE_FADE_IN_MS and QUEST_TITLE_FADE_IN_MS > 1e-3:
        return timer_ms / QUEST_TITLE_FADE_IN_MS
    if timer_ms < (QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS):
        return 1.0
    t = timer_ms - (QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS)
    return max(0.0, 1.0 - (t / max(1e-3, QUEST_TITLE_FADE_OUT_MS)))


def quest_complete_banner_alpha(timer_ms: float) -> float:
    t = float(timer_ms)
    if t <= 0.0:
        return 0.0
    if t < QUEST_COMPLETE_BANNER_FADE_IN_MS:
        return clamp(t / QUEST_COMPLETE_BANNER_FADE_IN_MS, 0.0, 1.0)
    if t < QUEST_COMPLETE_BANNER_HOLD_END_MS:
        return 1.0
    if t < QUEST_COMPLETE_BANNER_FADE_OUT_END_MS:
        return clamp((QUEST_COMPLETE_BANNER_FADE_OUT_END_MS - t) / QUEST_COMPLETE_BANNER_FADE_IN_MS, 0.0, 1.0)
    return 0.0


def draw_quest_title_timer_overlay(font: GrimMonoFont, title: str, number: str, *, timer_ms: float) -> None:
    alpha = quest_title_alpha(float(timer_ms))
    if alpha <= 0.0:
        return
    draw_quest_title_overlay(font, title, number, alpha=alpha)


def draw_quest_complete_banner_overlay(texture: rl.Texture, *, timer_ms: float) -> None:
    timer_ms = float(timer_ms)
    if timer_ms <= 0.0:
        return
    alpha = quest_complete_banner_alpha(timer_ms)
    if alpha <= 0.0:
        return
    scale = QUEST_COMPLETE_BANNER_SCALE_BASE + timer_ms * QUEST_COMPLETE_BANNER_SCALE_RATE
    width = QUEST_COMPLETE_BANNER_BASE_W * scale
    height = QUEST_COMPLETE_BANNER_BASE_H * scale
    center_x = float(rl.get_screen_width()) * 0.5
    center_y = float(rl.get_screen_height()) * 0.5
    src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
    dst = rl.Rectangle(center_x - width * 0.5, center_y - height * 0.5, width, height)
    tint = rl.Color(255, 255, 255, int(clamp(alpha, 0.0, 1.0) * 255.0))
    rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)
