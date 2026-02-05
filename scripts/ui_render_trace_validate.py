#!/usr/bin/env python3
"""
Validate a subset of our UI layout constants against a runtime oracle extracted
from the original game (ui_render_trace_oracle_*.json).

This is intentionally not a full renderer diff. For now we treat the oracle as
"pixel truth" at a single resolution (1024x768) and validate:
  - main menu sign + menu items + label quads
  - panel menu (options) panel quad + back item + back label

As we improve fidelity, extend this script screen-by-screen.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BBox:
    x0: float
    y0: float
    x1: float
    y1: float

    @property
    def w(self) -> float:
        return self.x1 - self.x0

    @property
    def h(self) -> float:
        return self.y1 - self.y0


def _as_bbox(v: object | None) -> BBox | None:
    if not isinstance(v, list) or len(v) != 4:
        return None
    if not all(isinstance(x, (int, float)) for x in v):
        return None
    x0, y0, x1, y1 = (float(v[0]), float(v[1]), float(v[2]), float(v[3]))
    return BBox(x0, y0, x1, y1)


def _bbox_max_abs_delta(a: BBox, b: BBox) -> float:
    return max(abs(a.x0 - b.x0), abs(a.y0 - b.y0), abs(a.x1 - b.x1), abs(a.y1 - b.y1))


def _draw_texture_pro_bbox(*, x: float, y: float, w: float, h: float, origin_x: float, origin_y: float, rotation_deg: float) -> BBox:
    # Match raylib DrawTexturePro math: pivot at (x, y), origin relative to dst rectangle.
    # Corners in destination-space relative to pivot:
    #   (-origin_x, -origin_y), (w-origin_x, -origin_y), (w-origin_x, h-origin_y), (-origin_x, h-origin_y)
    if w == 0.0 or h == 0.0:
        return BBox(x, y, x, y)
    rad = math.radians(rotation_deg)
    c = math.cos(rad)
    s = math.sin(rad)
    rel = [
        (-origin_x, -origin_y),
        (w - origin_x, -origin_y),
        (w - origin_x, h - origin_y),
        (-origin_x, h - origin_y),
    ]
    pts = [(x + rx * c - ry * s, y + rx * s + ry * c) for rx, ry in rel]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return BBox(min(xs), min(ys), max(xs), max(ys))


def _find_screen(oracle: dict[str, Any], label: str) -> dict[str, Any]:
    for s in oracle.get("screens") or []:
        if isinstance(s, dict) and s.get("label") == label:
            return s
    raise KeyError(f"screen not found: {label}")


def _instances(screen: dict[str, Any], texture_name: str) -> list[dict[str, Any]]:
    layout = screen.get("layout") or {}
    textures = layout.get("textures") or {}
    tex = textures.get(texture_name) or {}
    inst = tex.get("instances") or []
    return [x for x in inst if isinstance(x, dict)]


def _match_bbox(instances: list[dict[str, Any]], expected: BBox) -> tuple[BBox | None, float]:
    best: tuple[BBox | None, float] = (None, float("inf"))
    for inst in instances:
        bb = _as_bbox(inst.get("bbox"))
        if bb is None:
            continue
        d = _bbox_max_abs_delta(bb, expected)
        if d < best[1]:
            best = (bb, d)
    return best


def _panel_scale_and_shift(screen_w: int) -> tuple[float, float]:
    # Keep in sync with MenuView._sign_layout_scale.
    if screen_w <= 640:
        return 0.8, 10.0
    if 801 <= screen_w <= 1024:
        return 1.2, 10.0
    return 1.0, 0.0


def validate_main_menu(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m

    errors: list[str] = []
    screen = _find_screen(oracle, "state_0")

    screen_w = 1024
    screen_h = 768
    _ = screen_h

    # --- Sign ---
    scale, shift_x = _panel_scale_and_shift(screen_w)
    sign_w = m.MENU_SIGN_WIDTH * scale
    sign_h = m.MENU_SIGN_HEIGHT * scale
    offset_x = m.MENU_SIGN_OFFSET_X * scale + shift_x
    offset_y = m.MENU_SIGN_OFFSET_Y * scale
    pos_x = float(screen_w) + m.MENU_SIGN_POS_X_PAD
    pos_y = m.MENU_SIGN_POS_Y
    exp_sign = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=sign_w,
        h=sign_h,
        origin_x=-offset_x,
        origin_y=-offset_y,
        rotation_deg=0.0,
    )
    got_sign, d_sign = _match_bbox(_instances(screen, "ui\\ui_signCrimson"), exp_sign)
    if got_sign is None or d_sign > tol:
        errors.append(f"main_menu: sign bbox mismatch: expected={exp_sign} got={got_sign} max_abs_delta={d_sign:.3f}")

    # --- Menu items + labels ---
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))
    # The capture's main menu has 4 entries (slots 1..4). Validate those slots explicitly.
    slots = [1, 2, 3, 4]
    item_w = 510.0  # inferred from oracle; avoids having to load textures
    item_h = 62.0
    for slot in slots:
        pos_x = m.MenuView._menu_slot_pos_x(slot)
        pos_y = m.MENU_LABEL_BASE_Y + m.MENU_LABEL_STEP * float(slot) + y_shift
        item_scale = 1.0
        local_y_shift = 0.0
        offset_x = m.MENU_ITEM_OFFSET_X * item_scale
        offset_y = m.MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
        exp_item = _draw_texture_pro_bbox(
            x=pos_x,
            y=pos_y,
            w=item_w * item_scale,
            h=item_h * item_scale,
            origin_x=-offset_x,
            origin_y=-offset_y,
            rotation_deg=0.0,
        )
        got_item, d_item = _match_bbox(_instances(screen, "ui\\ui_menuItem"), exp_item)
        if got_item is None or d_item > tol:
            errors.append(
                f"main_menu: menuItem slot={slot} bbox mismatch: expected={exp_item} got={got_item} max_abs_delta={d_item:.3f}"
            )

        exp_label = _draw_texture_pro_bbox(
            x=pos_x,
            y=pos_y,
            w=m.MENU_LABEL_WIDTH * item_scale,
            h=m.MENU_LABEL_HEIGHT * item_scale,
            origin_x=-(m.MENU_LABEL_OFFSET_X * item_scale),
            origin_y=-(m.MENU_LABEL_OFFSET_Y * item_scale - local_y_shift),
            rotation_deg=0.0,
        )
        got_label, d_label = _match_bbox(_instances(screen, "ui\\ui_itemTexts.jaz"), exp_label)
        if got_label is None or d_label > tol:
            errors.append(
                f"main_menu: label slot={slot} bbox mismatch: expected={exp_label} got={got_label} max_abs_delta={d_label:.3f}"
            )

    return errors


def validate_options_panel(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.frontend.panels import base as pb

    errors: list[str] = []
    screen = _find_screen(oracle, "state_2:Sound volume:")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    # PanelMenuView draws the menu panel with slide_x=0 and rotation=0 at timeline>=300.
    pos_x = pb.PANEL_POS_X
    pos_y = pb.PANEL_POS_Y + y_shift
    panel_scale = 1.0
    panel_w = m.MENU_PANEL_WIDTH * panel_scale
    panel_h = m.MENU_PANEL_HEIGHT * panel_scale
    origin_x = -(m.MENU_PANEL_OFFSET_X * panel_scale)
    origin_y = -(m.MENU_PANEL_OFFSET_Y * panel_scale)
    exp_panel = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=panel_w,
        h=panel_h,
        origin_x=origin_x,
        origin_y=origin_y,
        rotation_deg=0.0,
    )
    got_panel, d_panel = _match_bbox(_instances(screen, "ui\\ui_menuPanel"), exp_panel)
    if got_panel is None or d_panel > tol:
        errors.append(f"options: panel bbox mismatch: expected={exp_panel} got={got_panel} max_abs_delta={d_panel:.3f}")

    # Back item.
    item_w = 510.0
    item_h = 62.0
    pos_x = pb.PANEL_BACK_POS_X
    pos_y = pb.PANEL_BACK_POS_Y + y_shift
    offset_x = m.MENU_ITEM_OFFSET_X
    offset_y = m.MENU_ITEM_OFFSET_Y
    exp_back_item = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=item_w,
        h=item_h,
        origin_x=-offset_x,
        origin_y=-offset_y,
        rotation_deg=0.0,
    )
    got_item, d_item = _match_bbox(_instances(screen, "ui\\ui_menuItem"), exp_back_item)
    if got_item is None or d_item > tol:
        errors.append(f"options: back menuItem bbox mismatch: expected={exp_back_item} got={got_item} max_abs_delta={d_item:.3f}")

    exp_back_label = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=m.MENU_LABEL_WIDTH,
        h=m.MENU_LABEL_HEIGHT,
        origin_x=-(m.MENU_LABEL_OFFSET_X),
        origin_y=-(m.MENU_LABEL_OFFSET_Y),
        rotation_deg=0.0,
    )
    got_label, d_label = _match_bbox(_instances(screen, "ui\\ui_itemTexts.jaz"), exp_back_label)
    if got_label is None or d_label > tol:
        errors.append(f"options: back label bbox mismatch: expected={exp_back_label} got={got_label} max_abs_delta={d_label:.3f}")

    return errors


def validate_pause_menu(oracle: dict[str, Any], *, tol: float) -> list[str]:
    """
    Validate the gameplay pause menu (state_5) which reuses the menu item + sign
    layout with three entries.
    """

    from crimson.frontend import menu as m

    errors: list[str] = []
    screen = _find_screen(oracle, "state_5")

    screen_w = 1024

    # --- Sign ---
    scale, shift_x = _panel_scale_and_shift(screen_w)
    sign_w = m.MENU_SIGN_WIDTH * scale
    sign_h = m.MENU_SIGN_HEIGHT * scale
    offset_x = m.MENU_SIGN_OFFSET_X * scale + shift_x
    offset_y = m.MENU_SIGN_OFFSET_Y * scale
    pos_x = float(screen_w) + m.MENU_SIGN_POS_X_PAD
    pos_y = m.MENU_SIGN_POS_Y
    exp_sign = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=sign_w,
        h=sign_h,
        origin_x=-offset_x,
        origin_y=-offset_y,
        rotation_deg=0.0,
    )
    got_sign, d_sign = _match_bbox(_instances(screen, "ui\\ui_signCrimson"), exp_sign)
    if got_sign is None or d_sign > tol:
        errors.append(f"pause_menu: sign bbox mismatch: expected={exp_sign} got={got_sign} max_abs_delta={d_sign:.3f}")

    # --- Menu items + labels ---
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))
    item_w = 510.0
    item_h = 62.0
    for slot in (0, 1, 2):
        pos_x = m.MenuView._menu_slot_pos_x(int(slot))
        pos_y = m.MENU_LABEL_BASE_Y + m.MENU_LABEL_STEP * float(slot) + y_shift
        exp_item = _draw_texture_pro_bbox(
            x=pos_x,
            y=pos_y,
            w=item_w,
            h=item_h,
            origin_x=-(m.MENU_ITEM_OFFSET_X),
            origin_y=-(m.MENU_ITEM_OFFSET_Y),
            rotation_deg=0.0,
        )
        got_item, d_item = _match_bbox(_instances(screen, "ui\\ui_menuItem"), exp_item)
        if got_item is None or d_item > tol:
            errors.append(
                f"pause_menu: menuItem slot={slot} bbox mismatch: expected={exp_item} got={got_item} max_abs_delta={d_item:.3f}"
            )

        exp_label = _draw_texture_pro_bbox(
            x=pos_x,
            y=pos_y,
            w=m.MENU_LABEL_WIDTH,
            h=m.MENU_LABEL_HEIGHT,
            origin_x=-(m.MENU_LABEL_OFFSET_X),
            origin_y=-(m.MENU_LABEL_OFFSET_Y),
            rotation_deg=0.0,
        )
        got_label, d_label = _match_bbox(_instances(screen, "ui\\ui_itemTexts.jaz"), exp_label)
        if got_label is None or d_label > tol:
            errors.append(
                f"pause_menu: label slot={slot} bbox mismatch: expected={exp_label} got={got_label} max_abs_delta={d_label:.3f}"
            )

    return errors


def validate_play_game_panel(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m

    errors: list[str] = []
    screen = _find_screen(oracle, "state_1:Quests")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    # Matches raw trace (ui_frame 1112 in ui_render_trace_oracle_1024x768.json):
    # panel element pos = (-45, 210) (plus widescreen shift) and uses offset_x=-64 (+1 inset => -63).
    panel_pos_x = -45.0
    panel_pos_y = 210.0 + y_shift
    panel_offset_x = -63.0
    panel_offset_y = m.MENU_PANEL_OFFSET_Y
    panel_w = m.MENU_PANEL_WIDTH
    panel_h = 278.0

    x0 = panel_pos_x + panel_offset_x
    y0 = panel_pos_y + panel_offset_y
    top_h = 138.0
    bottom_h = 116.0
    mid_h = panel_h - top_h - bottom_h

    exp = [
        BBox(x0, y0, x0 + panel_w, y0 + top_h),
        BBox(x0, y0 + top_h, x0 + panel_w, y0 + top_h + mid_h),
        BBox(x0, y0 + top_h + mid_h, x0 + panel_w, y0 + panel_h),
    ]

    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp):
        got, d = _match_bbox(inst, bb)
        if got is None or d > tol:
            errors.append(f"play_game: panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    return errors


def validate_controls_menu(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.frontend.panels import controls as c

    errors: list[str] = []
    screen = _find_screen(oracle, "state_3:Configure for:")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    # --- Panels (left: 254px, right: 378px) ---
    left_x0 = c.CONTROLS_LEFT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    left_y0 = c.CONTROLS_LEFT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    exp_left = BBox(left_x0, left_y0, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + m.MENU_PANEL_HEIGHT)
    got_left, d_left = _match_bbox(_instances(screen, "ui\\ui_menuPanel"), exp_left)
    if got_left is None or d_left > tol:
        errors.append(f"controls: left panel bbox mismatch: expected={exp_left} got={got_left} max_abs_delta={d_left:.3f}")

    right_x0 = c.CONTROLS_RIGHT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    right_y0 = c.CONTROLS_RIGHT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    right_h = float(c.CONTROLS_RIGHT_PANEL_HEIGHT)
    top_h = 138.0
    bottom_h = 116.0
    mid_h = right_h - top_h - bottom_h
    exp = [
        BBox(right_x0, right_y0, right_x0 + m.MENU_PANEL_WIDTH, right_y0 + top_h),
        BBox(right_x0, right_y0 + top_h, right_x0 + m.MENU_PANEL_WIDTH, right_y0 + top_h + mid_h),
        BBox(right_x0, right_y0 + top_h + mid_h, right_x0 + m.MENU_PANEL_WIDTH, right_y0 + right_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp):
        got, d = _match_bbox(inst, bb)
        if got is None or d > tol:
            errors.append(f"controls: right panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    # --- Back item + label ---
    item_w = 510.0
    item_h = 62.0
    pos_x = c.CONTROLS_BACK_POS_X
    pos_y = c.CONTROLS_BACK_POS_Y + y_shift
    exp_back_item = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=item_w,
        h=item_h,
        origin_x=-(m.MENU_ITEM_OFFSET_X),
        origin_y=-(m.MENU_ITEM_OFFSET_Y),
        rotation_deg=0.0,
    )
    got_item, d_item = _match_bbox(_instances(screen, "ui\\ui_menuItem"), exp_back_item)
    if got_item is None or d_item > tol:
        errors.append(f"controls: back menuItem bbox mismatch: expected={exp_back_item} got={got_item} max_abs_delta={d_item:.3f}")

    exp_back_label = _draw_texture_pro_bbox(
        x=pos_x,
        y=pos_y,
        w=m.MENU_LABEL_WIDTH,
        h=m.MENU_LABEL_HEIGHT,
        origin_x=-(m.MENU_LABEL_OFFSET_X),
        origin_y=-(m.MENU_LABEL_OFFSET_Y),
        rotation_deg=0.0,
    )
    got_label, d_label = _match_bbox(_instances(screen, "ui\\ui_itemTexts.jaz"), exp_back_label)
    if got_label is None or d_label > tol:
        errors.append(f"controls: back label bbox mismatch: expected={exp_back_label} got={got_label} max_abs_delta={d_label:.3f}")

    # --- Icons inside the left panel ---
    # These are stable anchors for the rest of the layout.
    exp_title = BBox(left_x0 + 206.0, left_y0 + 44.0, left_x0 + 206.0 + 128.0, left_y0 + 44.0 + 32.0)
    got_title, d_title = _match_bbox(_instances(screen, "ui\\ui_textControls.jaz"), exp_title)
    if got_title is None or d_title > tol:
        errors.append(f"controls: ui_textControls bbox mismatch: expected={exp_title} got={got_title} max_abs_delta={d_title:.3f}")

    exp_check = BBox(left_x0 + 213.0, left_y0 + 174.0, left_x0 + 213.0 + 16.0, left_y0 + 174.0 + 16.0)
    got_check, d_check = _match_bbox(_instances(screen, "ui_checkOn"), exp_check)
    if got_check is None or d_check > tol:
        errors.append(f"controls: checkOn bbox mismatch: expected={exp_check} got={got_check} max_abs_delta={d_check:.3f}")

    drop_inst = _instances(screen, "ui_dropOff")
    for idx, (ox, oy) in enumerate(((418.0, 56.0), (336.0, 102.0), (336.0, 144.0))):
        bb = BBox(left_x0 + ox, left_y0 + oy, left_x0 + ox + 16.0, left_y0 + oy + 16.0)
        got, d = _match_bbox(drop_inst, bb)
        if got is None or d > tol:
            errors.append(f"controls: dropOff[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    return errors


def validate_statistics_menu(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.frontend.panels import stats as s

    errors: list[str] = []
    screen = _find_screen(oracle, "state_4:played for # hours # minutes")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    # --- Panel (tall 378px, 3 vertical slices) ---
    x0 = s.STATISTICS_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    y0 = s.STATISTICS_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    panel_h = float(s.STATISTICS_PANEL_HEIGHT)

    top_h = 138.0
    bottom_h = 116.0
    mid_h = panel_h - top_h - bottom_h
    exp = [
        BBox(x0, y0, x0 + m.MENU_PANEL_WIDTH, y0 + top_h),
        BBox(x0, y0 + top_h, x0 + m.MENU_PANEL_WIDTH, y0 + top_h + mid_h),
        BBox(x0, y0 + top_h + mid_h, x0 + m.MENU_PANEL_WIDTH, y0 + panel_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp):
        got, d = _match_bbox(inst, bb)
        if got is None or d > tol:
            errors.append(f"statistics: panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    # Title label (full 128x32 row from ui_itemTexts).
    exp_title = BBox(x0 + 290.0, y0 + 52.0, x0 + 290.0 + 128.0, y0 + 52.0 + 32.0)
    got_title, d_title = _match_bbox(_instances(screen, "ui\\ui_itemTexts.jaz"), exp_title)
    if got_title is None or d_title > tol:
        errors.append(f"statistics: title bbox mismatch: expected={exp_title} got={got_title} max_abs_delta={d_title:.3f}")

    # Buttons: 4x medium (145x32) + 1x small (82x32).
    # These are stable and should not depend on text widths at 1024x768.
    btn_x = x0 + 270.0
    btn_y0 = y0 + 104.0
    btn_step = 34.0
    for i in range(4):
        bb = BBox(btn_x, btn_y0 + btn_step * float(i), btn_x + 145.0, btn_y0 + btn_step * float(i) + 32.0)
        got, d = _match_bbox(_instances(screen, "ui_buttonMd"), bb)
        if got is None or d > tol:
            errors.append(f"statistics: buttonMd[{i}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    bb_back = BBox(x0 + 394.0, y0 + 290.0, x0 + 394.0 + 82.0, y0 + 290.0 + 32.0)
    got_back, d_back = _match_bbox(_instances(screen, "ui_buttonSm"), bb_back)
    if got_back is None or d_back > tol:
        errors.append(f"statistics: back button bbox mismatch: expected={bb_back} got={got_back} max_abs_delta={d_back:.3f}")

    return errors


def validate_credits_screen(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.frontend.panels import credits as c

    errors: list[str] = []
    screen = _find_screen(oracle, "state_17:credits")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    # --- Panel (tall 378px, 3 slices) ---
    x0 = c.CREDITS_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    y0 = c.CREDITS_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    panel_h = float(c.CREDITS_PANEL_HEIGHT)

    top_h = 138.0
    bottom_h = 116.0
    mid_h = panel_h - top_h - bottom_h
    exp = [
        BBox(x0, y0, x0 + m.MENU_PANEL_WIDTH, y0 + top_h),
        BBox(x0, y0 + top_h, x0 + m.MENU_PANEL_WIDTH, y0 + top_h + mid_h),
        BBox(x0, y0 + top_h + mid_h, x0 + m.MENU_PANEL_WIDTH, y0 + panel_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp):
        got, d = _match_bbox(inst, bb)
        if got is None or d > tol:
            errors.append(f"credits: panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    # Back button (82x32).
    bb_back = BBox(x0 + 298.0, y0 + 310.0, x0 + 298.0 + 82.0, y0 + 310.0 + 32.0)
    got_back, d_back = _match_bbox(_instances(screen, "ui_buttonSm"), bb_back)
    if got_back is None or d_back > tol:
        errors.append(f"credits: back button bbox mismatch: expected={bb_back} got={got_back} max_abs_delta={d_back:.3f}")

    return errors


def validate_weapon_database_screen(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.frontend.panels import databases as d

    errors: list[str] = []
    screen = _find_screen(oracle, "state_15:Unlocked Weapons Database")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    # Left tall panel.
    left_x0 = d.LEFT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    left_y0 = d.LEFT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    left_h = float(d.LEFT_PANEL_HEIGHT)
    top_h = 138.0
    bottom_h = 116.0
    mid_h = left_h - top_h - bottom_h
    exp_left = [
        BBox(left_x0, left_y0, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + top_h),
        BBox(left_x0, left_y0 + top_h, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + top_h + mid_h),
        BBox(left_x0, left_y0 + top_h + mid_h, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + left_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp_left):
        got, d0 = _match_bbox(inst, bb)
        if got is None or d0 > tol:
            errors.append(f"weapons_db: left panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d0:.3f}")

    # Right short panel (254px => 1 quad).
    right_x0 = d.RIGHT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    right_y0 = d.RIGHT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    exp_right = BBox(right_x0, right_y0, right_x0 + m.MENU_PANEL_WIDTH, right_y0 + 254.0)
    got_right, d_right = _match_bbox(inst, exp_right)
    if got_right is None or d_right > tol:
        errors.append(f"weapons_db: right panel bbox mismatch: expected={exp_right} got={got_right} max_abs_delta={d_right:.3f}")

    # Back button.
    bb_back = BBox(left_x0 + 368.0, left_y0 + 313.0, left_x0 + 368.0 + 82.0, left_y0 + 313.0 + 32.0)
    got_back, d_back = _match_bbox(_instances(screen, "ui_buttonSm"), bb_back)
    if got_back is None or d_back > tol:
        errors.append(f"weapons_db: back button bbox mismatch: expected={bb_back} got={got_back} max_abs_delta={d_back:.3f}")

    return errors


def validate_perk_database_screen(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.frontend.panels import databases as d

    errors: list[str] = []
    screen = _find_screen(oracle, "state_16:Unlocked Perks Database")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    left_x0 = d.LEFT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    left_y0 = d.LEFT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    left_h = float(d.LEFT_PANEL_HEIGHT)
    top_h = 138.0
    bottom_h = 116.0
    mid_h = left_h - top_h - bottom_h
    exp_left = [
        BBox(left_x0, left_y0, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + top_h),
        BBox(left_x0, left_y0 + top_h, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + top_h + mid_h),
        BBox(left_x0, left_y0 + top_h + mid_h, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + left_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp_left):
        got, d0 = _match_bbox(inst, bb)
        if got is None or d0 > tol:
            errors.append(f"perks_db: left panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d0:.3f}")

    right_x0 = d.RIGHT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
    right_y0 = d.RIGHT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
    exp_right = BBox(right_x0, right_y0, right_x0 + m.MENU_PANEL_WIDTH, right_y0 + 254.0)
    got_right, d_right = _match_bbox(inst, exp_right)
    if got_right is None or d_right > tol:
        errors.append(f"perks_db: right panel bbox mismatch: expected={exp_right} got={got_right} max_abs_delta={d_right:.3f}")

    bb_back = BBox(left_x0 + 356.0, left_y0 + 315.0, left_x0 + 356.0 + 82.0, left_y0 + 315.0 + 32.0)
    got_back, d_back = _match_bbox(_instances(screen, "ui_buttonSm"), bb_back)
    if got_back is None or d_back > tol:
        errors.append(f"perks_db: back button bbox mismatch: expected={bb_back} got={got_back} max_abs_delta={d_back:.3f}")

    return errors


def validate_high_scores_screens(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import high_scores_layout as hs
    from crimson.frontend import menu as m

    errors: list[str] = []
    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    for label, tag in (
        ("state_14:High scores - Quests", "high_scores_quests"),
        ("state_14:High scores - Survival", "high_scores_survival"),
    ):
        screen = _find_screen(oracle, label)

        left_x0 = hs.HS_LEFT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
        left_y0 = hs.HS_LEFT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
        left_h = float(hs.HS_LEFT_PANEL_HEIGHT)
        top_h = 138.0
        bottom_h = 116.0
        mid_h = left_h - top_h - bottom_h
        exp_left = [
            BBox(left_x0, left_y0, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + top_h),
            BBox(left_x0, left_y0 + top_h, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + top_h + mid_h),
            BBox(left_x0, left_y0 + top_h + mid_h, left_x0 + m.MENU_PANEL_WIDTH, left_y0 + left_h),
        ]
        inst = _instances(screen, "ui\\ui_menuPanel")
        for idx, bb in enumerate(exp_left):
            got, d0 = _match_bbox(inst, bb)
            if got is None or d0 > tol:
                errors.append(f"{tag}: left panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d0:.3f}")

        right_x0 = hs.HS_RIGHT_PANEL_POS_X + m.MENU_PANEL_OFFSET_X
        right_y0 = hs.HS_RIGHT_PANEL_POS_Y + y_shift + m.MENU_PANEL_OFFSET_Y
        exp_right = BBox(right_x0, right_y0, right_x0 + m.MENU_PANEL_WIDTH, right_y0 + 254.0)
        got_right, d_right = _match_bbox(inst, exp_right)
        if got_right is None or d_right > tol:
            errors.append(f"{tag}: right panel bbox mismatch: expected={exp_right} got={got_right} max_abs_delta={d_right:.3f}")

        # Buttons (2x medium + 1x small) inside left panel.
        btn1 = BBox(
            left_x0 + hs.HS_BUTTON_X,
            left_y0 + hs.HS_BUTTON_Y0,
            left_x0 + hs.HS_BUTTON_X + 145.0,
            left_y0 + hs.HS_BUTTON_Y0 + 32.0,
        )
        btn2 = BBox(
            left_x0 + hs.HS_BUTTON_X,
            left_y0 + hs.HS_BUTTON_Y0 + hs.HS_BUTTON_STEP_Y,
            left_x0 + hs.HS_BUTTON_X + 145.0,
            left_y0 + hs.HS_BUTTON_Y0 + hs.HS_BUTTON_STEP_Y + 32.0,
        )
        for i, bb in enumerate((btn1, btn2)):
            got, d0 = _match_bbox(_instances(screen, "ui_buttonMd"), bb)
            if got is None or d0 > tol:
                errors.append(f"{tag}: buttonMd[{i}] bbox mismatch: expected={bb} got={got} max_abs_delta={d0:.3f}")

        bb_back = BBox(
            left_x0 + hs.HS_BACK_BUTTON_X,
            left_y0 + hs.HS_BACK_BUTTON_Y,
            left_x0 + hs.HS_BACK_BUTTON_X + 82.0,
            left_y0 + hs.HS_BACK_BUTTON_Y + 32.0,
        )
        got_back, d_back = _match_bbox(_instances(screen, "ui_buttonSm"), bb_back)
        if got_back is None or d_back > tol:
            errors.append(f"{tag}: back button bbox mismatch: expected={bb_back} got={got_back} max_abs_delta={d_back:.3f}")

    return errors


def validate_quest_menu_panel(oracle: dict[str, Any], *, tol: float) -> list[str]:
    from crimson.frontend import menu as m
    from crimson.game import QUEST_MENU_BASE_X, QUEST_MENU_BASE_Y, QUEST_MENU_PANEL_OFFSET_X, QUEST_PANEL_HEIGHT

    errors: list[str] = []
    screen = _find_screen(oracle, "state_11:#.#")

    screen_w = 1024
    y_shift = m.MenuView._menu_widescreen_y_shift(float(screen_w))

    x0 = float(QUEST_MENU_BASE_X + QUEST_MENU_PANEL_OFFSET_X)
    y0 = float(QUEST_MENU_BASE_Y + m.MENU_PANEL_OFFSET_Y + y_shift)
    panel_w = m.MENU_PANEL_WIDTH
    panel_h = float(QUEST_PANEL_HEIGHT)

    top_h = 138.0
    bottom_h = 116.0
    mid_h = panel_h - top_h - bottom_h

    exp = [
        BBox(x0, y0, x0 + panel_w, y0 + top_h),
        BBox(x0, y0 + top_h, x0 + panel_w, y0 + top_h + mid_h),
        BBox(x0, y0 + top_h + mid_h, x0 + panel_w, y0 + panel_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp):
        got, d = _match_bbox(inst, bb)
        if got is None or d > tol:
            errors.append(f"quests: panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    return errors


def validate_perk_selection_panel(oracle: dict[str, Any], *, tol: float) -> list[str]:
    """
    Validate the in-game perk selection panel (state_6) which uses the tall 3-slice menu panel.
    """

    from crimson.ui.perk_menu import PerkMenuLayout, perk_menu_compute_layout

    errors: list[str] = []
    screen = _find_screen(oracle, "state_6")

    screen_w = 1024
    screen_h = 768
    _ = screen_h

    computed = perk_menu_compute_layout(
        PerkMenuLayout(),
        screen_w=float(screen_w),
        origin_x=0.0,
        origin_y=0.0,
        scale=1.0,
        choice_count=0,
        expert_owned=False,
        master_owned=False,
    )

    x0 = float(computed.panel.x)
    y0 = float(computed.panel.y)
    panel_w = float(computed.panel.width)
    panel_h = float(computed.panel.height)

    # Keep in sync with crimson.ui.menu_panel.draw_classic_menu_panel (scale by width/510).
    panel_scale = panel_w / 510.0 if panel_w != 0.0 else 1.0
    top_h = 138.0 * panel_scale
    bottom_h = 116.0 * panel_scale
    mid_h = panel_h - top_h - bottom_h

    exp = [
        BBox(x0, y0, x0 + panel_w, y0 + top_h),
        BBox(x0, y0 + top_h, x0 + panel_w, y0 + top_h + mid_h),
        BBox(x0, y0 + top_h + mid_h, x0 + panel_w, y0 + panel_h),
    ]
    inst = _instances(screen, "ui\\ui_menuPanel")
    for idx, bb in enumerate(exp):
        got, d = _match_bbox(inst, bb)
        if got is None or d > tol:
            errors.append(f"perk_menu: panel slice[{idx}] bbox mismatch: expected={bb} got={got} max_abs_delta={d:.3f}")

    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate UI layout constants against a captured oracle.")
    p.add_argument(
        "oracle",
        type=Path,
        nargs="?",
        default=Path("analysis/frida/ui_render_trace_oracle_1024x768.json"),
        help="Oracle JSON produced by scripts/ui_render_trace_oracle.py",
    )
    p.add_argument("--tol", type=float, default=1.01, help="Max allowed abs delta (pixels) for bbox coords")
    args = p.parse_args(argv)

    oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
    errors: list[str] = []
    errors.extend(validate_main_menu(oracle, tol=float(args.tol)))
    errors.extend(validate_options_panel(oracle, tol=float(args.tol)))
    errors.extend(validate_pause_menu(oracle, tol=float(args.tol)))
    errors.extend(validate_play_game_panel(oracle, tol=float(args.tol)))
    errors.extend(validate_controls_menu(oracle, tol=float(args.tol)))
    errors.extend(validate_statistics_menu(oracle, tol=float(args.tol)))
    errors.extend(validate_credits_screen(oracle, tol=float(args.tol)))
    errors.extend(validate_weapon_database_screen(oracle, tol=float(args.tol)))
    errors.extend(validate_perk_database_screen(oracle, tol=float(args.tol)))
    errors.extend(validate_high_scores_screens(oracle, tol=float(args.tol)))
    errors.extend(validate_quest_menu_panel(oracle, tol=float(args.tol)))
    errors.extend(validate_perk_selection_panel(oracle, tol=float(args.tol)))

    if not errors:
        print("OK")
        return 0

    print(f"ERRORS: {len(errors)}")
    for e in errors[:80]:
        print(e)
    if len(errors) > 80:
        print(f"... ({len(errors) - 80} more)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
