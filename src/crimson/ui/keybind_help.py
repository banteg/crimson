from __future__ import annotations

from grim.color import grim_color
from grim.config import CrimsonConfig
from grim.draw import grim_draw_rect_outline
from grim.fonts.grim_mono import GrimMonoFont, draw_grim_mono_text
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle

from ..input_codes import input_code_name


def ui_render_keybind_help(
    xy: Vec2,
    alpha: float,
    *,
    config: CrimsonConfig,
    small: SmallFontData,
    mono: GrimMonoFont,
) -> None:
    """`ui_render_keybind_help`: the key info panel the F1 pause shows."""
    rl.draw_rectangle_rec(rl_rectangle(xy.x, xy.y, 512.0, 256.0), grim_color(0.0, 0.0, 0.0, alpha * 0.8))
    color = grim_color(1.0, 1.0, 1.0, alpha)
    grim_draw_rect_outline(xy, 512.0, 256.0, color)
    draw_grim_mono_text(mono, "key info", Vec2(xy.x + 16.0, xy.y + 16.0), 0.8, color)

    x = xy.x + 32.0
    y = xy.y + 50.0
    draw_small_text(small, "Level Up:", Vec2(x, y), color)
    value_x = x + 128.0
    pick_perk = input_code_name(config.controls.pick_perk_code)
    draw_small_text(small, f"{pick_perk} or SPACE BAR or KeyPadAdd", Vec2(value_x, y), color)
    y += 18.0
    draw_small_text(small, "Reload:", Vec2(x, y), color)
    draw_small_text(small, input_code_name(config.controls.reload_code), Vec2(value_x, y), color)
    y += 18.0
    y += 20.0
    for player in range(2):
        if player == 1:
            x += 256.0
        draw_small_text(small, f"Player {player + 1}", Vec2(x, y), color)
        controls = config.controls.player(player)
        y += 22.0
        for index, (label, code) in enumerate(zip(("Up:", "Down:", "Left:", "Right:", "Fire:"), (*controls.move_codes, controls.fire_code), strict=True)):
            if index:
                y += 16.0
            draw_small_text(small, label, Vec2(x, y), color)
            draw_small_text(small, input_code_name(code), Vec2(x + 64.0, y), color)
        if player == 0:
            y -= 94.0

    draw_small_text(small, "Press F1 to return to game", Vec2(x - 20.0, y + 32.0), color)
