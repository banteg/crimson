from __future__ import annotations

import pyray as rl

# ui_element_render (0x446c40): shadow pass uses offset (7, 7), tint 0x44444444, and
# blend factors (src=ZERO, dst=ONE_MINUS_SRC_ALPHA).
UI_SHADOW_OFFSET = 7.0
UI_SHADOW_TINT = rl.Color(0x44, 0x44, 0x44, 0x44)


def draw_ui_quad_shadow(
    *,
    texture: rl.Texture2D,
    src: rl.Rectangle,
    dst: rl.Rectangle,
    origin: rl.Vector2,
    rotation_deg: float,
) -> None:
    # NOTE: raylib/rlgl tracks custom blend factors as state; some backends
    # only apply them when switching the blend mode.
    rl.rl_set_blend_factors_separate(
        rl.RL_ZERO,
        rl.RL_ONE_MINUS_SRC_ALPHA,
        rl.RL_ZERO,
        rl.RL_ONE,
        rl.RL_FUNC_ADD,
        rl.RL_FUNC_ADD,
    )
    rl.begin_blend_mode(rl.BLEND_CUSTOM_SEPARATE)
    rl.rl_set_blend_factors_separate(
        rl.RL_ZERO,
        rl.RL_ONE_MINUS_SRC_ALPHA,
        rl.RL_ZERO,
        rl.RL_ONE,
        rl.RL_FUNC_ADD,
        rl.RL_FUNC_ADD,
    )
    rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, UI_SHADOW_TINT)
    rl.end_blend_mode()
