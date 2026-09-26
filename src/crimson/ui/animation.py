from __future__ import annotations


def ui_element_anim(
    timeline_ms: float,
    *,
    index: int,
    start_ms: float,
    end_ms: float,
    width: float,
    direction_flag: int = 0,
) -> tuple[float, float]:
    # Matches ui_element_update: angle lerps pi/2 -> 0 over [end_ms, start_ms].
    # direction_flag=0 slides from left  (-width -> 0)
    # direction_flag=1 slides from right (+width -> 0)
    if start_ms <= end_ms or width <= 0.0:
        return 0.0, 0.0
    dir_sign = 1.0 if int(direction_flag) else -1.0
    t = timeline_ms
    if t < end_ms:
        angle = 1.5707964
        offset_x = dir_sign * abs(width)
    elif t < start_ms:
        elapsed = t - end_ms
        span = float(start_ms - end_ms)
        p = float(elapsed) / span
        angle = 1.5707964 * (1.0 - p)
        offset_x = dir_sign * ((1.0 - p) * abs(width))
    else:
        angle = 0.0
        offset_x = 0.0
    if index == 0:
        angle = -abs(angle)
    return angle, offset_x


# Result panels (`ui_element_slot_30` game over, `ui_element_slot_35` quest results,
# quest failed and end note) are hidden until 100 ms of the UI timeline and fully
# visible at 400 ms: the element default 0..300 window shifted by 100 in
# `ui_menu_layout_init`. The timeline stops at 400, the latest active element end.
RESULTS_PANEL_HIDDEN_MS = 100
RESULTS_PANEL_VISIBLE_MS = 400
# `gameplay_render_world` fades world entities by timeline / `ui_element_slot_28` span.
WORLD_FADE_SPAN_MS = 500


def results_panel_slide_x(timeline_ms: float, *, width: float) -> float:
    _angle, slide_x = ui_element_anim(
        timeline_ms,
        index=1,
        start_ms=RESULTS_PANEL_VISIBLE_MS,
        end_ms=RESULTS_PANEL_HIDDEN_MS,
        width=width,
    )
    return slide_x


def world_fade_alpha(timeline_ms: float) -> float:
    return min(1.0, max(0.0, float(timeline_ms) / WORLD_FADE_SPAN_MS))
