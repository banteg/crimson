from __future__ import annotations

from crimson.ui.hud import HUD_QUEST_LEFT_Y_SHIFT, HudState, hud_layout


class _FontStub:
    def __init__(self, cell_size: int) -> None:
        self.cell_size = int(cell_size)


def test_hud_state_smooth_xp_resets_on_non_positive_target() -> None:
    state = HudState(survival_xp_smoothed=123)
    assert state.smooth_xp(0, 16.0) == 0
    assert state.survival_xp_smoothed == 0


def test_hud_state_smooth_xp_steps_towards_target() -> None:
    state = HudState()
    assert state.smooth_xp(100, 16.0) == 8
    assert state.survival_xp_smoothed == 8


def test_hud_state_smooth_xp_scales_for_large_diffs() -> None:
    state = HudState()
    assert state.smooth_xp(5000, 16.0) == 400


def test_hud_state_smooth_xp_clamps_when_overshooting() -> None:
    state = HudState(survival_xp_smoothed=98)
    assert state.smooth_xp(100, 16.0) == 100


def test_hud_layout_draws_in_fixed_pixels() -> None:
    # ui_render_hud has no resolution scale: the default line height is the 18 px fallback.
    layout = hud_layout(font=None, show_quest_hud=False)
    assert layout.line_h == 18.0
    assert layout.hud_y_shift == 0.0


def test_hud_layout_uses_font_cell_size() -> None:
    layout = hud_layout(font=_FontStub(12), show_quest_hud=False)
    assert layout.line_h == 12.0


def test_hud_layout_quest_hud_y_shift() -> None:
    layout = hud_layout(font=None, show_quest_hud=True)
    assert layout.hud_y_shift == HUD_QUEST_LEFT_Y_SHIFT

