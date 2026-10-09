from __future__ import annotations

from crimson.ui.hud import HudState


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
