from __future__ import annotations

import pytest

from crimson.ui.hud import (
    HUD_QUEST_LEFT_Y_SHIFT,
    HudAssets,
    HudRenderContext,
    HudRenderFlags,
    HudState,
    hud_layout,
)


class _FontStub:
    def __init__(self, cell_size: int) -> None:
        self.cell_size = int(cell_size)


def _empty_assets() -> HudAssets:
    return HudAssets(
        game_top=None,
        life_heart=None,
        ind_life=None,
        ind_panel=None,
        ind_bullet=None,
        ind_fire=None,
        ind_rocket=None,
        ind_electric=None,
        wicons=None,
        clock_table=None,
        clock_pointer=None,
        bonuses=None,
    )


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


def test_hud_layout_matches_reference_scale() -> None:
    layout = hud_layout(1024, 768, font=None, show_quest_hud=False)
    assert layout.scale == 1.0
    assert layout.text_scale == 1.0
    assert layout.line_h == 18.0
    assert layout.hud_y_shift == 0.0


def test_hud_layout_clamps_min_scale() -> None:
    layout = hud_layout(512, 384, font=None, show_quest_hud=False)
    assert layout.scale == 0.75
    assert layout.text_scale == 0.75
    assert layout.line_h == 18.0 * 0.75


def test_hud_layout_uses_font_cell_size() -> None:
    layout = hud_layout(1024, 768, font=_FontStub(12), show_quest_hud=False)
    assert layout.line_h == 12.0


def test_hud_layout_quest_hud_y_shift() -> None:
    layout = hud_layout(1024, 768, font=None, show_quest_hud=True)
    assert layout.hud_y_shift == HUD_QUEST_LEFT_Y_SHIFT


def test_hud_render_context_exposes_flags() -> None:
    flags = HudRenderFlags(
        show_health=False,
        show_weapon=False,
        show_xp=False,
        show_time=True,
        show_quest_hud=True,
    )
    context = HudRenderContext(assets=_empty_assets(), state=HudState(), flags=flags)
    assert context.flags == flags


def test_hud_render_context_defaults_to_standard_flags() -> None:
    context = HudRenderContext(assets=_empty_assets(), state=HudState())
    flags = context.flags
    assert flags.show_health is True
    assert flags.show_weapon is True
    assert flags.show_xp is True
    assert flags.show_time is False
    assert flags.show_quest_hud is False


def test_hud_render_context_rejects_legacy_show_overrides() -> None:
    with pytest.raises(TypeError):
        # Keep `HudRenderContext` cut over to `flags` only.
        HudRenderContext(
            assets=_empty_assets(),
            state=HudState(),
            show_health=False,  # type: ignore[call-arg]
        )
