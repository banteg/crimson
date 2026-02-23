from __future__ import annotations

import pytest

from crimson.render.rtx.mode import (
    RtxRenderMode,
    cycle_rtx_render_mode,
    mode_from_rtx_flag,
    parse_rtx_render_mode,
)


def test_parse_rtx_render_mode_accepts_supported_values() -> None:
    assert parse_rtx_render_mode("classic") is RtxRenderMode.CLASSIC
    assert parse_rtx_render_mode("rtx") is RtxRenderMode.RTX


def test_parse_rtx_render_mode_rejects_unknown_values() -> None:
    with pytest.raises(ValueError):
        parse_rtx_render_mode("shader_stamped_virtual")


def test_mode_from_rtx_flag_maps_to_render_mode() -> None:
    assert mode_from_rtx_flag(False) is RtxRenderMode.CLASSIC
    assert mode_from_rtx_flag(True) is RtxRenderMode.RTX


def test_cycle_rtx_render_mode_toggles_between_modes() -> None:
    assert cycle_rtx_render_mode(RtxRenderMode.CLASSIC) is RtxRenderMode.RTX
    assert cycle_rtx_render_mode(RtxRenderMode.RTX) is RtxRenderMode.CLASSIC
