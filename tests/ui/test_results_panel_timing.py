from __future__ import annotations

import pytest

from crimson.ui.animation import results_panel_slide_x, world_fade_alpha


@pytest.mark.parametrize(
    ("timeline_ms", "expected"),
    [(0.0, -400.0), (99.0, -400.0), (100.0, -400.0), (250.0, -200.0), (399.0, -400.0 / 300.0), (400.0, 0.0)],
)
def test_results_panel_slides_in_linearly_between_100_and_400_ms(timeline_ms: float, expected: float) -> None:
    # ui_element_update: render_offset_x = -(1 - (t - start) / (end - start)) * width for slots 30/35.
    assert results_panel_slide_x(timeline_ms, width=400.0) == pytest.approx(expected)


@pytest.mark.parametrize(("timeline_ms", "expected"), [(-5.0, 0.0), (0.0, 0.0), (250.0, 0.5), (400.0, 0.8), (600.0, 1.0)])
def test_world_fade_alpha_is_timeline_over_slot_28_span(timeline_ms: float, expected: float) -> None:
    assert world_fade_alpha(timeline_ms) == pytest.approx(expected)
